'use strict';

// Local server for the DNS lookup page. It serves the static files and runs the lookups a browser
// cannot: querying DNS servers directly (UDP/TCP) and reaching them, or a DNS-over-HTTPS resolver,
// through HTTP/HTTPS/SOCKS5 proxies. Bound to localhost only; no dependencies.

const http = require('http');
const https = require('https');
const net = require('net');
const tls = require('tls');
const fs = require('fs');
const path = require('path');
const { promises: dnsPromises } = require('dns');
const dnsClient = require('./dns-client');
const { RECORD_TYPES, isValidHost, describeError, splitAnswers, parseResolverResults, parseGeoResult, parseWhoisResult } = require('./lookup-common');

// Host names for outgoing connections are resolved with Node's own (c-ares) resolver, IPv4 first. The
// default, getaddrinfo, shares a pool of 4 threads: a few slow lookups (an IPv6-only host on a network
// where IPv6 stalls, say) would queue every other lookup behind them and make unrelated requests time out.
const cares = new dnsPromises.Resolver({ timeout: 3000, tries: 2 });
function lookupViaResolver(hostname, options, callback) {
  const opts = typeof options === 'function' ? {} : options ?? {};
  const done = typeof options === 'function' ? options : callback;
  const families = opts.family === 6 ? [6] : opts.family === 4 ? [4] : [4, 6];
  (async () => {
    for (const family of families) {
      try {
        const addresses = family === 4 ? await cares.resolve4(hostname) : await cares.resolve6(hostname);
        if (addresses.length) return { addresses, family };
      } catch {
        // try the next family
      }
    }
    throw Object.assign(new Error(`getaddrinfo ENOTFOUND ${hostname}`), { code: 'ENOTFOUND', hostname });
  })().then(
    ({ addresses, family }) => (opts.all ? done(null, addresses.map((address) => ({ address, family }))) : done(null, addresses[0], family)),
    (err) => done(err),
  );
}

const PORT = Number(process.env.PORT) || 8765;
const BIND = '127.0.0.1';
const TIMEOUT_MS = 10000;
const DNS_TIMEOUT_MS = 5000;
const DNS_GIVE_UP = 3; // consecutive timeouts, with no answer at all, before a DNS server is skipped
const PROXY_CONCURRENCY = 10; // vantage points (proxies, or the direct connection) worked on at once
const QUERY_CONCURRENCY = 3; // queries in flight per vantage point
const MAX_PROXIES = 500;
const MAX_DNS_SERVERS = 100;
const MAX_HOSTS = 500;
const MAX_JOBS = 50000;
const MAX_BODY_BYTES = 1 << 20;
const MAX_RESPONSE_BYTES = 256 * 1024;

const DOH = {
  google: 'https://dns.google/resolve',
  cloudflare: 'https://cloudflare-dns.com/dns-query',
};
const DOH_LABELS = { google: 'Google DoH (dns.google)', cloudflare: 'Cloudflare DoH' };
const EXIT_CHECK = 'https://www.cloudflare.com/cdn-cgi/trace';
const RESOLVER_TEST = 'bash.ws'; // a public DNS test service: it reports which DNS servers looked up its names
const RESOLVER_PROBES = 16; // unique names each proxy is asked to resolve (a pool of DNS servers shows up over several)
const MAX_RESOLVER_CHECKS = 100;
const GEO_CACHE_MS = 10 * 60 * 1000; // ip-api.com's free tier allows 45 requests/minute; cache to stay well under it

const STATIC_FILES = {
  '/': ['index.html', 'text/html; charset=utf-8'],
  '/index.html': ['index.html', 'text/html; charset=utf-8'],
  '/style.css': ['style.css', 'text/css; charset=utf-8'],
  '/app.js': ['app.js', 'text/javascript; charset=utf-8'],
};

// --- Proxy and DNS server addresses ----------------------------------------

const DEFAULT_PORTS = { 'http:': 80, 'https:': 443, 'socks5:': 1080, 'socks5h:': 1080 };

// Accepts scheme://user:pass@host:port, user:pass@host:port, host:port and host:port:user:pass.
function parseProxy(line) {
  const original = line.trim();
  let text = original;
  const colonForm = text.match(/^([^:@/\s]+):(\d{1,5}):([^:\s]+):(\S+)$/);
  if (colonForm) {
    const [, host, port, user, pass] = colonForm;
    text = `http://${encodeURIComponent(user)}:${encodeURIComponent(pass)}@${host}:${port}`;
  } else if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(text)) {
    text = `http://${text}`;
  }

  let url;
  try {
    url = new URL(text);
  } catch {
    throw new Error('not a valid proxy address');
  }
  if (!(url.protocol in DEFAULT_PORTS)) throw new Error(`unsupported proxy type "${url.protocol.slice(0, -1)}"`);

  const host = url.hostname.replace(/^\[|\]$/g, '');
  const port = Number(url.port) || DEFAULT_PORTS[url.protocol];
  if (!host || port < 1 || port > 65535) throw new Error('missing or invalid proxy host/port');

  // A stray "%" in a password is not valid percent-encoding; use the text as typed in that case.
  const decode = (value) => {
    try {
      return decodeURIComponent(value);
    } catch {
      return value;
    }
  };
  const user = url.username ? decode(url.username) : null;
  const pass = user === null ? null : decode(url.password);
  if (user !== null && (Buffer.byteLength(user) > 255 || Buffer.byteLength(pass) > 255)) {
    throw new Error('proxy username/password too long');
  }

  const scheme = url.protocol.startsWith('socks') ? 'socks5' : url.protocol.slice(0, -1);
  // The label is what the UI and exports show: exactly what was typed, so proxies that are otherwise
  // identical (same host:port, different session in the username) stay tellable apart and match what
  // was pasted in. This includes the password: it is never sent anywhere but this proxy itself and the
  // export file this computer writes, so there is nothing gained by hiding it from the person who typed it.
  return { scheme, host, port, user, pass, label: original };
}

// Accepts 8.8.8.8, 8.8.8.8:5353, 2001:4860:4860::8888 and [2001:4860:4860::8888]:53, each optionally
// followed by a name (for example "1.1.1.1 Cloudflare").
function parseDnsServer(line) {
  const [address, ...rest] = line.trim().split(/\s+/);
  const name = rest.join(' ').replace(/^#\s*/, '').slice(0, 60) || null;
  let host = address;
  let port = 53;
  const bracketed = address.match(/^\[([^\]]+)\](?::(\d{1,5}))?$/);
  const withPort = address.match(/^([^:]+):(\d{1,5})$/);
  if (bracketed) {
    host = bracketed[1];
    if (bracketed[2]) port = Number(bracketed[2]);
  } else if (withPort) {
    host = withPort[1];
    port = Number(withPort[2]);
  }
  if (!net.isIP(host) || host.includes('%') || (net.isIPv6(host) && host.includes('.'))) {
    throw new Error('enter the DNS server as an IP address, for example 8.8.8.8');
  }
  if (port < 1 || port > 65535) throw new Error('invalid port');
  const shownHost = net.isIPv6(host) && port !== 53 ? `[${host}]` : host;
  return { kind: 'dns', host, port, label: port === 53 ? host : `${shownHost}:${port}`, name };
}

// --- Connections -----------------------------------------------------------

class ProxyError extends Error {
  // fatal: the connection itself is unusable (unreachable, wrong protocol, bad credentials).
  constructor(message, fatal = false) {
    super(message);
    this.name = 'ProxyError';
    this.fatal = fatal;
  }
}

const SOCKS_ERRORS = {
  1: 'general failure', 2: 'not allowed by ruleset', 3: 'network unreachable', 4: 'host unreachable',
  5: 'connection refused', 6: 'TTL expired', 7: 'command not supported', 8: 'address type not supported',
};

// Destroys the socket when the shared deadline passes and keeps late socket errors from crashing us.
function guard(socket, signal) {
  const onAbort = () => socket.destroy(new Error('timed out'));
  if (signal.aborted) onAbort();
  else signal.addEventListener('abort', onAbort, { once: true });
  socket.once('close', () => signal.removeEventListener('abort', onAbort));
  socket.on('error', () => {});
  return socket;
}

// Buffers incoming bytes so handshakes can await an exact length. `lengthOf` is either a byte
// count or a function that inspects the buffer and returns the total length once it is known.
function createReader(socket) {
  let buffered = Buffer.alloc(0);
  let pending = null;
  let failure = null;

  const settle = () => {
    if (!pending) return;
    if (failure) {
      const { reject } = pending;
      pending = null;
      reject(failure);
      return;
    }
    const need = typeof pending.lengthOf === 'function' ? pending.lengthOf(buffered) : pending.lengthOf;
    if (need != null && buffered.length >= need) {
      const { resolve } = pending;
      pending = null;
      resolve(buffered.subarray(0, need));
      buffered = buffered.subarray(need);
    }
  };
  const onData = (chunk) => {
    buffered = Buffer.concat([buffered, chunk]);
    settle();
  };
  const onFail = (err) => {
    failure ??= err ?? new Error('connection closed by proxy');
    settle();
  };
  socket.on('data', onData);
  socket.on('error', onFail);
  socket.once('close', () => onFail(new Error('connection closed by proxy')));

  return {
    read: (lengthOf) => new Promise((resolve, reject) => {
      pending = { lengthOf, resolve, reject };
      settle();
    }),
    release() {
      socket.off('data', onData);
      socket.off('error', onFail);
      if (buffered.length) socket.unshift(buffered);
    },
  };
}

async function httpConnect(socket, reader, proxy, host, port) {
  const target = net.isIPv6(host) ? `[${host}]:${port}` : `${host}:${port}`;
  const auth = proxy.user === null
    ? ''
    : `Proxy-Authorization: Basic ${Buffer.from(`${proxy.user}:${proxy.pass}`).toString('base64')}\r\n`;
  socket.write(`CONNECT ${target} HTTP/1.1\r\nHost: ${target}\r\n${auth}\r\n`);

  const head = await reader.read((buf) => {
    const end = buf.indexOf('\r\n\r\n');
    return end < 0 ? null : end + 4;
  });
  const code = Number(head.toString('latin1').match(/^HTTP\/1\.[01] (\d{3})/)?.[1] ?? 0);
  if (code === 0) throw new ProxyError('not an HTTP proxy', true);
  if (code === 407) throw new ProxyError('proxy authentication failed (407)', true);
  if (code !== 200) throw new ProxyError(`proxy refused the connection (HTTP ${code})`);
}

function ipv6Bytes(ip) {
  const [head, tail = ''] = ip.split('::');
  const first = head ? head.split(':') : [];
  const last = tail ? tail.split(':') : [];
  const groups = ip.includes('::') ? [...first, ...Array(8 - first.length - last.length).fill('0'), ...last] : first;
  const bytes = Buffer.alloc(16);
  groups.forEach((group, i) => bytes.writeUInt16BE(parseInt(group, 16), i * 2));
  return bytes;
}

// IP literals are sent as addresses so the proxy does not try to resolve them; names are sent as
// names so the proxy resolves them itself.
function socksAddress(host) {
  if (net.isIPv4(host)) return Buffer.from([1, ...host.split('.').map(Number)]);
  if (net.isIPv6(host)) return Buffer.concat([Buffer.from([4]), ipv6Bytes(host)]);
  const name = Buffer.from(host);
  return Buffer.concat([Buffer.from([3, name.length]), name]);
}

function socksReplyLength(buf) {
  if (buf.length < 2) return null;
  if (buf[1] !== 0) return 2; // failure replies are not always padded out to full length
  if (buf.length < 5) return null;
  if (buf[3] === 1) return 10;
  if (buf[3] === 4) return 22;
  return 7 + buf[4];
}

async function socksConnect(socket, reader, proxy, host, port) {
  const hasAuth = proxy.user !== null;
  socket.write(Buffer.from(hasAuth ? [5, 2, 0, 2] : [5, 1, 0]));
  const [version, method] = await reader.read(2);
  if (version !== 5) throw new ProxyError('not a SOCKS5 proxy', true);
  if (method === 2) {
    if (!hasAuth) throw new ProxyError('proxy requires a username and password', true);
    const user = Buffer.from(proxy.user);
    const pass = Buffer.from(proxy.pass);
    socket.write(Buffer.concat([Buffer.from([1, user.length]), user, Buffer.from([pass.length]), pass]));
    const [, status] = await reader.read(2);
    if (status !== 0) throw new ProxyError('proxy authentication failed', true);
  } else if (method !== 0) {
    throw new ProxyError(hasAuth ? 'proxy rejected every authentication method' : 'proxy requires a username and password', true);
  }

  socket.write(Buffer.concat([Buffer.from([5, 1, 0]), socksAddress(host), Buffer.from([port >> 8, port & 255])]));
  const reply = await reader.read(socksReplyLength);
  if (reply[1] !== 0) throw new ProxyError(`SOCKS5 connect failed (${SOCKS_ERRORS[reply[1]] ?? `code ${reply[1]}`})`);
}

async function openTunnel(proxy, host, port, signal) {
  const raw = proxy.scheme === 'https'
    ? tls.connect({ host: proxy.host, port: proxy.port, lookup: lookupViaResolver, servername: net.isIP(proxy.host) ? undefined : proxy.host })
    : net.connect({ host: proxy.host, port: proxy.port, lookup: lookupViaResolver });
  const socket = guard(raw, signal);
  const reader = createReader(socket);
  try {
    if (proxy.scheme === 'socks5') await socksConnect(socket, reader, proxy, host, port);
    else await httpConnect(socket, reader, proxy, host, port);
    reader.release();
    return socket;
  } catch (err) {
    socket.destroy();
    // Anything other than a ProxyError here is a transport failure before the tunnel existed.
    throw err instanceof ProxyError ? err : new ProxyError(describeError(err), true);
  }
}

// `family` (4 or 6) limits the connection to one address family; without it the system picks.
function connectDirect(host, port, signal, family) {
  return new Promise((resolve, reject) => {
    const socket = guard(net.connect({ host, port, lookup: lookupViaResolver, ...(family ? { family } : {}) }), signal);
    socket.once('connect', () => resolve(socket));
    socket.once('error', (err) => reject(new ProxyError(describeError(err), true)));
  });
}

// HTTPS GET through a proxy tunnel, or straight out when `proxy` is null.
async function fetchThrough(proxy, urlString, headers = {}, family, timeoutMs = TIMEOUT_MS) {
  const url = new URL(urlString);
  const signal = AbortSignal.timeout(timeoutMs);
  const port = Number(url.port) || 443;
  const tunnel = proxy
    ? await openTunnel(proxy, url.hostname, port, signal)
    : await connectDirect(url.hostname, port, signal, family);
  const secure = guard(tls.connect({ socket: tunnel, servername: url.hostname }), signal);

  return new Promise((resolve, reject) => {
    const req = https.request({
      host: url.hostname,
      // Without an agent Node assumes port 80 and would send "Host: name:80" over TLS, which some sites redirect.
      port,
      defaultPort: 443,
      path: url.pathname + url.search,
      method: 'GET',
      headers: { accept: 'application/dns-json', 'user-agent': 'dns-lookup', ...headers },
      // Without an agent, Node uses this connection (and asks for Connection: close). With `agent: false` it
      // silently ignores it and opens its own, bypassing the proxy tunnel.
      createConnection: () => secure,
    }, (res) => {
      const parts = [];
      let size = 0;
      res.on('data', (chunk) => {
        size += chunk.length;
        if (size > MAX_RESPONSE_BYTES) {
          secure.destroy();
          reject(new Error('response too large'));
        } else {
          parts.push(chunk);
        }
      });
      res.on('end', () => {
        secure.destroy();
        resolve({ status: res.statusCode, body: Buffer.concat(parts).toString('utf8') });
      });
      res.on('error', reject);
    });
    req.on('error', reject);
    req.end();
  });
}

// --- Lookups ---------------------------------------------------------------

// One address of this computer's own connection, by asking a host that only has records for one family.
async function familyAddress(host, family) {
  const { status, body } = await fetchThrough(null, `https://${host}`, { accept: 'text/plain' }, family);
  const ip = body.trim();
  return status === 200 && net.isIP(ip) ? ip : null;
}

// This computer's own connection, remembered for a few seconds and never allowed to hold the page up. A
// machine can have both an IPv4 and an IPv6 address, so report every one that works.
let directCache = { at: 0, value: null };
async function directConnection() {
  if (Date.now() - directCache.at < 5000) return directCache.value;
  // Each piece has its own limit, so one slow request cannot throw away the answers that did arrive.
  const within = (promise) => Promise.race([promise, new Promise((resolve) => setTimeout(resolve, 3500, null))]).catch(() => null);
  const [trace, v4, v6] = await Promise.all([
    within(exitInfo(null)),
    within(familyAddress('ipv4.icanhazip.com', 4)),
    within(familyAddress('ipv6.icanhazip.com', 6)),
  ]);
  const ips = [...new Set([trace?.exitIp, v4, v6].filter(Boolean))];
  const value = ips.length ? { ip: trace?.exitIp ?? ips[0], ips, country: trace?.country ?? null } : null;
  directCache = { at: Date.now(), value };
  return value;
}

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

// The proxy's own address(es): what its host name points to, or the address itself.
async function proxyAddresses(proxy) {
  if (net.isIP(proxy.host)) return [proxy.host];
  const [v4, v6] = await Promise.all([cares.resolve4(proxy.host).catch(() => []), cares.resolve6(proxy.host).catch(() => [])]);
  return [...new Set([...v4, ...v6])];
}

// Checking many proxies at once means many concurrent calls to each external service; each gets its own
// pool sized to that service, so a slow one (bash.ws's multi-round probing) cannot queue up the others
// (single quick requests to ip-api.com/RDAP) behind it, and a request that hangs is retried on a fresh
// connection rather than waited on for 10 seconds.
function makePool(slots) {
  let free = slots;
  const waiters = [];
  return async function withSlot(task) {
    while (free === 0) await new Promise((resolve) => waiters.push(resolve));
    free--;
    try {
      return await task();
    } finally {
      free++;
      waiters.shift()?.();
    }
  };
}
const withDiscoverySlot = makePool(3); // bash.ws: a small shared community service, be gentle
const withGeoSlot = makePool(6); // ip-api.com + RDAP: one quick request each, no shared multi-round probing
const PROBE_CONCURRENCY = 4;

async function withRetries(task, attempts = 3) {
  let failure;
  for (let attempt = 0; attempt < attempts; attempt++) {
    try {
      return await task();
    } catch (err) {
      failure = err;
      await sleep(300);
    }
  }
  throw failure;
}

// bash.ws's own country/ASN data is enough to tell servers apart, but not where they are: add the same
// public geolocation (city, region, ISP) each exit IP gets, so a DNS server shows the same kind of detail.
// Best-effort per server — one that fails or is rate-limited just keeps its bash.ws-only country/org.
async function enrichResolverGeo(servers) {
  await Promise.all(servers.map((server) => geoLookup(server.ip).then((geo) => {
    if (geo) Object.assign(server, { city: geo.city, region: geo.region, isp: geo.isp });
  }).catch(() => {})));
  return servers;
}

// Finds the DNS servers a proxy (or, with no proxy, this computer) uses. A proxy resolves host names itself,
// so asking it to connect to names only the test service knows makes its DNS servers contact that service,
// which lists who asked. Whether the connection then succeeds does not matter, only that the name is looked up.
function findResolvers(proxy) {
  return withDiscoverySlot(async () => {
    const fetchTest = (path) => withRetries(() => fetchThrough(null, `https://${RESOLVER_TEST}${path}`, { accept: 'application/json, text/plain' }, undefined, 6000));
    const { status, body } = await fetchTest('/id');
    const id = body.trim();
    if (status !== 200 || !/^[a-z0-9]{6,40}$/.test(id)) throw new Error(`the DNS test service gave no test id (HTTP ${status}, ${body.length} bytes)`);

    const names = Array.from({ length: RESOLVER_PROBES }, (_, i) => `${i + 1}.${id}.${RESOLVER_TEST}`);
    const outcomes = [];
    await runPool(names, PROBE_CONCURRENCY, async (name, i) => {
      try {
        if (proxy) (await openTunnel(proxy, name, i % 2 ? 80 : 443, AbortSignal.timeout(7000))).destroy();
        else await cares.resolve4(name);
        outcomes.push('ok');
      } catch {
        outcomes.push('failed');
      }
    });
    // If no probe got through, the proxy never looked anything up, so one quick read is enough.
    const attempts = outcomes.includes('ok') ? 5 : 1;
    for (let attempt = 0; attempt < attempts; attempt++) {
      await sleep(attempt === 0 ? 700 : 1600);
      const reply = await fetchTest(`/dnsleak/test/${id}?json`);
      let rows;
      try {
        rows = JSON.parse(reply.body);
      } catch {
        throw new Error('the DNS test service sent an unreadable answer');
      }
      const servers = parseResolverResults(rows);
      if (servers.length) return servers;
    }
    return [];
  });
}

// Plain HTTPS/HTTP GET, following redirects (RDAP's rdap.org bounces to the right registry). Never
// goes through a proxy: this asks a public database about an address we already know, not the
// proxy itself, so there is nothing to gain by routing it through the tunnel.
function plainGet(urlString, hops = 3) {
  return new Promise((resolve, reject) => {
    const url = new URL(urlString);
    const client = url.protocol === 'http:' ? http : https;
    const req = client.get(url, { headers: { accept: 'application/json', 'user-agent': 'dns-lookup' }, timeout: 5000 }, (res) => {
      if ([301, 302, 303, 307, 308].includes(res.statusCode) && res.headers.location && hops > 0) {
        res.resume();
        return resolve(plainGet(new URL(res.headers.location, url).href, hops - 1));
      }
      const parts = [];
      res.on('data', (c) => parts.push(c));
      res.on('end', () => resolve({ status: res.statusCode, body: Buffer.concat(parts).toString('utf8') }));
    });
    req.on('timeout', () => req.destroy(new Error('timed out')));
    req.on('error', reject);
  });
}

const geoCache = new Map();
async function cached(cache, key, fetcher) {
  const hit = cache.get(key);
  if (hit && Date.now() - hit.at < GEO_CACHE_MS) return hit.value;
  const value = await fetcher();
  cache.set(key, { at: Date.now(), value });
  return value;
}

// Public geolocation for an IP: country/region/city (free-tier accuracy - a rough placement,
// not a physical trace), ISP/org and a best-effort usage-type signal.
async function geoLookup(ip) {
  return withGeoSlot(() => cached(geoCache, `geo:${ip}`, async () => {
    const fields = 'status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,asname,mobile,proxy,hosting,query';
    const { status, body } = await plainGet(`http://ip-api.com/json/${ip}?fields=${fields}`);
    if (status !== 200) throw new Error(`geolocation service returned HTTP ${status}`);
    const json = JSON.parse(body);
    // A rate-limit response ("status":"fail","message":"rate limit") is transient and must not be
    // cached as "no data": throwing here (instead of resolving) skips the cache.set in `cached`, so
    // the next check for this IP tries again rather than showing nothing for the full cache window.
    if (json.message === 'rate limit') throw new Error('geolocation service rate limit reached, try again shortly');
    return parseGeoResult(json);
  }));
}

// Public WHOIS (RDAP) for an IP: which registry allocated it, the network's name and range.
async function whoisLookup(ip) {
  return withGeoSlot(() => cached(geoCache, `whois:${ip}`, async () => {
    const { status, body } = await plainGet(`https://rdap.org/ip/${ip}`);
    if (status !== 200) throw new Error(`WHOIS service returned HTTP ${status}`);
    return parseWhoisResult(JSON.parse(body));
  }));
}

async function exitInfo(proxy, timeoutMs = TIMEOUT_MS) {
  const fetchTrace = (family) => fetchThrough(proxy, EXIT_CHECK, { accept: 'text/plain' }, family, timeoutMs);
  // Straight out, try IPv4 first: on a dual-stack machine whose IPv6 path is stalled, the first address
  // the system picks could otherwise hold the check up until it times out.
  const { status, body } = await (proxy ? fetchTrace() : fetchTrace(4).catch(() => fetchTrace()));
  if (status !== 200) throw new Error(`exit-IP check returned HTTP ${status}`);
  const fields = Object.fromEntries(body.split('\n').map((line) => line.split('=')).filter((pair) => pair.length === 2));
  return {
    exitIp: net.isIP(fields.ip) ? fields.ip : null,
    country: /^[A-Z]{2}$/.test(fields.loc) ? fields.loc : null,
    warp: fields.warp === 'on' || fields.gateway === 'on',
  };
}

async function dohQuery(proxy, resolver, name, type) {
  const url = new URL(DOH[resolver]);
  url.search = new URLSearchParams({ name, type }).toString();
  const { status, body } = await fetchThrough(proxy, url.href);
  if (status !== 200) throw new Error(`resolver returned HTTP ${status}`);
  let data;
  try {
    data = JSON.parse(body);
  } catch {
    throw new Error('resolver sent an unreadable response');
  }
  const answers = (data.Answer ?? []).map((a) => ({ name: a.name, type: a.type, ttl: a.TTL, data: a.data }));
  // Each request opens a fresh tunnel and TLS session, so a timing would measure that, not the resolver.
  return {
    rcode: data.Status,
    ms: null,
    transport: 'HTTPS',
    flags: { aa: null, ra: Boolean(data.RA), ad: Boolean(data.AD) },
    ...splitAnswers(answers, type),
  };
}

async function dnsQuery(proxy, target, name, type) {
  // Through a proxy the query goes over TCP inside the tunnel; directly it goes over UDP.
  const connectTcp = proxy ? (host, port) => openTunnel(proxy, host, port, AbortSignal.timeout(TIMEOUT_MS)) : null;
  const reply = await dnsClient.query({ server: target.host, port: target.port, name, type, timeoutMs: DNS_TIMEOUT_MS, connectTcp });
  return {
    rcode: reply.rcode,
    ms: reply.ms,
    transport: reply.transport,
    flags: reply.flags,
    ...splitAnswers(reply.answers, type),
  };
}

async function runPool(items, limit, fn) {
  let next = 0;
  const worker = async () => {
    while (next < items.length) {
      const i = next++;
      await fn(items[i], i);
    }
  };
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, worker));
}

async function processVantage(vantage, p, targets, hosts, emit, isClosed, wantResolvers) {
  const info = vantage.proxy
    ? proxyAddresses(vantage.proxy).catch(() => []).then((ips) => emit({ event: 'proxyinfo', p, ips }))
    : Promise.resolve();
  let exitIp = null;
  try {
    // One retry: a request that hangs once (a network hiccup) usually works on a fresh connection. A proxy that
    // failed outright (refused, wrong password) is not retried.
    const exit = await exitInfo(vantage.proxy, 6000).catch((err) => {
      if (err.fatal) throw err;
      return exitInfo(vantage.proxy, 6000);
    });
    exitIp = exit.exitIp;
    emit({ event: 'vantage', p, ok: true, ...exit });
  } catch (err) {
    if (err.fatal) {
      // A proxy that failed outright is not asked about its DNS servers or its exit IP's geo/WHOIS.
      emit({ event: 'vantage', p, ok: false, error: describeError(err) });
      return info;
    }
    // Reachable, but the exit-IP check failed; carry on without exit details.
    emit({ event: 'vantage', p, ok: true, exitIp: null, country: null, warp: false, warning: describeError(err) });
  }

  // The proxy answers, so find its DNS servers now; this runs alongside the lookups below and is awaited at the end.
  const resolversTask = wantResolvers && vantage.proxy
    ? findResolvers(vantage.proxy)
      .then((servers) => enrichResolverGeo(servers))
      .then((servers) => emit({ event: 'resolvers', p, ok: true, servers }))
      .catch((err) => emit({ event: 'resolvers', p, ok: false, error: describeError(err) }))
    : Promise.resolve();

  // Public geolocation and WHOIS for the exit IP itself; never asked through the proxy (see plainGet).
  const geoTask = exitIp
    ? Promise.allSettled([geoLookup(exitIp), whoisLookup(exitIp)])
      .then(([geo, whois]) => emit({
        event: 'geoinfo', p,
        geo: geo.status === 'fulfilled' ? geo.value : null,
        whois: whois.status === 'fulfilled' ? whois.value : null,
        error: geo.status === 'rejected' && whois.status === 'rejected' ? describeError(geo.reason) : null,
      }))
    : Promise.resolve();

  let dead = false;
  // A DNS server that has not answered its first few queries is treated as down for the rest of
  // the run, so one bad entry cannot hold up a long list for minutes of timeouts.
  const health = targets.map(() => ({ timeouts: 0, answered: 0 }));
  const jobs = targets.flatMap((target, t) => (target.error ? [] : hosts.flatMap((host) =>
    Object.keys(RECORD_TYPES).map((type) => ({ target, t, host, type })))));
  await runPool(jobs, QUERY_CONCURRENCY, async ({ target, t, host, type }) => {
    if (dead || isClosed()) return;
    if (target.kind === 'dns' && health[t].answered === 0 && health[t].timeouts >= DNS_GIVE_UP) {
      return emit({ event: 'result', p, t, host, type, ok: false, error: `no reply (skipped after ${DNS_GIVE_UP} timeouts)` });
    }
    try {
      const reply = target.kind === 'doh'
        ? await dohQuery(vantage.proxy, target.resolver, host, type)
        : await dnsQuery(vantage.proxy, target, host, type);
      health[t].answered++;
      emit({ event: 'result', p, t, host, type, ok: true, ...reply });
    } catch (err) {
      if (target.kind === 'dns' && describeError(err) === 'timed out') health[t].timeouts++;
      // A DNS server that cannot be reached says nothing about the proxy, so only the
      // DNS-over-HTTPS path (a known-good endpoint) can mark the proxy itself as dead.
      if (err.fatal && target.kind === 'doh') {
        dead = true;
        emit({ event: 'vantage', p, ok: false, error: describeError(err) });
      } else {
        emit({ event: 'result', p, t, host, type, ok: false, error: describeError(err) });
      }
    }
  });
  await Promise.all([info, resolversTask, geoTask]);
}

// --- HTTP server -----------------------------------------------------------

function sendJson(res, status, body) {
  res.writeHead(status, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' });
  res.end(JSON.stringify(body));
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    const parts = [];
    let size = 0;
    req.on('data', (chunk) => {
      size += chunk.length;
      if (size > MAX_BODY_BYTES) {
        reject(new Error('request too large'));
        req.destroy();
      } else {
        parts.push(chunk);
      }
    });
    req.on('end', () => resolve(Buffer.concat(parts).toString('utf8')));
    req.on('error', reject);
  });
}

const isLineList = (value, max) =>
  Array.isArray(value) && value.length <= max && value.every((line) => typeof line === 'string' && line.length < 400);

async function handleLookup(req, res) {
  if (!/^application\/json/i.test(req.headers['content-type'] ?? '')) {
    return sendJson(res, 415, { error: 'Expected a JSON request body.' });
  }
  let payload;
  try {
    payload = JSON.parse(await readBody(req));
  } catch {
    return sendJson(res, 400, { error: 'The request body is not valid JSON.' });
  }

  const { proxies = [], dns = [], hosts, resolver = 'google', resolvers: wantResolvers = false } = payload ?? {};
  if (!isLineList(proxies, MAX_PROXIES)) return sendJson(res, 400, { error: `Send at most ${MAX_PROXIES} proxies.` });
  if (!isLineList(dns, MAX_DNS_SERVERS)) return sendJson(res, 400, { error: `Send at most ${MAX_DNS_SERVERS} DNS servers.` });
  if (proxies.length + dns.length < 1) return sendJson(res, 400, { error: 'Add at least one proxy or DNS server.' });
  // Domains are optional when the request only asks about proxies (their addresses and DNS servers).
  const minHosts = proxies.length > 0 && dns.length === 0 ? 0 : 1;
  if (!Array.isArray(hosts) || hosts.length < minHosts || hosts.length > MAX_HOSTS || !hosts.every(isValidHost)) {
    return sendJson(res, 400, { error: `Send ${minHosts === 0 ? 'up to' : 'between 1 and'} ${MAX_HOSTS} valid domain names.` });
  }
  if (!(resolver in DOH)) return sendJson(res, 400, { error: 'Unknown resolver.' });

  const parse = (parser, line, i) => {
    try {
      return parser(line);
    } catch (err) {
      return { error: err.message, label: `line ${i + 1}` };
    }
  };
  const vantages = proxies.length
    ? proxies.map((line, i) => {
      const entry = parse(parseProxy, line, i);
      return { proxy: entry.error ? null : entry, label: entry.label, error: entry.error ?? null };
    })
    : [{ proxy: null, label: 'Direct (this machine)', error: null }];
  const targets = dns.length
    ? dns.map((line, i) => ({ error: null, ...parse(parseDnsServer, line, i) }))
    : [{ kind: 'doh', resolver, label: DOH_LABELS[resolver], name: null, error: null }];

  const runnableVantages = vantages.filter((v) => !v.error).length;
  const runnableTargets = targets.filter((t) => !t.error).length;
  const jobCount = runnableVantages * runnableTargets * hosts.length * Object.keys(RECORD_TYPES).length;
  if (jobCount > MAX_JOBS) {
    return sendJson(res, 400, { error: `That is ${jobCount} lookups; the limit is ${MAX_JOBS}. Use fewer sites, proxies or DNS servers.` });
  }

  let closed = false;
  res.on('close', () => { closed = !res.writableFinished; });
  res.writeHead(200, {
    'content-type': 'application/x-ndjson; charset=utf-8',
    'cache-control': 'no-store',
    'x-content-type-options': 'nosniff',
  });
  const emit = (message) => {
    if (!closed) res.write(`${JSON.stringify(message)}\n`);
  };

  emit({
    event: 'start',
    viaProxies: proxies.length > 0,
    dnsList: dns.length > 0,
    vantages: vantages.map(({ label, error }) => ({ label, error })),
    targets: targets.map(({ label, name, error }) => ({ label, name, error })),
  });
  const lowered = hosts.map((host) => host.toLowerCase());
  const runnable = vantages.flatMap((vantage, p) => (vantage.error ? [] : [{ vantage, p }]));
  // This computer's own DNS servers, so each proxy's can be compared with them.
  const checkResolvers = wantResolvers === true && proxies.length > 0;
  const baseline = checkResolvers
    ? findResolvers(null)
      .then((servers) => enrichResolverGeo(servers))
      .then((servers) => emit({ event: 'baseline', ok: true, servers }))
      .catch((err) => emit({ event: 'baseline', ok: false, error: describeError(err) }))
    : Promise.resolve();
  // This computer's own direct IP (never through a proxy), so each proxy's exit IP can be compared with
  // it: a proxy whose exit matches is not actually changing your address.
  const directTask = proxies.length > 0
    ? directConnection()
      .then((direct) => emit({ event: 'directinfo', ok: Boolean(direct), ...direct }))
      .catch((err) => emit({ event: 'directinfo', ok: false, error: describeError(err) }))
    : Promise.resolve();
  // Each DNS server's own location/ISP (it is a public IP already known from the box, not sent
  // anything), so the summary table can show where a server actually is, not just its address.
  const targetGeoTasks = targets.map((target, t) => (target.error || target.kind !== 'dns' ? Promise.resolve() :
    geoLookup(target.host)
      .then((geo) => emit({ event: 'targetgeo', t, ok: true, geo }))
      .catch((err) => emit({ event: 'targetgeo', t, ok: false, error: describeError(err) }))));
  await runPool(runnable, PROXY_CONCURRENCY, ({ vantage, p }) =>
    processVantage(vantage, p, targets, lowered, emit, () => closed, checkResolvers && p < MAX_RESOLVER_CHECKS));
  await Promise.all([baseline, directTask, ...targetGeoTasks]);
  emit({ event: 'done' });
  res.end();
}

function serveStatic(pathname, res) {
  const entry = STATIC_FILES[pathname];
  if (!entry) return sendJson(res, 404, { error: 'Not found' });
  fs.readFile(path.join(__dirname, entry[0]), (err, data) => {
    if (err) return sendJson(res, 500, { error: 'Could not read file' });
    res.writeHead(200, { 'content-type': entry[1], 'cache-control': 'no-store' });
    res.end(data);
  });
}

const server = http.createServer((req, res) => {
  // Refuse foreign Host headers so a hostile web page cannot reach this server via DNS rebinding.
  if (!/^(127\.0\.0\.1|localhost|\[::1\])(:\d+)?$/.test(req.headers.host ?? '')) {
    return sendJson(res, 403, { error: 'Forbidden' });
  }
  const { pathname } = new URL(req.url, 'http://localhost');
  if (req.method === 'GET' && pathname === '/api/status') {
    sendJson(res, 200, { serverMode: true }); // lets the page know proxies and DNS server lists are available
  } else if (req.method === 'GET' && pathname === '/api/whoami') {
    // Browsers skip their proxy for localhost, so the proxied address cannot be seen from here. Report this
    // computer's own connection instead, so the page can compare it with what the browser shows.
    directConnection()
      .then((direct) => sendJson(res, 200, { local: true, direct }))
      .catch(() => sendJson(res, 200, { local: true, direct: null }));
  } else if (req.method === 'POST' && pathname === '/api/lookup') {
    handleLookup(req, res).catch(() => {
      if (!res.headersSent) sendJson(res, 500, { error: 'Something went wrong.' });
      else res.end();
    });
  } else if (req.method === 'GET') {
    serveStatic(pathname, res);
  } else {
    sendJson(res, 405, { error: 'Method not allowed' });
  }
});

server.on('error', (err) => {
  console.error(err.code === 'EADDRINUSE' ? `Port ${PORT} is already in use. Try PORT=9000 node server.js` : err.message);
  process.exit(1);
});
server.listen(PORT, BIND, () => console.log(`DNS lookup running at http://${BIND}:${PORT}`));
