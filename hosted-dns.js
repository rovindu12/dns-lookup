'use strict';

// The hosted site's DNS endpoint (runs as a Netlify Function). Unlike the local server, anyone on the
// internet can reach it, so it is deliberately narrow: DNS only (UDP port 53), public IP addresses only,
// one DNS server and a few domains per request, same-origin callers only, and no proxies.

const net = require('net');
const dnsClient = require('./dns-client');
const { RECORD_TYPES, isValidHost, describeError, splitAnswers } = require('./lookup-common');
const { checkQuota } = require('./billing');

const MAX_HOSTS = 5;
const MAX_BODY_BYTES = 4096;
const QUERY_TIMEOUT_MS = 2500;
const DEADLINE_MS = 8000; // Netlify stops synchronous functions at 10 s
const RATE_LIMIT = { windowMs: 60 * 1000, max: 60 }; // requests per client address, per warm instance

// Ranges a DNS server must never be in: private, loopback, link-local (cloud metadata lives at
// 169.254.169.254), shared address space, documentation, benchmarking, multicast and reserved.
const BLOCKED_IPV4 = [
  ['0.0.0.0', 8], ['10.0.0.0', 8], ['100.64.0.0', 10], ['127.0.0.0', 8], ['169.254.0.0', 16],
  ['172.16.0.0', 12], ['192.0.0.0', 24], ['192.0.2.0', 24], ['192.88.99.0', 24], ['192.168.0.0', 16],
  ['198.18.0.0', 15], ['198.51.100.0', 24], ['203.0.113.0', 24], ['224.0.0.0', 4], ['240.0.0.0', 4],
];

const ipv4ToInt = (ip) => ip.split('.').reduce((n, part) => n * 256 + Number(part), 0);

function isPublicIPv4(ip) {
  const parts = ip.split('.');
  // Only canonical dotted decimals: "010.0.0.1" is octal to some resolvers and could dodge the range checks.
  if (parts.length !== 4 || parts.some((part) => String(Number(part)) !== part || Number(part) > 255)) return false;
  const n = ipv4ToInt(ip);
  return !BLOCKED_IPV4.some(([base, bits]) => n >= ipv4ToInt(base) && n < ipv4ToInt(base) + 2 ** (32 - bits));
}

function ipv6Groups(ip) {
  if (!net.isIPv6(ip) || ip.includes('%') || ip.includes('.')) return null;
  const [head, tail = ''] = ip.split('::');
  const first = head ? head.split(':') : [];
  const last = tail ? tail.split(':') : [];
  const groups = ip.includes('::') ? [...first, ...Array(8 - first.length - last.length).fill('0'), ...last] : first;
  return groups.length === 8 ? groups.map((group) => parseInt(group, 16)) : null;
}

// Global unicast (2000::/3) only, minus documentation, Teredo and 6to4 ranges.
function isPublicIPv6(ip) {
  const g = ipv6Groups(ip);
  if (!g || g[0] < 0x2000 || g[0] > 0x3fff) return false;
  if (g[0] === 0x2001 && (g[1] === 0x0db8 || g[1] === 0)) return false;
  if (g[0] === 0x2002) return false;
  if (g[0] === 0x3fff && g[1] < 0x1000) return false;
  return true;
}

function isPublicAddress(ip) {
  if (typeof ip !== 'string') return false;
  if (net.isIPv4(ip)) return isPublicIPv4(ip);
  if (net.isIPv6(ip)) return isPublicIPv6(ip);
  return false;
}

const recentHits = new Map();
function rateLimited(key, now = Date.now()) {
  const recent = (recentHits.get(key) ?? []).filter((time) => now - time < RATE_LIMIT.windowMs);
  recent.push(now);
  recentHits.set(key, recent);
  if (recentHits.size > 5000) recentHits.clear(); // bounded memory
  return recent.length > RATE_LIMIT.max;
}

const json = (status, body) => new Response(JSON.stringify(body), {
  status,
  headers: {
    'content-type': 'application/json; charset=utf-8',
    'cache-control': 'no-store',
    'x-content-type-options': 'nosniff',
  },
});

async function runQueries(server, hosts) {
  let timer;
  const deadline = new Promise((resolve, reject) => {
    timer = setTimeout(() => reject(Object.assign(new Error('timed out'), { code: 'ETIMEDOUT' })), DEADLINE_MS);
  });
  const jobs = hosts.flatMap((host) => Object.keys(RECORD_TYPES).map((type) => ({ host, type })));
  try {
    return await Promise.all(jobs.map(async ({ host, type }) => {
      try {
        const reply = await Promise.race([
          dnsClient.query({ server, port: 53, name: host, type, timeoutMs: QUERY_TIMEOUT_MS }),
          deadline,
        ]);
        return {
          host, type, ok: true,
          rcode: reply.rcode, ms: reply.ms, transport: reply.transport, flags: reply.flags,
          ...splitAnswers(reply.answers, type),
        };
      } catch (err) {
        return { host, type, ok: false, error: describeError(err) };
      }
    }));
  } finally {
    clearTimeout(timer);
  }
}

const status = () => json(200, { serverMode: false, hostedDns: true, region: process.env.AWS_REGION ?? null });

// What this site's server sees of the caller: the address the request came from (the proxy's address when
// the browser uses a proxy), Netlify's location estimate for it, and any proxy headers on the request.
// Only the caller's own information is returned, and only to the caller.
const clip = (value) => (value ? String(value).slice(0, 200) : null);

function whoami(req, context = {}) {
  const geo = context.geo ?? {};
  return json(200, {
    ip: context.ip ?? req.headers.get('x-nf-client-connection-ip') ?? null,
    geo: {
      city: geo.city ?? null,
      region: geo.subdivision?.name ?? null,
      country: geo.country?.name ?? null,
      countryCode: geo.country?.code ?? null,
      timezone: geo.timezone ?? null,
    },
    headers: { via: clip(req.headers.get('via')), forwarded: clip(req.headers.get('forwarded')) },
    region: process.env.AWS_REGION ?? null,
  });
}

async function handle(req, context = {}) {
  const url = new URL(req.url);
  if (url.pathname === '/api/status') return status();
  if (req.method !== 'POST') return json(405, { error: 'Use POST.' });

  // Only this site's own pages may call the endpoint from a browser.
  const origin = req.headers.get('origin');
  const fetchSite = req.headers.get('sec-fetch-site');
  if ((origin && origin !== url.origin) || (fetchSite && fetchSite !== 'same-origin' && fetchSite !== 'none')) {
    return json(403, { error: 'Cross-site requests are not allowed.' });
  }
  if (!/^application\/json/i.test(req.headers.get('content-type') ?? '')) {
    return json(415, { error: 'Expected a JSON request body.' });
  }
  const client = context.ip ?? req.headers.get('x-nf-client-connection-ip') ?? 'unknown';
  if (rateLimited(client)) return json(429, { error: 'Too many requests. Wait a minute and try again.' });

  if (Number(req.headers.get('content-length') ?? 0) > MAX_BODY_BYTES) return json(413, { error: 'Request too large.' });
  const text = await req.text();
  if (text.length > MAX_BODY_BYTES) return json(413, { error: 'Request too large.' });
  let payload;
  try {
    payload = JSON.parse(text);
  } catch {
    return json(400, { error: 'The request body is not valid JSON.' });
  }

  const { server, hosts } = payload ?? {};
  if (!isPublicAddress(server)) {
    return json(400, { error: 'The DNS server must be a public IP address (private, local and reserved ranges are not allowed).' });
  }
  if (!Array.isArray(hosts) || hosts.length < 1 || hosts.length > MAX_HOSTS || !hosts.every(isValidHost)) {
    return json(400, { error: `Send between 1 and ${MAX_HOSTS} valid domain names.` });
  }

  let quota;
  try {
    quota = await checkQuota({ apiKey: req.headers.get('x-api-key'), ip: client });
  } catch {
    return json(503, { error: 'Usage tracking is temporarily unavailable. Try again shortly.' });
  }
  if (!quota.allowed) return json(quota.status, { error: quota.error });

  const results = await runQueries(server, hosts.map((host) => host.toLowerCase()));
  return json(200, {
    server, region: process.env.AWS_REGION ?? null, results,
    usage: { plan: quota.plan, limit: quota.limit, remaining: quota.remaining },
  });
}

module.exports = { handle, status, whoami, isPublicAddress, MAX_HOSTS };
