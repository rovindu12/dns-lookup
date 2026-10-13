'use strict';

const RESOLVERS = {
  cloudflare: 'https://cloudflare-dns.com/dns-query',
  google: 'https://dns.google/resolve',
};
const TYPE_NAMES = { 1: 'A', 2: 'NS', 5: 'CNAME', 6: 'SOA', 15: 'MX', 16: 'TXT', 28: 'AAAA', 257: 'CAA' };
const TYPE_ORDER = ['CNAME', 'A', 'AAAA', 'NS', 'MX', 'TXT', 'SOA', 'CAA'];
const RCODE_NAMES = { 0: 'NOERROR', 1: 'FORMERR', 2: 'SERVFAIL', 3: 'NXDOMAIN', 4: 'NOTIMP', 5: 'REFUSED' };
const CONCURRENCY = 8;
const TIMEOUT_MS = 8000;
const MAX_DETAIL_IPS = 300;

const $ = (id) => document.getElementById(id);
const form = $('form');
const input = $('input');
const goButton = $('go');
const summary = $('summary');
const notice = $('notice');
const toolbar = $('toolbar');
const results = $('results');
const proxiesInput = $('proxies');
const dnsInput = $('dns');
const resolversBox = $('resolvers');
const detailsBox = $('details');
const typesFieldset = $('types');
const stopButton = $('stop');
const apiKeyInput = $('apikey');

let lastRun = [];
let serverRun = null;
let lastMode = 'browser'; // 'browser' or 'server'
let controller = null;
let backend = 'none'; // 'local' (node server.js), 'hosted' (the site's function) or 'none'
const ipInfo = new Map(); // address -> { ptr, asn, org, prefix, country }, kept for the page session
let detailsActive = false; // whether the results on screen (and their exports) include IP details

// API key for the hosted lookup's paid tier: kept only in this browser, never in exports.
try {
  const savedKey = localStorage.getItem('dns-lookup-api-key');
  if (savedKey && apiKeyInput) apiKeyInput.value = savedKey;
} catch { /* localStorage unavailable (private mode, blocked storage) — the field just starts empty */ }
apiKeyInput?.addEventListener('change', () => {
  try {
    if (apiKeyInput.value.trim()) localStorage.setItem('dns-lookup-api-key', apiKeyInput.value.trim());
    else localStorage.removeItem('dns-lookup-api-key');
  } catch { /* localStorage unavailable; the key still works for this page load */ }
});
function hostedHeaders() {
  const key = apiKeyInput?.value.trim();
  return key ? { 'content-type': 'application/json', 'x-api-key': key } : { 'content-type': 'application/json' };
}

// --- Input parsing ---------------------------------------------------------

const LABEL = /^[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?$/;

function toHostname(token) {
  const cleaned = token.replace(/^["'<(\[]+|["'>)\],;]+$/g, '');
  if (!cleaned) return null;
  const withScheme = /^[a-z][a-z0-9+.-]*:\/\//i.test(cleaned) ? cleaned : `http://${cleaned}`;
  let host;
  try {
    host = new URL(withScheme).hostname;
  } catch {
    return null;
  }
  host = host.replace(/\.$/, '');
  const labels = host.split('.');
  const valid = host.length <= 253
    && labels.length >= 2
    && labels.every((label) => LABEL.test(label))
    && !/^\d+$/.test(labels[labels.length - 1]); // rejects IPv4 addresses
  return valid ? host : null;
}

function parseSites(text) {
  const sites = new Map();
  const skipped = [];
  for (const token of text.split(/[\s,]+/).filter(Boolean)) {
    const host = toHostname(token);
    if (!host) skipped.push(token);
    else if (!sites.has(host)) sites.set(host, token);
  }
  return { sites: [...sites].map(([host, source]) => ({ host, source })), skipped };
}

// --- DNS-over-HTTPS --------------------------------------------------------

async function query(resolver, name, type) {
  const url = new URL(RESOLVERS[resolver]);
  url.search = new URLSearchParams({ name, type }).toString();
  const res = await fetch(url, {
    headers: { accept: 'application/dns-json' },
    signal: AbortSignal.timeout(TIMEOUT_MS),
  });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res.json();
}

function describeError(err) {
  return err.name === 'TimeoutError' ? 'timed out' : err.message;
}

// Bytes of one quoted TXT string in DNS presentation format: \DDD is a decimal byte, \X is a literal X.
function txtBytes(body) {
  const encoder = new TextEncoder();
  const bytes = [];
  for (const [, decimal, escaped, plain] of body.matchAll(/\\(\d{3})|\\([^])|([^\\]+)/g)) {
    if (decimal !== undefined) bytes.push(Number(decimal));
    else bytes.push(...encoder.encode(escaped ?? plain));
  }
  return bytes;
}

function cleanValue(type, data) {
  if (type === 'TXT') {
    const strings = [...data.matchAll(/"((?:[^"\\]|\\[^])*)"/g)];
    if (!strings.length) return data;
    // A TXT record is a list of strings (each at most 255 bytes) that readers concatenate. Join the
    // bytes before decoding so a multi-byte character split across two strings survives.
    return new TextDecoder().decode(Uint8Array.from(strings.flatMap(([, body]) => txtBytes(body))));
  }
  return data.replace(/(\S)\.(?=\s|$)/g, '$1'); // drop trailing dots, but keep a lone "." (null MX)
}

function addRecord(site, answer) {
  const type = TYPE_NAMES[answer.type] ?? `TYPE${answer.type}`;
  const record = {
    name: answer.name.replace(/\.$/, ''),
    type,
    value: cleanValue(type, answer.data),
    ttl: answer.TTL,
  };
  site.records.set(`${record.name}|${type}|${record.value}`, record);
}

function sortedRecords(site) {
  const rank = (type) => {
    const i = TYPE_ORDER.indexOf(type);
    return i < 0 ? TYPE_ORDER.length : i;
  };
  const priority = (r) => (r.type === 'MX' ? parseInt(r.value, 10) : 0);
  return [...site.records.values()].sort((a, b) => rank(a.type) - rank(b.type) || priority(a) - priority(b));
}

async function lookup(sites, types, resolver) {
  lastMode = 'browser';
  results.replaceChildren();
  lastRun = sites.map(({ host, source }) => ({
    host,
    source,
    typeCount: types.length,
    pending: types.length,
    records: new Map(),
    rcodes: [],
    errors: [],
    card: h('article', { class: 'card' }),
  }));
  for (const site of lastRun) {
    renderCard(site, types.length);
    results.append(site.card);
  }

  const jobs = lastRun.flatMap((site) => types.map((type) => ({ site, type })));
  let next = 0;
  let done = 0;

  async function worker() {
    while (next < jobs.length) {
      const { site, type } = jobs[next++];
      try {
        const data = await query(resolver, site.host, type);
        site.rcodes.push(data.Status);
        // NXDOMAIN is a real answer (the name does not exist); anything else non-zero means the
        // resolver could not answer, which must not be mistaken for "no such record".
        if (data.Status !== 0 && data.Status !== 3) {
          site.errors.push({ type, message: RCODE_NAMES[data.Status] ?? `rcode ${data.Status}` });
        }
        for (const answer of data.Answer ?? []) addRecord(site, answer);
      } catch (err) {
        site.errors.push({ type, message: describeError(err) });
      }
      site.pending--;
      done++;
      renderCard(site, types.length);
      summary.textContent = `Completed ${done} of ${jobs.length} queries…`;
    }
  }

  await Promise.all(Array.from({ length: Math.min(CONCURRENCY, jobs.length) }, worker));
  const total = lastRun.reduce((n, site) => n + site.records.size, 0);
  summary.textContent = `Done: ${total} record${total === 1 ? '' : 's'} across ${lastRun.length} site${lastRun.length === 1 ? '' : 's'}.`;
}

// --- Rendering (DOM nodes + textContent only; DNS data is untrusted) -------

function h(tag, attrs = {}, ...children) {
  const el = document.createElement(tag);
  for (const [key, value] of Object.entries(attrs)) el.setAttribute(key, value);
  el.append(...children);
  return el;
}

function cardStatus(site, typeCount) {
  if (site.pending > 0) return { kind: 'pending', text: 'Looking up…' };
  if (site.records.size > 0) {
    const n = site.records.size;
    const text = `${n} record${n === 1 ? '' : 's'}`;
    return site.errors.length ? { kind: 'warn', text: `${text} · incomplete` } : { kind: 'ok', text };
  }
  if (site.rcodes.includes(3)) return { kind: 'error', text: 'Not found (NXDOMAIN)' };
  if (site.errors.length === typeCount) return { kind: 'error', text: 'Lookup failed' };
  if (site.errors.length) return { kind: 'error', text: 'Incomplete lookup' };
  return { kind: 'warn', text: 'No records' };
}

function renderCard(site, typeCount) {
  const status = cardStatus(site, typeCount);
  const head = h('div', { class: 'card-head' }, h('h2', {}, site.host));
  if (site.source !== site.host) head.append(h('span', { class: 'source' }, site.source));
  head.append(h('span', { class: `badge ${status.kind}` }, status.text));
  site.card.replaceChildren(head);

  const records = sortedRecords(site);
  if (records.length) {
    // The name only carries information when the answer came from elsewhere (e.g. a CNAME chain).
    const showName = records.some((r) => r.name !== site.host);
    const isAddress = (r) => r.type === 'A' || r.type === 'AAAA';
    const showDetails = records.some((r) => isAddress(r) && describeIp(r.value));
    const body = h('tbody');
    for (const r of records) {
      const row = h('tr', {}, h('td', { class: 'type' }, r.type));
      if (showName) row.append(h('td', { class: 'name' }, r.name));
      row.append(h('td', { class: 'value' }, r.value), h('td', { class: 'ttl' }, `${r.ttl}s`));
      if (showDetails) row.append(h('td', { class: 'detail-cell' }, isAddress(r) ? describeIp(r.value) : ''));
      body.append(row);
    }
    const headings = ['Type', ...(showName ? ['Name'] : []), 'Value', 'TTL', ...(showDetails ? ['IP details'] : [])];
    const table = h('table', {},
      h('thead', {}, h('tr', {}, ...headings.map((text) => h('th', {}, text)))),
      body,
    );
    site.card.append(h('div', { class: 'table-wrap' }, table));
  }

  if (site.errors.length && site.pending === 0) {
    const detail = site.errors.map((e) => `${e.type} (${e.message})`).join(', ');
    site.card.append(h('p', { class: 'card-errors' }, `Some queries failed: ${detail}`));
  }
}

// --- IP details: reverse DNS and network owner, looked up over DNS ---------
// The network owner comes from Team Cymru's DNS-based IP-to-ASN mapping (origin.asn.cymru.com),
// which reports the BGP origin AS and the registry that allocated the prefix.

const isIPv4 = (ip) => /^\d{1,3}(\.\d{1,3}){3}$/.test(ip);
const isIPv6 = (ip) => ip.includes(':') && /^[0-9a-f:]+$/i.test(ip);

async function answersOf(resolver, name, type, code) {
  const data = await query(resolver, name, type);
  if (data.Status !== 0 && data.Status !== 3) throw new Error(RCODE_NAMES[data.Status] ?? `rcode ${data.Status}`);
  return (data.Answer ?? []).filter((answer) => answer.type === code);
}

function expandIPv6(ip) {
  const [head, tail = ''] = ip.split('::');
  const first = head ? head.split(':') : [];
  const last = tail ? tail.split(':') : [];
  const groups = ip.includes('::') ? [...first, ...Array(8 - first.length - last.length).fill('0'), ...last] : first;
  return groups.map((group) => group.padStart(4, '0')).join('');
}

// 8.8.4.4 -> 4.4.8.8; IPv6 addresses are reversed nibble by nibble.
function reverseLabels(ip) {
  return isIPv6(ip) ? [...expandIPv6(ip)].reverse().join('.') : ip.split('.').reverse().join('.');
}

const asnNames = new Map();
function asnName(resolver, asn) {
  if (!asnNames.has(asn)) {
    const pending = answersOf(resolver, `AS${asn}.asn.cymru.com`, 'TXT', 16)
      .then(([record]) => (record ? cleanValue('TXT', record.data).split('|')[4]?.trim() || null : null));
    asnNames.set(asn, pending);
    pending.catch(() => asnNames.delete(asn)); // failures are not remembered
  }
  return asnNames.get(asn);
}

async function lookupNetwork(resolver, ip) {
  const zone = isIPv6(ip) ? 'origin6.asn.cymru.com' : 'origin.asn.cymru.com';
  const records = await answersOf(resolver, `${reverseLabels(ip)}.${zone}`, 'TXT', 16);
  // Several announced prefixes can cover one address (say a /20 and a /24). Routers use the most
  // specific one, so report that, whatever order the records arrive in.
  const prefixLength = (fields) => Number(fields[1]?.split('/')[1] ?? -1);
  const [best] = records
    .map((record) => cleanValue('TXT', record.data).split('|').map((part) => part.trim()))
    .sort((a, b) => prefixLength(b) - prefixLength(a));
  if (!best) return {};
  const [asns, prefix, country] = best;
  const asn = asns?.split(/\s+/)[0];
  if (!/^\d+$/.test(asn ?? '')) return {};
  return { asn, prefix: prefix || null, country: country || null, org: await asnName(resolver, asn) };
}

async function lookupPtr(resolver, ip) {
  const arpa = isIPv6(ip) ? 'ip6.arpa' : 'in-addr.arpa';
  const [record] = await answersOf(resolver, `${reverseLabels(ip)}.${arpa}`, 'PTR', 12);
  return record ? cleanValue('PTR', record.data) : null;
}

async function loadIpDetails(ips, resolver, isCancelled, onProgress) {
  const todo = ips.filter((ip) => (isIPv4(ip) || isIPv6(ip)) && !ipInfo.has(ip)).slice(0, MAX_DETAIL_IPS);
  let next = 0;
  let done = 0;
  async function worker() {
    while (next < todo.length && !isCancelled()) {
      const ip = todo[next++];
      // Keep whatever part answered: many networks' reverse DNS fails while the network owner is fine.
      const [ptr, network] = await Promise.allSettled([lookupPtr(resolver, ip), lookupNetwork(resolver, ip)]);
      if (ptr.status === 'fulfilled' || network.status === 'fulfilled') {
        ipInfo.set(ip, { ptr: ptr.value ?? null, ...(network.value ?? {}) });
      } // else: not cached, so the next run tries again; this address just shows no details
      onProgress(++done, todo.length);
    }
  }
  await Promise.all(Array.from({ length: Math.min(CONCURRENCY, todo.length) }, worker));
}

function describeIp(ip) {
  const info = detailsActive ? ipInfo.get(ip) : null;
  if (!info) return '';
  const parts = [];
  if (info.ptr) parts.push(info.ptr);
  if (info.asn) parts.push(`AS${info.asn}${info.org ? ` ${info.org}` : ''}`);
  if (info.prefix) parts.push(info.country ? `${info.prefix} · registered ${info.country}` : info.prefix);
  return parts.join(' · ');
}

function detailFields(ip) {
  const info = detailsActive ? ipInfo.get(ip) : null;
  return {
    ptr: info?.ptr ?? '',
    asn: info?.asn ? `AS${info.asn}` : '',
    network: info?.org ?? '',
    prefix: info?.prefix ?? '',
    country: info?.country ?? '',
  };
}

// --- Server mode: proxies and DNS servers, queried by the local server ------

const IP_TYPES = ['A', 'AAAA'];
const rcodeLabel = (code) => RCODE_NAMES[code] ?? `rcode ${code}`;

// A query failed if it errored, or the server answered with anything but NOERROR / NXDOMAIN.
const cellFailed = (cell) => !cell.ok || (cell.rcode !== 0 && cell.rcode !== 3);

const liveVantages = (run) => run.vantages.map((vantage, p) => ({ vantage, p })).filter(({ vantage }) => vantage.state !== 'failed');
const liveTargets = (run) => run.targets.map((target, t) => ({ target, t })).filter(({ target }) => !target.error);

async function serverModeError(response) {
  try {
    const { error } = await response.json();
    if (error) return error;
  } catch {
    // Not our server (for example a plain static file server).
  }
  return 'Proxies and DNS server lists need the local server. Stop the static server and run "node server.js" instead.';
}

async function lookupViaServer(sites, { proxies, dns, resolvers }, resolver, signal) {
  const bySite = new Map();
  const run = {
    wantResolvers: Boolean(resolvers) && proxies.length > 0,
    baseline: undefined,
    direct: undefined, // this machine's own direct IP(s), for the "does the proxy really change it" check
    viaProxies: proxies.length > 0,
    dnsList: dns.length > 0,
    vantages: [],
    targets: [],
    lookups: 0,
    proxyCard: h('article', { class: 'card' }),
    dnsCard: h('article', { class: 'card' }),
    sites: sites.map(({ host, source }) => {
      const site = { host, source, cells: new Map(), card: h('article', { class: 'card' }) };
      bySite.set(host, site);
      return site;
    }),
  };
  serverRun = run;
  lastMode = 'server';
  results.replaceChildren();

  const response = await fetch('/api/lookup', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ proxies, dns, hosts: sites.map((site) => site.host), resolver, resolvers: run.wantResolvers }),
    signal,
  });
  if (!response.ok) throw new Error(await serverModeError(response));

  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let pending = '';
  for (;;) {
    const { value, done } = await reader.read();
    if (done) break;
    pending += decoder.decode(value, { stream: true });
    let newline;
    while ((newline = pending.indexOf('\n')) >= 0) {
      const line = pending.slice(0, newline);
      pending = pending.slice(newline + 1);
      if (line) handleServerEvent(run, bySite, JSON.parse(line));
    }
  }
  if (!run.sites.length) {
    const working = run.vantages.filter((v) => v.state === 'ok').length;
    summary.textContent = `Checked ${run.vantages.length} prox${run.vantages.length === 1 ? 'y' : 'ies'}: ${working} working.`;
    return;
  }
  summary.textContent = `Done: ${run.lookups} lookup${run.lookups === 1 ? '' : 's'} completed.`;
}

// --- Hosted mode: DNS servers queried by the site's own function -----------
// Small requests: one DNS server and up to 5 domains at a time, so each finishes well inside the
// platform's time limit. Results feed the same tables as the local server's.

const HOSTED_MAX_SERVERS = 5;
const HOSTED_CHUNK = 5;
const HOSTED_CONCURRENCY = 4;
const HOSTED_MAX_REQUESTS = 40;

function parseHostedDns(line) {
  const [address, ...rest] = line.trim().split(/\s+/);
  const name = rest.join(' ').replace(/^#\s*/, '').slice(0, 60) || null;
  if (/^\[.*\]|^[^:]+:\d+$/.test(address)) return { error: 'hosted lookups always use port 53; enter just the IP address' };
  if (!isIPv4(address) && !isIPv6(address)) return { error: 'enter the DNS server as an IP address, for example 8.8.8.8' };
  return { address, name };
}

// Same idea as parseHostedDns, but for the local server, which (unlike the hosted one) allows a port -
// used only to give an early, specific error before a request is even sent, so pasting something that
// is not a DNS server at all (a proxy address, say) gets a useful answer instead of a generic one.
function parseLocalDnsPreview(line) {
  const [address, ...rest] = line.trim().split(/\s+/);
  const name = rest.join(' ').replace(/^#\s*/, '').slice(0, 60) || null;
  const bracketed = address.match(/^\[([^\]]+)\](?::\d{1,5})?$/);
  const withPort = address.match(/^([^:]+):\d{1,5}$/);
  const host = bracketed ? bracketed[1] : withPort ? withPort[1] : address;
  if (!isIPv4(host) && !isIPv6(host)) return { error: 'enter the DNS server as an IP address, for example 8.8.8.8' };
  return { address, name };
}

async function hostedError(response) {
  try {
    const { error } = await response.json();
    if (error) return error;
  } catch {
    // Not our function's JSON.
  }
  return response.status === 429
    ? 'Too many requests. Wait a minute and try again.'
    : `The lookup service answered HTTP ${response.status}.`;
}

async function lookupViaHosted(sites, dnsLines, signal) {
  let valid = 0;
  const targets = dnsLines.map((line, i) => {
    const entry = parseHostedDns(line);
    if (entry.error) return { label: `line ${i + 1}`, name: null, error: entry.error };
    if (++valid > HOSTED_MAX_SERVERS) {
      return { label: entry.address, name: entry.name, error: `hosted lookups allow up to ${HOSTED_MAX_SERVERS} DNS servers` };
    }
    return { label: entry.address, name: entry.name, error: null, address: entry.address };
  });

  const chunks = [];
  for (let i = 0; i < sites.length; i += HOSTED_CHUNK) chunks.push(sites.slice(i, i + HOSTED_CHUNK).map((site) => site.host));
  const items = targets.flatMap((target, t) => (target.error ? [] : chunks.map((hosts) => ({ t, target, hosts }))));
  if (items.length > HOSTED_MAX_REQUESTS) {
    throw new Error(`That needs ${items.length} requests; the hosted version allows ${HOSTED_MAX_REQUESTS} per lookup. Use fewer sites or DNS servers, or run the local version.`);
  }

  const bySite = new Map();
  const run = {
    viaProxies: false,
    dnsList: true,
    hosted: true,
    region: null,
    vantages: [],
    targets: [],
    lookups: 0,
    proxyCard: h('article', { class: 'card' }),
    dnsCard: h('article', { class: 'card' }),
    sites: sites.map(({ host, source }) => {
      const site = { host, source, cells: new Map(), card: h('article', { class: 'card' }) };
      bySite.set(host, site);
      return site;
    }),
  };
  serverRun = run;
  lastMode = 'server';
  results.replaceChildren();
  handleServerEvent(run, bySite, {
    event: 'start',
    viaProxies: false,
    dnsList: true,
    vantages: [{ label: 'Hosted', error: null }],
    targets: targets.map(({ label, name, error }) => ({ label, name, error })),
  });
  handleServerEvent(run, bySite, { event: 'vantage', p: 0, ok: true });

  const emitFailure = (item, message) => {
    for (const host of item.hosts) {
      for (const type of IP_TYPES) handleServerEvent(run, bySite, { event: 'result', p: 0, t: item.t, host, type, ok: false, error: message });
    }
  };
  const health = targets.map(() => ({ answered: 0, failedCalls: 0 }));
  let rateLimited = false;
  let next = 0;

  async function worker() {
    while (next < items.length) {
      const item = items[next++];
      if (rateLimited) { emitFailure(item, 'not sent: rate limit reached, try again in a minute'); continue; }
      if (health[item.t].answered === 0 && health[item.t].failedCalls >= 2) {
        emitFailure(item, 'no reply (skipped after 2 failed requests)');
        continue;
      }
      let data;
      try {
        const response = await fetch('/api/dns', {
          method: 'POST',
          headers: hostedHeaders(),
          body: JSON.stringify({ server: item.target.address, hosts: item.hosts }),
          signal,
        });
        if (response.status === 429) rateLimited = true;
        if (!response.ok) throw new Error(await hostedError(response));
        data = await response.json();
      } catch (err) {
        if (err.name === 'AbortError') throw err;
        health[item.t].failedCalls++;
        emitFailure(item, err instanceof TypeError ? 'could not reach the lookup service' : err.message);
        continue;
      }
      run.region ??= data.region;
      if (data.usage) run.usage = data.usage;
      const anyAnswered = data.results.some((result) => result.ok);
      if (anyAnswered) health[item.t].answered++;
      else health[item.t].failedCalls++;
      for (const result of data.results) handleServerEvent(run, bySite, { event: 'result', p: 0, t: item.t, ...result });
    }
  }
  await Promise.all(Array.from({ length: Math.min(HOSTED_CONCURRENCY, items.length) }, worker));
  renderServerRun(run);
  const usageNote = run.usage
    ? ` (${run.usage.plan} tier: ${run.usage.remaining} of ${run.usage.limit} left today)` : '';
  summary.textContent = `Done: ${run.lookups} lookup${run.lookups === 1 ? '' : 's'} completed from this site's servers.${usageNote}`;
}

function renderServerRun(run) {
  if (run.viaProxies) renderProxySummary(run);
  if (run.dnsList) renderDnsSummary(run);
  run.sites.forEach((site) => renderServerSite(run, site));
}

function handleServerEvent(run, bySite, event) {
  if (event.event === 'start') {
    run.vantages = event.vantages.map((v) => ({
      label: v.label, state: v.error ? 'failed' : 'checking', error: v.error, exitIp: null, country: null, warning: null,
      ips: null, // the proxy's own address(es)
      resolvers: run.wantResolvers && !v.error ? undefined : null, // its DNS servers; undefined while being found
      geo: undefined, whois: undefined, // public geolocation/WHOIS for the exit IP; undefined while being found
    }));
    run.targets = event.targets.map((t) => ({
      label: t.label, name: t.name, error: t.error,
      geo: t.error ? null : undefined, // this server's own public location/ISP; undefined while being found
    }));
    results.append(
      ...(run.viaProxies ? [run.proxyCard] : []),
      ...(run.dnsList ? [run.dnsCard] : []),
      ...run.sites.map((site) => site.card),
    );
    renderServerRun(run);
  } else if (event.event === 'vantage') {
    Object.assign(run.vantages[event.p], {
      state: event.ok ? 'ok' : 'failed',
      error: event.error ?? null,
      exitIp: event.exitIp ?? null,
      country: event.country ?? null,
      warp: event.warp ?? false,
      warning: event.warning ?? null,
    });
    renderServerRun(run);
  } else if (event.event === 'proxyinfo') {
    run.vantages[event.p].ips = event.ips;
    renderServerRun(run);
  } else if (event.event === 'resolvers') {
    run.vantages[event.p].resolvers = event.ok ? { servers: event.servers } : { error: event.error };
    renderServerRun(run);
  } else if (event.event === 'baseline') {
    run.baseline = event.ok ? { servers: event.servers } : { error: event.error };
    renderServerRun(run);
  } else if (event.event === 'directinfo') {
    run.direct = event.ok ? { ips: event.ips, country: event.country } : { error: event.error ?? 'unavailable' };
    renderServerRun(run);
  } else if (event.event === 'geoinfo') {
    Object.assign(run.vantages[event.p], { geo: event.geo, whois: event.whois, geoError: event.error ?? null });
    renderServerRun(run);
  } else if (event.event === 'targetgeo') {
    Object.assign(run.targets[event.t], { geo: event.ok ? event.geo : null, geoError: event.ok ? null : event.error });
    renderServerRun(run);
  } else if (event.event === 'result') {
    const site = bySite.get(event.host);
    site.cells.set(`${event.p}|${event.t}|${event.type}`, event);
    run.lookups++;
    renderServerSite(run, site);
    if (run.dnsList) renderDnsSummary(run);
    summary.textContent = `${run.lookups} lookup${run.lookups === 1 ? '' : 's'} completed…`;
  }
}

// bash.ws gives every server a country/org; when the extra geolocation lookup also succeeded, show the
// city too — same degrade-gracefully pattern as the rest of the app when that lookup fails or is skipped.
const serverLine = (server) => {
  const place = server.city ? [server.city, server.region, server.country].filter(Boolean).join(', ') : server.country;
  return [place, server.isp ?? server.org].filter(Boolean).join(' · ');
};

// The DNS servers a proxy uses, as found by having it look up test names. If any is also one of this
// computer's own, say so: it usually means the proxy is not resolving on its own network.
// A resolver-farm ISP can return dozens of addresses; capped on screen (all of them still export to
// CSV/JSON) so one proxy's row does not push every other proxy off screen when comparing several at once.
const RESOLVERS_SHOWN = 8;

function resolversCell(vantage, baseline) {
  const found = vantage.resolvers;
  if (vantage.state === 'failed') return h('td', { class: 'muted' }, '—');
  if (found === undefined) return h('td', { class: 'muted' }, 'checking…');
  if (found === null) return h('td', { class: 'muted' }, '—');
  if (found.error) return h('td', {}, h('span', { class: 'fail' }, found.error));
  if (!found.servers.length) return h('td', { class: 'muted', title: 'The proxy did not look up any of the test names.' }, 'none found');
  const mine = new Set((baseline?.servers ?? []).map((s) => s.ip.toLowerCase()));
  const shared = found.servers.some((s) => mine.has(s.ip.toLowerCase()));
  const extra = found.servers.length - RESOLVERS_SHOWN;
  return h('td', { class: 'ips' },
    ...found.servers.slice(0, RESOLVERS_SHOWN).map((server) => h('div', { class: 'ip' },
      h('span', {}, server.ip),
      ...(serverLine(server) ? [h('div', { class: 'detail' }, serverLine(server))] : []))),
    ...(extra > 0 ? [h('div', { class: 'sub' }, `+${extra} more (see the CSV/JSON export for all ${found.servers.length})`)] : []),
    ...(shared ? [h('div', { class: 'sub' }, "includes this computer's own DNS servers")] : []),
  );
}

function baselineNote(run) {
  const baseline = run.baseline;
  let text = "This computer's own DNS servers (for comparison): checking…";
  if (baseline?.error) text = `This computer's own DNS servers: ${baseline.error}`;
  else if (baseline) {
    text = `This computer's own DNS servers (for comparison): ${baseline.servers.length
      ? baseline.servers.map((s) => `${s.ip}${serverLine(s) ? ` (${serverLine(s)})` : ''}`).join(', ')
      : 'none found'}`;
  }
  return h('p', { class: 'card-note' }, text);
}

function directNote(run) {
  const direct = run.direct;
  let text = "This computer's own direct IP (for comparison): checking…";
  if (direct?.error) text = `This computer's own direct IP: ${direct.error}`;
  else if (direct) text = `This computer's own direct IP (for comparison): ${direct.ips.join(', ')}${direct.country ? ` (${direct.country})` : ''}`;
  return h('p', { class: 'card-note' }, text);
}

// Does this proxy's exit IP actually differ from this machine's own? A proxy whose exit matches is not
// changing your address — the equivalent of the connection panel's "same public IP" / "proxy in use" check,
// run here from the server's side instead of the browser's.
function directCompareBadge(vantage, direct) {
  if (!vantage.exitIp || !direct || direct.error) return null;
  const same = direct.ips.some((ip) => ip.toLowerCase() === vantage.exitIp.toLowerCase());
  return same
    ? h('span', { class: 'pill warn', title: "Same address as this machine's own direct connection" }, 'no change')
    : h('span', { class: 'pill ok', title: "Different from this machine's own direct connection" }, 'changes IP');
}

// A public, free-tier geolocation lookup (ip-api.com): city/region are a rough placement from the
// network's registered address, not a physical trace, and usage is a best-effort signal from three
// booleans (mobile/hosting/known-proxy), not a full classification.
function geoLine(geo) {
  if (!geo) return null;
  const place = [geo.city, geo.region, geo.country].filter(Boolean).join(', ');
  const coords = geo.lat != null && geo.lon != null ? `${geo.lat}, ${geo.lon}` : null;
  const where = [place || null, coords ? `(${coords})` : null].filter(Boolean).join(' ');
  const when = geo.timezone;
  const line1 = [where, when].filter(Boolean).join(' · ');
  const isp = [geo.isp && `ISP: ${geo.isp}`, geo.org && `Org: ${geo.org}`, geo.usage].filter(Boolean).join(' · ');
  return [line1, isp].filter(Boolean);
}

// Registry WHOIS (RDAP) for the exit IP's network: who it is allocated to, not who is using it now.
function whoisLine(whois) {
  if (!whois) return null;
  const head = [whois.registry, whois.name, whois.cidr ?? whois.range].filter(Boolean).join(' · ');
  const tail = [whois.lastChanged && `registered ${whois.lastChanged}`, whois.abuseEmail && `abuse: ${whois.abuseEmail}`]
    .filter(Boolean).join(' · ');
  return [head, tail].filter(Boolean).join(' · ') || null;
}

function exitDetailsCell(vantage) {
  if (!vantage.exitIp) return h('td', { class: 'detail-cell muted' }, '—');
  const lines = [];
  const known = describeIp(vantage.exitIp);
  if (known) lines.push(known);
  if (vantage.geo === undefined) {
    lines.push('checking location and registry…');
  } else if (!vantage.geo && !vantage.whois) {
    lines.push(vantage.geoError ? `location/registry lookup failed: ${vantage.geoError}` : 'location and registry unavailable');
  } else {
    lines.push(...(geoLine(vantage.geo) ?? []));
    const whoisText = whoisLine(vantage.whois);
    if (whoisText) lines.push(whoisText);
  }
  if (vantage.warp) lines.push('Cloudflare WARP: on (this proxy is itself going through WARP)');
  return h('td', { class: 'detail-cell' }, ...lines.map((line) => h('div', {}, line)));
}

// Where a DNS server itself is (its own public location/ISP, from ip-api.com) — distinct from the
// "network owner" shown per-answer, which is the IP a server *returned*, not the server's own address.
function targetLocationCell(target) {
  if (target.error) return h('td', { class: 'detail-cell muted' }, '—');
  if (target.geo === undefined) return h('td', { class: 'detail-cell muted' }, 'checking…');
  if (!target.geo) return h('td', { class: 'detail-cell muted' }, target.geoError ? `lookup failed: ${target.geoError}` : 'unavailable');
  return h('td', { class: 'detail-cell' }, ...(geoLine(target.geo) ?? []).map((line) => h('div', {}, line)));
}

function renderProxySummary(run) {
  const working = run.vantages.filter((v) => v.state === 'ok').length;
  const checking = run.vantages.some((v) => v.state === 'checking');
  const kind = checking ? 'pending' : working ? 'ok' : 'error';
  const head = h('div', { class: 'card-head' },
    h('h2', {}, 'Proxies'),
    h('span', { class: `badge ${kind}` }, `${working} of ${run.vantages.length} working`),
  );

  const showDetails = run.vantages.some((v) => v.exitIp);
  const body = h('tbody');
  for (const vantage of run.vantages) {
    let status = h('span', { class: 'muted' }, 'checking…');
    if (vantage.state === 'ok') status = h('span', {}, vantage.warning ? `reachable (exit check failed: ${vantage.warning})` : 'working');
    if (vantage.state === 'failed') status = h('span', { class: 'fail' }, vantage.error);
    const compareBadge = run.viaProxies ? directCompareBadge(vantage, run.direct) : null;
    const row = h('tr', {},
      h('td', { class: 'proxy' }, vantage.label),
      h('td', { class: 'exit' }, vantage.ips ? vantage.ips.join(', ') || '—' : '…'),
      h('td', {}, status, ...(compareBadge ? [' ', compareBadge] : [])),
      h('td', { class: 'exit' }, vantage.exitIp ?? '—'),
      h('td', {}, vantage.country ?? '—'),
    );
    if (run.wantResolvers) row.append(resolversCell(vantage, run.baseline));
    if (showDetails) row.append(exitDetailsCell(vantage));
    body.append(row);
  }
  const headings = ['Proxy', 'Proxy address', 'Status', 'Exit IP', 'Country',
    ...(run.wantResolvers ? ['DNS servers'] : []), ...(showDetails ? ['Exit IP details (location, ISP, registry)'] : [])];
  const table = h('table', {},
    h('thead', {}, h('tr', {}, ...headings.map((text) => h('th', {}, text)))),
    body,
  );
  run.proxyCard.replaceChildren(head, h('div', { class: 'table-wrap' }, table),
    ...(run.viaProxies ? [directNote(run)] : []), ...(run.wantResolvers ? [baselineNote(run)] : []));
}

function renderDnsSummary(run) {
  const vantages = liveVantages(run);
  const expected = run.sites.length * vantages.length * IP_TYPES.length;
  const stats = run.targets.map((target, t) => {
    const stat = { target, done: 0, answered: 0, times: [], problems: new Map() };
    if (target.error) return stat;
    for (const site of run.sites) {
      for (const { p } of vantages) {
        for (const type of IP_TYPES) {
          const cell = site.cells.get(`${p}|${t}|${type}`);
          if (!cell) continue;
          stat.done++;
          if (!cellFailed(cell)) stat.answered++;
          else {
            const why = cell.ok ? rcodeLabel(cell.rcode) : cell.error;
            stat.problems.set(why, (stat.problems.get(why) ?? 0) + 1);
          }
          if (cell.ok && cell.ms != null) stat.times.push(cell.ms);
        }
      }
    }
    return stat;
  });

  const usable = stats.filter((s) => !s.target.error);
  const pending = usable.some((s) => s.done < expected);
  const answering = usable.filter((s) => s.answered > 0).length;
  const kind = pending ? 'pending' : answering === usable.length ? 'ok' : answering ? 'warn' : 'error';
  const head = h('div', { class: 'card-head' },
    h('h2', {}, 'DNS servers'),
    ...(run.hosted ? [h('span', { class: 'source' }, `queried from this site's servers${run.region ? ` (${run.region})` : ''}`)] : []),
    h('span', { class: `badge ${kind}` }, `${answering} of ${usable.length} answering`),
  );

  const body = h('tbody');
  for (const stat of stats) {
    const { target } = stat;
    const problems = target.error
      ? target.error
      : [...stat.problems].map(([why, count]) => `${why} ×${count}`).join(', ');
    const average = stat.times.length ? `${(stat.times.reduce((a, b) => a + b, 0) / stat.times.length).toFixed(1)} ms` : '—';
    body.append(h('tr', {},
      h('td', { class: 'proxy' }, target.label, ...(target.name ? [h('div', { class: 'sub' }, target.name)] : [])),
      h('td', { class: 'ttl' }, target.error ? '—' : `${stat.answered} of ${stat.done}`),
      h('td', { class: 'ttl' }, average),
      h('td', {}, problems ? h('span', { class: 'fail' }, problems) : h('span', { class: 'muted' }, '—')),
      targetLocationCell(target),
    ));
  }
  const headings = ['DNS server', 'Answered', 'Avg time', 'Problems', 'Location'];
  const table = h('table', {},
    h('thead', {}, h('tr', {}, ...headings.map((text) => h('th', {}, text)))),
    body,
  );
  run.dnsCard.replaceChildren(head, h('div', { class: 'table-wrap' }, table));
}

function ipCell(cell) {
  if (!cell) return h('td', { class: 'ips muted' }, '…');
  if (!cell.ok) return h('td', { class: 'ips' }, h('span', { class: 'fail' }, cell.error));
  if (cell.records.length) {
    const lines = [...cell.records].sort((a, b) => (a.value < b.value ? -1 : 1)).map((record) => {
      const detail = describeIp(record.value);
      return h('div', { class: 'ip' },
        h('span', {}, record.value),
        h('span', { class: 'ttl' }, ` ${record.ttl}s`),
        ...(detail ? [h('div', { class: 'detail' }, detail)] : []),
      );
    });
    return h('td', { class: 'ips' }, ...lines);
  }
  if (cell.rcode === 3) return h('td', { class: 'ips muted' }, 'NXDOMAIN');
  if (cell.rcode !== 0) return h('td', { class: 'ips' }, h('span', { class: 'fail' }, rcodeLabel(cell.rcode)));
  return h('td', { class: 'ips muted' }, 'none');
}

function statusCell(cells) {
  const done = cells.filter(Boolean);
  if (done.length < cells.length) return h('td', { class: 'muted' }, '…');
  const failure = done.find(cellFailed);
  const missing = done.some((c) => c.ok && c.rcode === 3);
  const first = done.find((c) => c.ok);
  const text = failure ? (failure.ok ? rcodeLabel(failure.rcode) : failure.error) : missing ? 'NXDOMAIN' : 'NOERROR';
  // Response time is the average over the A and AAAA queries; hovering shows each one.
  const timed = done.filter((c) => c.ok && c.ms != null);
  const average = timed.length ? `${(timed.reduce((sum, c) => sum + c.ms, 0) / timed.length).toFixed(1)} ms` : null;
  const notes = first
    ? [first.transport, ...(average ? [average] : []), ...(first.flags.aa ? ['authoritative'] : []),
      ...(first.flags.ad ? ['DNSSEC-validated'] : []), ...(first.flags.ra === false ? ['no recursion'] : [])]
    : [];
  return h('td', {},
    h('span', { class: failure ? 'fail' : missing ? 'muted' : '' }, text),
    ...(notes.length ? [h('div', { class: 'sub', title: timed.map((c) => `${c.type} ${c.ms} ms`).join(' · ') }, notes.join(' · '))] : []),
  );
}

function cnameCell(cells) {
  const chain = cells.find((c) => c?.ok && c.cname?.length)?.cname ?? [];
  return h('td', { class: 'name' }, chain.length ? `→ ${chain.map((link) => link.target).join(' → ')}` : '');
}

function renderServerSite(run, site) {
  const vantages = liveVantages(run);
  const targets = liveTargets(run);
  const allChecked = run.vantages.every((v) => v.state !== 'checking');
  const expected = vantages.length * targets.length * IP_TYPES.length;
  const cellsFor = (p, t) => IP_TYPES.map((type) => site.cells.get(`${p}|${t}|${type}`));

  const distinct = new Set();
  let answered = 0;
  let failed = 0;
  let nxdomain = 0;
  let hasCname = false;
  for (const { p } of vantages) {
    for (const { t } of targets) {
      for (const cell of cellsFor(p, t)) {
        if (!cell) continue;
        answered++;
        if (cellFailed(cell)) failed++;
        else if (cell.rcode === 3) nxdomain++;
        if (cell.ok) {
          cell.records.forEach((record) => distinct.add(record.value));
          if (cell.cname?.length) hasCname = true;
        }
      }
    }
  }

  let status;
  const ips = `${distinct.size} distinct IP${distinct.size === 1 ? '' : 's'}`;
  if (vantages.length === 0) status = allChecked ? { kind: 'error', text: 'No working proxies' } : { kind: 'pending', text: 'Looking up…' };
  else if (targets.length === 0) status = { kind: 'error', text: 'No usable DNS servers' };
  else if (answered < expected) status = { kind: 'pending', text: 'Looking up…' };
  else if (distinct.size > 0) status = failed ? { kind: 'warn', text: `${ips} · incomplete` } : { kind: 'ok', text: ips };
  else if (failed === answered) status = { kind: 'error', text: 'Lookup failed' };
  else {
    // Some queries got a real answer. Judge by those, and say so if others failed.
    const suffix = failed ? ' · incomplete' : '';
    if (nxdomain === answered - failed) status = { kind: 'error', text: `Not found (NXDOMAIN)${suffix}` };
    else status = { kind: 'warn', text: `No addresses${suffix}` };
  }

  const head = h('div', { class: 'card-head' }, h('h2', {}, site.host));
  if (site.source !== site.host) head.append(h('span', { class: 'source' }, site.source));
  head.append(h('span', { class: `badge ${status.kind}` }, status.text));
  site.card.replaceChildren(head);
  if (!vantages.length || !targets.length) return;

  const body = h('tbody');
  for (const { vantage, p } of vantages) {
    for (const { target, t } of targets) {
      const cells = cellsFor(p, t);
      const row = h('tr', {});
      if (run.viaProxies) {
        const exit = vantage.exitIp ? `${vantage.exitIp}${vantage.country ? ` (${vantage.country})` : ''}` : '—';
        row.append(h('td', { class: 'proxy' }, vantage.label, h('div', { class: 'sub' }, exit)));
      }
      if (run.dnsList) {
        row.append(h('td', { class: 'proxy' }, target.label, ...(target.name ? [h('div', { class: 'sub' }, target.name)] : [])));
      }
      row.append(statusCell(cells), ...cells.map(ipCell));
      if (hasCname) row.append(cnameCell(cells));
      body.append(row);
    }
  }
  const headings = [
    ...(run.viaProxies ? ['Proxy'] : []),
    ...(run.dnsList ? ['DNS server'] : []),
    'Status',
    'IPv4',
    'IPv6',
    ...(hasCname ? ['Canonical name'] : []),
  ];
  const table = h('table', {},
    h('thead', {}, h('tr', {}, ...headings.map((text) => h('th', {}, text)))),
    body,
  );
  site.card.append(h('div', { class: 'table-wrap' }, table));
}

// --- Export ----------------------------------------------------------------

const BROWSER_COLUMNS = ['site', 'domain', 'type', 'name', 'value', 'ttl', 'ptr', 'asn', 'network', 'prefix', 'country'];
const SERVER_COLUMNS = ['site', 'domain', 'proxy', 'proxy_address', 'exit_ip', 'exit_country', 'exit_changes_ip', 'exit_warp', 'exit_asn', 'exit_network',
  'exit_city', 'exit_region', 'exit_coordinates', 'exit_timezone', 'exit_isp', 'exit_usage_type',
  'exit_registry', 'exit_net_range', 'exit_registered', 'proxy_dns_servers', 'dns_server', 'type', 'status', 'response_ms',
  'ip', 'ttl', 'ptr', 'asn', 'network', 'prefix', 'country', 'error'];

// The public geolocation/WHOIS fields for a proxy's exit IP, for the export; blank where not (yet) known.
function exitGeoFields(vantage) {
  const geo = vantage.geo, whois = vantage.whois;
  return {
    exit_city: geo?.city ?? '',
    exit_region: geo?.region ?? '',
    exit_coordinates: geo?.lat != null && geo?.lon != null ? `${geo.lat}, ${geo.lon}` : '',
    exit_timezone: geo?.timezone ?? '',
    exit_isp: geo?.isp ?? '',
    exit_usage_type: geo?.usage ?? '',
    exit_registry: whois?.registry ?? '',
    exit_net_range: whois?.cidr ?? whois?.range ?? '',
    exit_registered: whois?.lastChanged ?? '',
    exit_warp: vantage.warp ? 'on' : '',
  };
}

// "yes"/"no": whether this proxy's exit IP differs from this machine's own direct connection; blank
// when that is not yet known (still checking, or this run has no proxies to compare against).
function directCompareField(vantage, direct) {
  if (!vantage.exitIp || !direct || direct.error) return '';
  return direct.ips.some((ip) => ip.toLowerCase() === vantage.exitIp.toLowerCase()) ? 'no' : 'yes';
}

// The DNS servers a proxy uses, for the export: "ip (country · organisation); ...".
const proxyDnsServers = (vantage) => (vantage.resolvers?.servers ?? [])
  .map((server) => `${server.ip}${serverLine(server) ? ` (${serverLine(server)})` : ''}`).join('; ');

function serverExportRows() {
  const run = serverRun;
  // Checking only proxies: one row for each, including any that failed and why.
  if (!run.sites.length) {
    return run.vantages.map((vantage) => ({
      proxy: run.viaProxies ? vantage.label : 'direct',
      proxy_address: (vantage.ips ?? []).join('; '),
      exit_ip: vantage.exitIp ?? '',
      exit_country: vantage.country ?? '',
      exit_asn: detailFields(vantage.exitIp ?? '').asn,
      exit_network: detailFields(vantage.exitIp ?? '').network,
      exit_changes_ip: directCompareField(vantage, run.direct),
      ...exitGeoFields(vantage),
      proxy_dns_servers: proxyDnsServers(vantage) || vantage.resolvers?.error || '',
      status: vantage.state === 'ok' ? 'working' : vantage.state === 'failed' ? 'FAILED' : '',
      error: vantage.error ?? vantage.warning ?? '',
    }));
  }
  return run.sites.flatMap((site) =>
    liveVantages(run).flatMap(({ vantage, p }) =>
      liveTargets(run).flatMap(({ target, t }) =>
        IP_TYPES.flatMap((type) => {
          const cell = site.cells.get(`${p}|${t}|${type}`);
          if (!cell) return [];
          const base = {
            site: site.source,
            domain: site.host,
            proxy: run.hosted ? 'hosted' : run.viaProxies ? vantage.label : 'direct',
            proxy_address: (vantage.ips ?? []).join('; '),
            proxy_dns_servers: proxyDnsServers(vantage),
            exit_ip: vantage.exitIp ?? '',
            exit_country: vantage.country ?? '',
            exit_asn: detailFields(vantage.exitIp ?? '').asn,
            exit_network: detailFields(vantage.exitIp ?? '').network,
            exit_changes_ip: directCompareField(vantage, run.direct),
            ...exitGeoFields(vantage),
            dns_server: target.name ? `${target.label} (${target.name})` : target.label,
            type,
            status: cell.ok ? rcodeLabel(cell.rcode) : 'ERROR',
            response_ms: cell.ms ?? '',
            error: cell.ok ? '' : cell.error,
          };
          if (!cell.ok || !cell.records.length) return [{ ...base, ip: '', ttl: '', ...detailFields('') }];
          return cell.records.map((record) => ({ ...base, ip: record.value, ttl: record.ttl, ...detailFields(record.value) }));
        }))));
}

function exportRows() {
  if (lastMode === 'server') return serverExportRows();
  return lastRun.flatMap((site) =>
    sortedRecords(site).map((r) => ({
      site: site.source,
      domain: site.host,
      ...r,
      ...detailFields(r.type === 'A' || r.type === 'AAAA' ? r.value : ''),
    })));
}

function csvCell(value) {
  let text = String(value);
  if (/^[=+\-@\t\r]/.test(text)) text = `'${text}`; // stop spreadsheet formula injection
  return `"${text.replace(/"/g, '""')}"`;
}

function toCsv() {
  const columns = lastMode === 'server' ? SERVER_COLUMNS : BROWSER_COLUMNS;
  const lines = exportRows().map((row) => columns.map((c) => csvCell(row[c] ?? '')).join(','));
  return [columns.join(','), ...lines].join('\n');
}

function download(filename, mime, text) {
  const url = URL.createObjectURL(new Blob([text], { type: mime }));
  const link = h('a', { href: url, download: filename });
  link.click();
  URL.revokeObjectURL(url);
}

$('csv').addEventListener('click', () => download('dns-records.csv', 'text/csv', toCsv()));
$('json').addEventListener('click', () =>
  download('dns-records.json', 'application/json', JSON.stringify(exportRows(), null, 2)));
$('copy').addEventListener('click', async (event) => {
  const button = event.currentTarget;
  try {
    await navigator.clipboard.writeText(toCsv());
    button.textContent = 'Copied!';
  } catch {
    button.textContent = 'Copy failed';
  }
  setTimeout(() => { button.textContent = 'Copy CSV'; }, 1500);
});

// --- Your connection: the address and details this browser presents -----------
// When a browser uses a proxy, websites see the proxy's address instead of yours. This panel shows the
// address they see, whose network it is, and checks the ways a browser can give itself away around a proxy.

const CONN_RECHECK_MS = 8000;
const HOSTING_NETWORK = /amazon|aws|microsoft|azure|digitalocean|linode|akamai|ovh|hetzner|vultr|oracle|alibaba|tencent|choopa|m247|leaseweb|contabo|scaleway|equinix|datacamp|hosting|datacenter|data center|cloud|vpn|proxy/i;
const SIGNAL_LABELS = { ok: 'OK', note: 'Note', warn: 'Check', proxy: 'Proxy' };

const connBody = $('conn-body');
let connChecking = false;
let connCheckedAt = 0;
let lastConnection = null;

const isPrivateAddress = (ip) =>
  /^(10\.|127\.|169\.254\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/.test(ip) || /^(fc|fd|fe80|::1$)/i.test(ip);

function regionName(code) {
  try {
    return new Intl.DisplayNames(['en'], { type: 'region' }).of(code);
  } catch {
    return null;
  }
}

// "GMT+5:30" for a timezone name, so aliases of the same zone (Asia/Calcutta, Asia/Kolkata) compare equal.
function utcOffset(timeZone) {
  try {
    return new Intl.DateTimeFormat('en-US', { timeZone, timeZoneName: 'longOffset' })
      .formatToParts(new Date()).find((part) => part.type === 'timeZoneName')?.value ?? null;
  } catch {
    return null;
  }
}

async function siteWhoami() {
  const res = await fetch(`/api/whoami?_=${Date.now()}`, { cache: 'no-store', signal: AbortSignal.timeout(7000) });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res.json();
}

// One hostname per address family (icanhazip.com is run by Cloudflare), so each path is exercised. Asking
// both tells us every address websites see for this browser; a family that has no route, or whose proxy
// cannot carry it, simply gives no answer.
async function familyEcho(url) {
  const res = await fetch(url, { cache: 'no-store', signal: AbortSignal.timeout(5000) });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  const ip = (await res.text()).trim();
  return isIPv4(ip) || isIPv6(ip) ? ip : null;
}

async function cloudflareTrace() {
  const res = await fetch('https://www.cloudflare.com/cdn-cgi/trace', { cache: 'no-store', signal: AbortSignal.timeout(6000) });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  const text = await res.text();
  return Object.fromEntries(text.split('\n').map((line) => line.split('=')).filter((pair) => pair.length === 2));
}

// An ICE candidate line: "candidate:1 1 udp 2113937151 203.0.113.5 54400 typ srflx raddr ..."
function parseCandidate(line) {
  const parts = line.split(' ');
  const typeAt = parts.indexOf('typ');
  return parts.length >= 8 && typeAt > 0 ? { address: parts[4], type: parts[typeAt + 1] } : null;
}

function classifyWebrtc(candidates) {
  const publicIps = new Set();
  const localIps = new Set();
  let hidden = 0;
  for (const { address, type } of candidates) {
    if (/\.local$/i.test(address)) hidden++; // the browser replaced a local address with a random name
    else if (type === 'host' && isPrivateAddress(address)) localIps.add(address);
    else publicIps.add(address);
  }
  return { publicIps: [...publicIps], localIps: [...localIps], hidden };
}

// WebRTC talks to a STUN server outside the browser's proxy settings in some browsers, which is how a
// site can learn the real address behind a proxy. Ask it what it would reveal.
function webrtcCheck(timeoutMs = 3500) {
  const none = { supported: false, publicIps: [], localIps: [], hidden: 0 };
  return new Promise((resolve) => {
    if (typeof RTCPeerConnection === 'undefined') return resolve(none);
    const candidates = [];
    let connection;
    try {
      connection = new RTCPeerConnection({ iceServers: [{ urls: 'stun:stun.cloudflare.com:3478' }] });
    } catch {
      return resolve(none);
    }
    let finished = false;
    const finish = () => {
      if (finished) return;
      finished = true;
      clearTimeout(timer);
      try {
        connection.close();
      } catch {
        // already closed
      }
      resolve({ supported: true, ...classifyWebrtc(candidates) });
    };
    const timer = setTimeout(finish, timeoutMs);
    connection.onicecandidate = (event) => {
      if (!event.candidate) return finish();
      const parsed = parseCandidate(event.candidate.candidate);
      if (parsed) candidates.push(parsed);
    };
    connection.createDataChannel('probe');
    connection.createOffer().then((offer) => connection.setLocalDescription(offer)).catch(finish);
  });
}

async function browserInfo() {
  const data = navigator.userAgentData;
  const ua = navigator.userAgent ?? '';
  const chromium = data?.brands?.find((b) => /^chromium$/i.test(b.brand));
  let browser;
  if (await navigator.brave?.isBrave?.().catch(() => false)) browser = `Brave${chromium ? ` (Chromium ${chromium.version})` : ''}`;
  else {
    const brand = data?.brands?.find((b) => !/not.?a.?brand|^chromium$/i.test(b.brand));
    browser = brand ? `${brand.brand} ${brand.version}` : (/(Firefox|Edg|Chrome|Safari)\/([\d.]+)/.exec(ua)?.slice(1).join(' ') ?? null);
  }
  return {
    browser,
    os: data?.platform || /Windows|Mac OS X|Android|iPhone|iPad|Linux/.exec(ua)?.[0] || null,
    languages: [...new Set(navigator.languages ?? [])].slice(0, 3).join(', '),
    timezone: Intl.DateTimeFormat().resolvedOptions().timeZone ?? null,
  };
}

// What the evidence says. Each signal states a fact and what it usually means; none of them is proof.
function connectionSignals({ ip, seen = [], echoOk = { v4: true, v6: true }, timezone, browserTimezone, direct, webrtc, org, headers, warp }) {
  const same = (a, b) => a.toLowerCase() === b.toLowerCase();
  const signals = [];
  const directIps = direct?.ips?.length ? direct.ips : direct?.ip ? [direct.ip] : [];
  if (directIps.length) {
    // A computer can have both an IPv4 and an IPv6 address; sharing any one of them means the same connection.
    const seenByWebsites = [ip, ...seen];
    signals.push(directIps.some((d) => seenByWebsites.some((k) => same(d, k)))
      ? { level: 'note', text: 'Your browser and this computer show the same public IP, so no separate browser proxy is in use (a system-wide VPN would look the same).' }
      : { level: 'proxy', text: `Your browser's public IP (${[...new Set(seenByWebsites)].join(', ')}) is not this computer's own connection (${directIps.join(', ')}), so your browser is going through a proxy or VPN.` });
  }
  if (warp) signals.push({ level: 'proxy', text: 'Cloudflare WARP is on for this connection.' });
  if (!webrtc) {
    // still being checked: no verdict yet
  } else if (!webrtc.supported) {
    signals.push({ level: 'ok', text: 'WebRTC is unavailable or blocked, so it cannot bypass your proxy.' });
  } else {
    // An address only counts as leaking if websites did not see it: a machine with both IPv4 and IPv6
    // legitimately shows one of each.
    const known = [ip, ...seen];
    const other = webrtc.publicIps.filter((address) => !known.some((k) => same(k, address)));
    const isDirect = (address) => directIps.some((d) => same(d, address));
    // With this computer's own addresses known, a shared address means no separate proxy exists.
    const proxyInUse = directIps.length > 0 && !directIps.some((d) => known.some((k) => same(d, k)));
    const family = (address) => (address.includes(':') ? 'v6' : 'v4');
    if (other.length && directIps.length && !proxyInUse && other.every(isDirect)) {
      signals.push({ level: 'ok', text: `WebRTC also shows ${other.join(', ')}, which are this computer's own addresses. Your browser is not using a separate proxy, so nothing is being bypassed.` });
    } else if (other.length && proxyInUse && other.some(isDirect)) {
      const real = other.filter(isDirect);
      signals.push({ level: 'warn', text: `WebRTC exposes ${real.join(', ')}, ${real.length === 1 ? "this computer's own address" : "this computer's own addresses"}, around your proxy. Websites can see your real ${real.length === 1 ? 'address' : 'addresses'} through WebRTC.` });
    } else if (other.length && other.every((address) => !echoOk[family(address)])) {
      // The request that would show whether websites see this address never got through, so say so
      // rather than claim a leak.
      signals.push({ level: 'warn', text: `WebRTC exposes ${other.join(', ')}, but none of your web requests arrived from ${[...new Set(other.map((a) => (family(a) === 'v6' ? 'an IPv6' : 'an IPv4')))].join(' or ')} address (${[...new Set(known)].join(', ')} was seen). If you use a proxy, WebRTC can reveal this address to websites.` });
    } else if (other.length) {
      signals.push({ level: 'warn', text: `WebRTC exposes ${other.join(', ')}, which websites did not see for this connection (they saw ${[...new Set(known)].join(', ')}). WebRTC can bypass a browser proxy, so websites may see this address.` });
    } else if (webrtc.publicIps.length) {
      signals.push({ level: 'ok', text: 'WebRTC reports only addresses that websites also see for this connection, so it does not leak around the proxy.' });
    } else {
      signals.push({ level: 'ok', text: 'WebRTC exposes no public address.' });
    }
    if (webrtc.localIps.length) {
      signals.push({ level: 'note', text: `WebRTC exposes local network address${webrtc.localIps.length === 1 ? '' : 'es'}: ${webrtc.localIps.join(', ')}. Websites cannot connect to these, but they describe your network.` });
    }
  }
  if (timezone && browserTimezone) {
    const there = utcOffset(timezone);
    const here = utcOffset(browserTimezone);
    if (there && here && there !== here) {
      signals.push({ level: 'note', hint: true, text: `Your browser's timezone (${browserTimezone}, ${here}) differs from the timezone of the IP's location (${timezone}, ${there}). That is common when a proxy or VPN is in another region.` });
    } else if (there && here) {
      signals.push({ level: 'ok', text: `Your browser's timezone matches the IP's location (${timezone}).` });
    }
  }
  if (org && HOSTING_NETWORK.test(org)) {
    signals.push({ level: 'note', hint: true, text: `The network (${org}) looks like a hosting or cloud provider. Proxies and VPNs usually run there, but so do ordinary servers.` });
  }
  const proxyHeaders = ['via', 'forwarded'].filter((name) => headers?.[name]);
  if (proxyHeaders.length) {
    signals.push({ level: 'note', hint: true, text: `The request carried proxy headers: ${proxyHeaders.map((name) => `${name}: ${headers[name]}`).join('; ')}.` });
  }
  return signals;
}

function connectionSummary(signals) {
  const proxy = signals.some((s) => s.level === 'proxy');
  const leak = signals.some((s) => s.level === 'warn');
  if (proxy && leak) return { kind: 'warn', text: 'Proxy in use, but an address leaks' };
  if (proxy) return { kind: 'info', text: 'A proxy or VPN is in use' };
  if (leak) return { kind: 'warn', text: 'Possible leak around your proxy' };
  if (signals.some((s) => s.hint)) return { kind: 'info', text: 'Signs of a proxy or VPN' };
  return { kind: 'pending', text: 'No sign of a proxy', title: 'These checks cannot prove that no proxy is in use.' };
}

function locationText(view) {
  const country = view.country ?? (view.countryCode ? regionName(view.countryCode) ?? view.countryCode : null);
  const text = [view.city, view.region, country].filter(Boolean).join(', ');
  return view.city ? text : text && `${text} (country only)`;
}

function connectionRows({ view, seen, direct, webrtc, network, ptr, browser }) {
  const checking = 'checking…';
  const webrtcText = webrtc === undefined ? checking
    : !webrtc.supported ? 'unavailable'
      : [webrtc.publicIps.length ? `public ${webrtc.publicIps.join(', ')}` : 'no public address',
        webrtc.localIps.length ? `local ${webrtc.localIps.join(', ')}` : null,
        webrtc.hidden ? `${webrtc.hidden} local address${webrtc.hidden === 1 ? '' : 'es'} hidden` : null].filter(Boolean).join(' · ');
  const alsoSeen = seen === undefined ? checking
    : seen.filter((a) => a.toLowerCase() !== view.ip.toLowerCase()).map((a) => `${a} (${a.includes(':') ? 'IPv6' : 'IPv4'})`).join(', ') || null;
  return [
    ['Location', locationText(view)],
    ['Also seen as', alsoSeen],
    ['Timezone of the IP', view.timezone ? `${view.timezone} (${utcOffset(view.timezone) ?? 'offset unknown'})` : null],
    ['Network', network === undefined ? checking : network?.asn ? `AS${network.asn}${network.org ? ` ${network.org}` : ''}` : null],
    ['Announced prefix', network === undefined ? checking : network?.prefix ? `${network.prefix}${network.country ? ` · registered ${network.country}` : ''}` : null],
    ['Reverse DNS', ptr === undefined ? checking : ptr ?? 'none'],
    ['This computer, direct', direct?.ip ? `${(direct.ips?.length ? direct.ips : [direct.ip]).join(', ')}${direct.country ? ` (${direct.country})` : ''}` : null],
    ['WebRTC', webrtcText],
    ['Cloudflare WARP', view.warp === undefined ? null : view.warp ? 'on' : 'off'],
    ['Browser', browser ? [browser.browser, browser.os].filter(Boolean).join(' on ') || null : null],
    ['Language', browser?.languages || null],
    ['Browser timezone', browser?.timezone ? `${browser.timezone} (${utcOffset(browser.timezone) ?? 'offset unknown'})` : null],
  ].filter(([, value]) => value);
}

// Drawn as soon as the address is known and again whenever another detail arrives. `undefined` means a
// piece is still being checked; `null` means it was checked and there is nothing to show.
function renderConnection(state) {
  const { view } = state;
  connBody.replaceChildren();
  $('conn-source').textContent = view ? `asked ${view.source}` : '';
  if (view === undefined) {
    connBody.append(h('p', { class: 'muted' }, 'Checking…'));
    return;
  }
  if (view === null) {
    connBody.append(h('p', { class: 'fail' }, "Couldn't find out your IP address. Check that you're online and that nothing is blocking the request, then press Recheck."));
    return;
  }
  const done = ['seen', 'direct', 'webrtc', 'network', 'ptr', 'browser'].every((key) => state[key] !== undefined);
  const signals = connectionSignals({
    ip: view.ip,
    seen: state.seen ?? [],
    echoOk: state.echoOk,
    timezone: view.timezone,
    browserTimezone: state.browser?.timezone,
    direct: state.direct,
    // A WebRTC verdict needs to know every address websites saw, so it waits for that.
    webrtc: state.seen === undefined ? undefined : state.webrtc,
    org: state.network?.org,
    headers: view.headers,
    warp: view.warp,
  });
  const summary = done ? connectionSummary(signals) : { kind: 'pending', text: 'Checking…' };
  const rows = connectionRows({ ...state, view });
  state.text = [`IP address: ${view.ip}`, ...rows.map(([label, value]) => `${label}: ${value}`), '', ...signals.map((s) => `${SIGNAL_LABELS[s.level]}: ${s.text}`)].join('\n');
  $('conn-copy').disabled = false;

  connBody.append(
    h('div', { class: 'conn-top' },
      h('span', { class: 'ip-big' }, view.ip),
      h('span', { class: 'badge pending' }, view.ip.includes(':') ? 'IPv6' : 'IPv4'),
      h('span', { class: `badge ${summary.kind}`, ...(summary.title ? { title: summary.title } : {}) }, summary.text),
    ),
    h('dl', { class: 'conn-rows' }, ...rows.flatMap(([label, value]) => [h('dt', {}, label), h('dd', {}, value)])),
    h('ul', { class: 'signals' }, ...signals.map((s) => h('li', {}, h('span', { class: `pill ${s.level}` }, SIGNAL_LABELS[s.level]), h('span', {}, s.text)))),
  );
}

// Ask both resolvers at once and take the first answer: a resolver that is slow or fails on one query
// should not hold up a detail the other can give straight away.
async function firstAnswer(lookup) {
  try {
    return await Promise.any([lookup('cloudflare'), lookup('google')]);
  } catch {
    return null;
  }
}

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

// One quick retry for a request that failed fast (a page that has only just opened can hit a hiccup).
// A request that timed out is not repeated: that path is stalled, and waiting again would not help.
function withRetry(fn) {
  const started = Date.now();
  return fn().catch(() => (Date.now() - started < 2500 ? sleep(1000).then(fn) : null)).catch(() => null);
}

async function checkConnection() {
  if (connChecking) return;
  connChecking = true;
  $('conn-recheck').disabled = true;
  $('conn-copy').disabled = true;
  const state = { view: undefined, seen: undefined, direct: undefined, webrtc: undefined, network: undefined, ptr: undefined, browser: undefined };
  lastConnection = state;
  const draw = () => {
    if (lastConnection === state) renderConnection(state);
  };
  draw();

  let site = null;
  let trace = null;
  let detailsFor = null;
  const update = () => {
    if (site?.ip) {
      state.view = {
        source: "this site's server", ip: site.ip, headers: site.headers ?? {},
        city: site.geo?.city, region: site.geo?.region, country: site.geo?.country,
        countryCode: site.geo?.countryCode, timezone: site.geo?.timezone,
      };
    } else if (trace && (isIPv4(trace.ip ?? '') || isIPv6(trace.ip ?? ''))) {
      state.view = { source: 'Cloudflare', ip: trace.ip, headers: {}, countryCode: trace.loc, warp: trace.warp === 'on' || trace.gateway === 'on' };
    } else if (site?.local && site.direct?.ip) {
      // Local mode falls back to this: the browser's own Cloudflare request can be blocked by an ad
      // blocker or browser privacy shield, or just fail on a flaky connection, even though the local
      // server's own check (which also tries icanhazip.com, not just Cloudflare) already succeeded.
      state.view = { source: 'the local server', ip: site.direct.ip, headers: {}, countryCode: site.direct.country };
    }
    // Reverse DNS and the network owner can be looked up as soon as the address is known.
    if (state.view && detailsFor !== state.view.ip) {
      const ip = state.view.ip;
      detailsFor = ip;
      state.network = undefined;
      state.ptr = undefined;
      firstAnswer((r) => lookupNetwork(r, ip)).then((value) => { if (detailsFor === ip) { state.network = value; draw(); } });
      firstAnswer((r) => lookupPtr(r, ip)).then((value) => { if (detailsFor === ip) { state.ptr = value; draw(); } });
    }
    draw();
  };

  // On the hosted site the site's own server reports the address the request arrived from; anywhere else
  // (or if that fails) Cloudflare does. The local server can only report this computer's own connection.
  const findAddress = async () => {
    for (let attempt = 0; attempt < 2 && !state.view; attempt++) {
      if (attempt) await sleep(1500);
      await Promise.all([
        siteWhoami().catch(() => null).then((value) => {
          site = value;
          state.direct = value?.local ? value.direct ?? null : null;
          update();
        }),
        cloudflareTrace().catch(() => null).then((value) => {
          trace = value;
          update();
        }),
      ]);
    }
    if (!state.view) {
      state.view = null;
      draw();
    }
  };

  const echoes = {};
  const seenWhenBothReport = () => {
    if ('v4' in echoes && 'v6' in echoes) {
      state.seen = [...new Set([echoes.v4, echoes.v6].filter(Boolean))];
      state.echoOk = { v4: Boolean(echoes.v4), v6: Boolean(echoes.v6) };
      draw();
    }
  };
  try {
    await Promise.all([
      findAddress(),
      webrtcCheck().then((value) => { state.webrtc = value; draw(); }),
      browserInfo().then((value) => { state.browser = value; draw(); }),
      withRetry(() => familyEcho('https://ipv4.icanhazip.com')).then((value) => { echoes.v4 = value; seenWhenBothReport(); }),
      withRetry(() => familyEcho('https://ipv6.icanhazip.com')).then((value) => { echoes.v6 = value; seenWhenBothReport(); }),
    ]);
    // Details are looked up on their own schedule; wait for them so the verdict is complete.
    for (let waited = 0; waited < 12000 && state.view && (state.network === undefined || state.ptr === undefined); waited += 200) await sleep(200);
    if (state.view) {
      if (state.network === undefined) state.network = null;
      if (state.ptr === undefined) state.ptr = null;
    }
    draw();
  } catch (err) {
    connBody.replaceChildren(h('p', { class: 'fail' }, `The connection check failed: ${err.message}`));
  } finally {
    connChecking = false;
    connCheckedAt = Date.now();
    $('conn-recheck').disabled = false;
  }
}

// --- Form ------------------------------------------------------------------

function showNotice(message) {
  notice.textContent = message;
  notice.hidden = !message;
}

// The DNS-server box needs a backend: the local server (which also allows proxies) or the hosted
// site's function (DNS servers only). With neither, the boxes stay hidden, so the page never offers
// something it cannot do.
function showServerFeatures(status) {
  backend = status?.serverMode === true ? 'local' : status?.hostedDns === true ? 'hosted' : 'none';
  if (backend === 'none') {
    // Explain the missing boxes when the page is opened as a file or from a local static server. On a
    // public host visitors cannot start anything, so nothing is shown there.
    const local = typeof location !== 'undefined'
      && (location.protocol === 'file:' || ['localhost', '127.0.0.1', '[::1]'].includes(location.hostname));
    if (local) $('local-hint').hidden = false;
    return;
  }
  const selector = backend === 'local' ? '#dns-field, #proxy-field, [data-local-only]' : '#dns-field, [data-hosted-only]';
  for (const el of document.querySelectorAll(selector)) el.hidden = false;
  if (backend === 'hosted' && status.region) $('hosted-region').textContent = `region ${status.region}`;
}

fetch('/api/status')
  .then((res) => (res.ok ? res.json() : null))
  .then((status) => showServerFeatures(status))
  .catch(() => showServerFeatures(null));

const linesOf = (box) => box.value.split('\n').map((line) => line.trim()).filter((line) => line && !line.startsWith('#'));

// Record types only apply to the browser-side lookup; server mode always asks for A and AAAA.
function syncMode() {
  typesFieldset.disabled = linesOf(proxiesInput).length > 0 || linesOf(dnsInput).length > 0;
}
proxiesInput.addEventListener('input', syncMode);
dnsInput.addEventListener('input', syncMode);

stopButton.addEventListener('click', () => controller?.abort());

function collectIps() {
  if (lastMode === 'server') {
    const answers = serverRun.sites.flatMap((site) => [...site.cells.values()].flatMap((cell) => (cell.ok ? cell.records.map((r) => r.value) : [])));
    return [...serverRun.vantages.map((v) => v.exitIp).filter(Boolean), ...answers]; // the proxies' own exit addresses too
  }
  return lastRun.flatMap((site) => sortedRecords(site).filter((r) => r.type === 'A' || r.type === 'AAAA').map((r) => r.value));
}

function rerenderAll() {
  if (lastMode === 'server') renderServerRun(serverRun);
  else lastRun.forEach((site) => renderCard(site, site.typeCount));
}

async function addIpDetails(resolver) {
  if (!detailsBox.checked) return;
  const unique = [...new Set(collectIps())].filter((ip) => isIPv4(ip) || isIPv6(ip));
  if (!unique.length) return;
  const before = summary.textContent;
  stopButton.hidden = false;
  await loadIpDetails(unique, resolver, () => controller.signal.aborted, (done, total) => {
    summary.textContent = `${before} Looking up IP details… ${done} of ${total}`;
  });
  detailsActive = true;
  rerenderAll();
  const known = unique.filter((ip) => ipInfo.has(ip)).length;
  const cap = unique.length > MAX_DETAIL_IPS ? ` (limited to the first ${MAX_DETAIL_IPS})` : '';
  summary.textContent = controller.signal.aborted ? 'Stopped.' : `${before} IP details for ${known} of ${unique.length} addresses${cap}.`;
}

form.addEventListener('submit', async (event) => {
  event.preventDefault();
  const proxies = linesOf(proxiesInput);
  const dns = linesOf(dnsInput);
  const serverMode = proxies.length > 0 || dns.length > 0;
  const types = [...form.querySelectorAll('input[name="type"]:checked')].map((box) => box.value);
  const { sites, skipped } = parseSites(input.value);
  const resolver = $('resolver').value;

  // Sites are optional when the request only asks about proxies (their addresses and DNS servers).
  const proxiesOnly = proxies.length > 0 && dns.length === 0;
  if (!sites.length && !proxiesOnly) {
    // Give specific feedback about what is actually in the DNS servers box, instead of a blanket
    // "enter a site" message that ignores it - for example someone pasting a proxy address there,
    // which is never valid there: this box takes a DNS server's own IP, not a proxy to route through.
    if (dns.length) {
      const parseLine = backend === 'hosted' ? parseHostedDns : parseLocalDnsPreview;
      const bad = dns.map((line, i) => ({ i, ...parseLine(line) })).find((r) => r.error);
      if (bad) return showNotice(`DNS servers, line ${bad.i + 1}: ${bad.error}`);
      return showNotice('DNS servers need at least one site to check them against. Add a site above'
        + (backend === 'local' ? ', or use the Proxies box below if you meant to enter a proxy address.' : '.'));
    }
    return showNotice('Enter at least one valid site URL or domain, or add proxies to check.');
  }
  if (!serverMode && !types.length) return showNotice('Select at least one record type.');
  showNotice(skipped.length ? `Skipped (not a domain name): ${skipped.join(', ')}` : '');

  goButton.disabled = true;
  stopButton.hidden = !serverMode;
  toolbar.hidden = true;
  detailsActive = false;
  controller = new AbortController();
  try {
    if (!serverMode) await lookup(sites, types, resolver);
    else if (backend === 'hosted') await lookupViaHosted(sites, dns, controller.signal);
    else await lookupViaServer(sites, { proxies, dns, resolvers: resolversBox.checked }, resolver, controller.signal);
    await addIpDetails(resolver);
    toolbar.hidden = false;
  } catch (err) {
    if (err.name === 'AbortError') {
      summary.textContent = 'Stopped.';
      toolbar.hidden = exportRows().length === 0;
    } else {
      showNotice(err instanceof TypeError
        ? (backend === 'hosted'
          ? 'Could not reach the lookup service. Check your connection and try again.'
          : 'Could not reach the lookup server. Proxies and DNS server lists need "node server.js" running at this address.')
        : err.message);
      summary.textContent = '';
    }
  } finally {
    goButton.disabled = false;
    stopButton.hidden = true;
    controller = null;
  }
});

input.addEventListener('keydown', (event) => {
  if ((event.ctrlKey || event.metaKey) && event.key === 'Enter') form.requestSubmit();
});

$('conn-recheck').addEventListener('click', () => checkConnection());
$('conn-copy').addEventListener('click', async (event) => {
  const button = event.currentTarget;
  try {
    await navigator.clipboard.writeText(lastConnection?.text ?? '');
    button.textContent = 'Copied!';
  } catch {
    button.textContent = 'Copy failed';
  }
  setTimeout(() => { button.textContent = 'Copy'; }, 1500);
});

// Someone who switches a proxy on or off leaves this tab and comes back, so check again when they do.
document.addEventListener?.('visibilitychange', () => {
  if (document.visibilityState === 'visible' && Date.now() - connCheckedAt > CONN_RECHECK_MS) checkConnection().catch(() => {});
});
globalThis.addEventListener?.('online', () => checkConnection().catch(() => {}));
checkConnection().catch(() => {});
