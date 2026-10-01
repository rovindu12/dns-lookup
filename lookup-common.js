'use strict';

// Helpers shared by the local server (server.js) and the hosted Netlify function (hosted-dns.js).

const net = require('net');

const RECORD_TYPES = { A: 1, AAAA: 28 };
const LABEL = /^[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?$/;

function isValidHost(host) {
  if (typeof host !== 'string' || host.length > 253) return false;
  const labels = host.split('.');
  return labels.length >= 2 && labels.every((label) => LABEL.test(label)) && !/^\d+$/.test(labels[labels.length - 1]);
}

const ERROR_TEXT = {
  ECONNREFUSED: 'connection refused',
  ENOTFOUND: 'host not found',
  ETIMEDOUT: 'timed out',
  ECONNRESET: 'connection reset',
  EHOSTUNREACH: 'host unreachable',
  ENETUNREACH: 'network unreachable',
  EACCES: 'blocked by the local firewall',
  EPERM: 'blocked by the local firewall',
};

function describeError(err) {
  return ERROR_TEXT[err.code] ?? err.message ?? String(err);
}

// Splits DNS answers into the addresses asked for and the CNAME chain that led to them.
function splitAnswers(answers, type) {
  return {
    records: answers
      .filter((a) => a.type === RECORD_TYPES[type] && net.isIP(a.data))
      .map((a) => ({ value: a.data, ttl: a.ttl })),
    cname: answers
      .filter((a) => a.type === 5)
      .map((a) => ({ name: a.name.replace(/\.$/, ''), target: a.data.replace(/\.$/, '') })),
  };
}

// The DNS test service (bash.ws) answers with one row per party that contacted it: the requester
// ("ip"), each DNS server that looked up one of the test names ("dns") and a verdict ("conclusion").
// Only the DNS servers are wanted, each once, with just the text fields we display.
function parseResolverResults(rows) {
  if (!Array.isArray(rows)) return [];
  const text = (value) => (typeof value === 'string' && value.trim() ? value.trim().slice(0, 80) : null);
  const servers = new Map();
  for (const row of rows) {
    if (row?.type !== 'dns' || typeof row.ip !== 'string' || !net.isIP(row.ip)) continue;
    if (!servers.has(row.ip)) {
      servers.set(row.ip, { ip: row.ip, country: text(row.country_name), asn: text(row.asn), org: text(row.org) });
    }
  }
  return [...servers.values()];
}

// Registry ("RIR") that runs a WHOIS server, keyed by the RDAP response's own port43 field.
const REGISTRY_NAMES = {
  'whois.arin.net': 'ARIN', 'whois.ripe.net': 'RIPE NCC', 'whois.apnic.net': 'APNIC',
  'whois.lacnic.net': 'LACNIC', 'whois.afrinic.net': 'AFRINIC',
};

// Pulls the fields worth showing out of an ip-api.com response. Returns null for anything that
// failed or that free-tier geolocation cannot usefully place (country-level accuracy at best;
// city/coordinates are estimates, not a physical trace).
function parseGeoResult(json) {
  if (!json || json.status !== 'success') return null;
  const text = (value) => (typeof value === 'string' && value.trim() ? value.trim() : null);
  return {
    country: text(json.country),
    countryCode: text(json.countryCode),
    region: text(json.regionName),
    city: text(json.city),
    lat: typeof json.lat === 'number' ? json.lat : null,
    lon: typeof json.lon === 'number' ? json.lon : null,
    timezone: text(json.timezone),
    isp: text(json.isp),
    org: text(json.org) !== text(json.isp) ? text(json.org) : null, // org often repeats isp; skip the duplicate
    // Free-tier signal only: three booleans, not a full classification. mobile/hosting come from
    // ip-api's own network-type database; proxy flags known anonymizer/VPN/proxy infrastructure.
    usage: json.hosting ? 'Hosting / datacenter' : json.proxy ? 'Known proxy or VPN infrastructure' : json.mobile ? 'Mobile network' : null,
  };
}

// Finds the vCard "fn" (name) and first "email" for an RDAP entity with the given role.
function vcardField(entity, field) {
  const row = (entity.vcardArray?.[1] ?? []).find(([name]) => name === field);
  return typeof row?.[3] === 'string' ? row[3] : null;
}

// Pulls the fields worth showing out of an RDAP (WHOIS) response for an IP network.
function parseWhoisResult(json) {
  if (!json || (!json.name && !json.handle)) return null;
  const cidr = json.cidr0_cidrs?.[0];
  const abuse = json.entities?.find((e) => e.roles?.includes('abuse')) ?? json.entities?.[0];
  return {
    registry: REGISTRY_NAMES[json.port43] ?? (typeof json.port43 === 'string' ? json.port43 : null),
    name: typeof json.name === 'string' ? json.name : null,
    range: json.startAddress && json.endAddress ? `${json.startAddress} - ${json.endAddress}` : null,
    cidr: cidr ? `${cidr.v4prefix ?? cidr.v6prefix}/${cidr.length}` : null,
    country: typeof json.country === 'string' ? json.country : null,
    lastChanged: json.events?.find((e) => e.eventAction === 'last changed')?.eventDate?.slice(0, 10) ?? null,
    abuseEmail: abuse ? vcardField(abuse, 'email') : null,
  };
}

module.exports = {
  RECORD_TYPES, isValidHost, describeError, splitAnswers, parseResolverResults, parseGeoResult, parseWhoisResult,
};
