# Bulk DNS Lookup

Paste site URLs or domains and get their DNS records and IP addresses, with details. Optionally add your own
list of DNS servers and/or proxies to see what each one returns.

## Quick start

1. **Install Node.js** if you don't have it: [nodejs.org](https://nodejs.org) (the LTS version). Nothing else
   to install — no dependencies.
2. **Run it:**
   - **macOS/Linux:** double-click `start.sh`, or in a terminal: `./start.sh`
   - **Windows:** double-click `start.bat`
   - **Any OS, from a terminal:** `npm start` (or `node server.js`), then open the printed address yourself
3. Your browser opens to `http://127.0.0.1:8765` automatically (on Windows/from a terminal, open it yourself
   if it doesn't). `PORT=9000 ./start.sh` (macOS/Linux) or `set PORT=9000 & start.bat` (Windows) to use a
   different port.
4. To stop it: close the terminal/window, or press Ctrl+C.

It runs entirely on your own machine — nothing is installed system-wide, and closing the window removes
nothing but the running process. Opening `index.html` directly from the folder (double-clicking it) does not
work for DNS servers and proxies, because those need the server; use `start.sh`/`start.bat` instead.

Without the server the page still works from any static file server: lookups run in the browser through
DNS-over-HTTPS. The DNS-server and proxy boxes are hidden then, and when the page is opened as a file or from
localhost a notice says how to start the server. On the Netlify deployment the DNS-server box works through the
site's function (see Publishing).

## What you get

- **Your connection** (top of the page): the IP address websites see for your browser, and details about it, so
  you can tell what a proxy or VPN is doing. It shows the address (IPv4 and IPv6), the network owner and announced
  prefix, reverse DNS, location, browser and timezone, and checks for the ways a browser can give itself away
  around a proxy:
  - *Proxy in use*: on the local version, your browser's address is compared with this computer's own connection.
    A different address means the browser is going through a proxy or VPN.
  - *WebRTC*: browsers can reveal your real address through WebRTC even when a proxy is set. The panel reports
    whether WebRTC exposes an address websites did not see. It says "leak" only when there is evidence (for
    example WebRTC shows this computer's own address while the browser is behind a proxy), and says so when a check
    did not answer instead of guessing.
  - *Timezone* of the IP's location versus your browser's, and whether the network looks like a hosting provider.
  These are signals, not proof, and the panel says what each one usually means. The address comes from this site's
  server on the hosted version, or from Cloudflare otherwise; press **Recheck** after switching a proxy on or off
  (it also rechecks when you return to the tab). The address shows within a fraction of a second; the details fill in as they arrive.
- **Records:** A, AAAA, CNAME, MX, NS, TXT, SOA, CAA for every site (browser mode).
- **IP details** for every address (on by default): reverse DNS, the AS number and network owner, the announced
  prefix and the registry country. This comes from two more DNS lookups per address (PTR, and Team Cymru's
  IP-to-ASN mapping); the most specific announced prefix is reported. The country is the prefix's registry
  country, not a physical location.
- **Export** as CSV or JSON, including the details.

## DNS servers

Available on the local server (everything below) and, with the limits described under Publishing, on the
Netlify deployment. One per line, as an IP address with an optional port and name:

```
8.8.8.8
1.1.1.1 Cloudflare
[2001:4860:4860::8888]:53
192.0.2.53:5353 office resolver
```

Every site is asked of every server directly, over UDP (TCP when the answer is truncated), using the DNS wire
protocol, for A and AAAA. Per server and site you see:

- the status (NOERROR, NXDOMAIN, SERVFAIL, REFUSED, timed out, ...) and the transport;
- the response time (average of the A and AAAA queries; hover for each one);
- flags: `authoritative` when the server answers for the zone itself, `DNSSEC-validated` when a validating
  resolver vouches for the answer, `no recursion` when it will not resolve for you;
- every address with its exact TTL, plus the CNAME chain;
- a summary card per server: answered / total, average time, and what went wrong.

A server that gives no reply to its first 3 queries is skipped for the rest of the run, so one dead entry
does not stall a long list.

## Proxies (local server only)

One per line (blank lines and `#` comments are ignored):

```
203.0.113.10:8080
user:pass@198.51.100.7:3128
192.0.2.9:8000:user:pass
https://user:pass@proxy.example.com:443
socks5://user:pass@192.0.2.5:1080
```

The server opens a tunnel (HTTP `CONNECT` or SOCKS5) per proxy, records the proxy's exit IP and country (with the
network owner and prefix of the exit IP), and runs the lookups from there. Dead, unreachable or wrongly authenticated proxies are listed with the reason and
skipped.

- **With DNS servers listed**, each query goes over TCP inside the tunnel to that server. SOCKS5 proxies
  normally allow this. Many HTTP proxies only allow `CONNECT` to port 443 and will show as
  "proxy refused the connection (HTTP 403)" for port 53; that is reported, not hidden.
- **Without DNS servers**, the selected resolver (Google or Cloudflare) is queried over HTTPS through each
  proxy. Use Google to compare locations: it passes the client's network (EDNS Client Subnet) on to the
  domain's DNS servers. For a site that answers by region (for example `www.instagram.com`) Google returned
  different addresses for different client networks, and its default matched the caller's own /24. Many sites
  do not do this (`www.google.com`, `www.microsoft.com`), so identical results everywhere are normal for them.
- **Proxy address, exit IP details and DNS servers.** Paste only proxies (leave the sites box empty) to check
  just them. For each proxy you get:
  - its own address (what its host name resolves to);
  - its exit IP, with reverse DNS and the network owner/prefix (from a DNS-based IP-to-ASN lookup);
  - the exit IP's **location, ISP and registry** — city/region/country, coordinates, timezone and usage type
    (residential/mobile/hosting/known-proxy, a best-effort signal) from `ip-api.com`'s free geolocation API, and
    the registry WHOIS (which RIR allocated it, the network's name, range and registration date, and an abuse
    contact) from the RDAP system (`rdap.org`). Both are asked directly about the exit IP already learned from
    the proxy, never through the proxy itself, and are cached for 10 minutes per address. Free-tier geolocation
    is a rough placement from the network's registered address, not a physical trace — city/coordinates can be
    off by a town or two, as they were in testing.
  - unless you turn it off, **the DNS servers it uses**. A proxy resolves host names with its own DNS servers, so
    each proxy is asked to look up 16 unique test names, and the public test service bash.ws reports which DNS
    servers asked. That means bash.ws sees random test names and the addresses of the DNS servers (not your
    sites, and not your proxies' passwords). This computer's own DNS servers are looked up the same way for
    comparison, and a proxy that uses one of them is flagged.
    What the list means: these are the addresses DNS servers use when they contact the internet, which can differ
    from the resolver address a proxy is configured with, and a big resolver (Google, Cloudflare) shows a pool of
    addresses; a residential ISP's full pool is often larger than what one check catches; repeating the check can
    surface more of it. "None found" means the proxy did not look up any of the names, for example because it
    refused the connection before resolving or does not resolve names itself. Only proxies that answered are asked.
    A resolver-farm ISP can return dozens of addresses; the page shows the first 8 with a "+N more" note and
    keeps the rest in the CSV/JSON export, so one proxy's row does not push every other proxy off screen when
    comparing several at once.
- **Does the proxy actually change your IP, and is it going through Cloudflare WARP?** The same two signals
  "Your connection" shows for your browser, computed here for each proxy from the server's side: a
  **changes IP** / **no change** pill next to Status (compares the proxy's exit IP against this computer's own
  direct connection, shown as a note under the table — the direct check never goes through any proxy), and a
  note when the proxy's own connection is itself going through Cloudflare WARP.
- **What this cannot show:** a proxy's **WebRTC leak**, **browser or TCP/TLS fingerprint** (OS, JA3/JA4 TLS
  fingerprint, HTTP/2 fingerprint, `User-Agent`/`Sec-CH-UA` headers), or **browser language**. Those all
  describe the network stack that opens the connection at the OS level; a site like browserleaks.com sees them
  because a real browser, with its OS network settings pointed at the proxy, made the request. WebRTC
  specifically does not travel through an HTTP/SOCKS proxy at all, so there is nothing a proxy-mediated request
  could show for it regardless. This tool asks the proxy itself to make each connection instead (the only way a
  script can drive an arbitrary proxy without changing the machine's own network configuration), so any such
  fingerprint it reported would describe this computer, not the proxy — showing one would be misleading, so
  none is shown. To see that data for a proxy, point your OS's or browser's own network/proxy settings at it
  and visit a fingerprinting site directly.
- Credentials are used only to authenticate to the proxy. They are never returned to the page, shown or
  exported. The server listens on 127.0.0.1 only and rejects requests with a foreign `Host` header.

## Publishing (Netlify)

`./build-netlify.sh` builds `dist/`, the folder to deploy: the static site in `dist/public` and six Netlify
Functions with the shared code they need: `/api/dns` (the lookups, rate limited and metered — see "Paid tier"
below), `/api/status` (tells the page the DNS-server box is available; kept separate so a rate-limited visitor
still sees the box), `/api/whoami` (reports the address a request came from, with Netlify's location estimate,
to that caller only), and `/api/checkout`, `/api/webhook`, `/api/session-key` (the Stripe-backed paid tier).
`server.js` is never included.

The first build needs the shared dependency installed once: `cd netlify-function && npm install && cd ..` (adds
`@netlify/blobs`, used to store API keys and usage counts; `build-netlify.sh` then copies `node_modules` into
`dist/` automatically on every build after that).

**Off switch:** `STATIC_ONLY=1 ./build-netlify.sh` builds the site without the functions. Deploy that and the
public DNS-server box disappears (lookups and IP details still work). You can also disable or delete the
functions in the Netlify dashboard.

Deployed at https://cool-croissant-869add.netlify.app (Netlify adds its own small toolbar script to served
pages; the page's security policy blocks its inline parts, which is harmless).
Deploy `dist/` with the Netlify CLI or the Netlify connector (`netlify deploy --prod --dir=dist/public
--functions=dist/netlify/functions`, or run the connector's command from inside `dist/`).

The published site has the full lookup page and, for visitors, a **DNS servers** box:

- Lookups run from Netlify's servers, not the visitor's network, so response times and location-based answers
  reflect that place. The page says so, and shows the region when Netlify reports it.
- The function only sends DNS queries (UDP, port 53) and is deliberately narrow, because anyone can reach it:
  public IP addresses only (private, loopback, link-local, cloud-metadata, shared, documentation and multicast
  ranges are refused, including tricks like `010.0.0.1`), one DNS server and at most 5 domains per request, JSON
  from the site's own pages only, request-size limits, and a per-address rate limit (60 requests a minute, plus
  the same limit in the function config for Netlify to enforce). The page allows 5 servers and 40 requests per
  lookup.
- There are no proxies on the public site. `server.js` connects to whatever address it is told, so it stays on
  your own machine.

Use the local version (`./start.sh`) for private or LAN DNS servers, other ports, proxies and large lists.

## Paid tier (API keys, Stripe)

The hosted `/api/dns` endpoint is metered: 10 checks a day per visitor IP address for free, no account needed.
An API key (`dnslk_…`, pasted into the **API key** field on the main page or sent as an `X-API-Key` header)
raises that to 1000 a day. Usage counts and keys are stored in [Netlify Blobs](https://docs.netlify.com/blobs/overview/),
so they persist across deploys and warm/cold function instances — a plain in-memory counter would not. `pricing.html`
is the signup page; it posts to `/api/checkout` to start a Stripe Checkout session and, on return, claims the new
key from `/api/session-key` (shown once, right after payment, never again — there is no email delivery built in).

This repo has no Stripe account wired in; payments stay off (`/api/checkout` returns a clear "not configured yet"
error, the rest of the site is unaffected) until the site owner sets one up:

1. Create a [Stripe](https://stripe.com) account (or use an existing one) and switch to **test mode** first.
2. **Products → Add product**, e.g. "Pro API access", priced as a monthly subscription. Copy its **Price ID**
   (`price_…`).
3. **Developers → API keys**: copy the **Secret key** (`sk_…`; use the test one while testing, the live one when
   ready to charge real cards).
4. **Developers → Webhooks → Add endpoint**: URL `https://<your-site>/api/webhook`, events
   `checkout.session.completed`, `customer.subscription.deleted`, `customer.subscription.updated`. Copy the
   endpoint's **Signing secret** (`whsec_…`).
5. Set three environment variables on the Netlify site (**Site configuration → Environment variables**, or
   `netlify env:set NAME value`): `STRIPE_SECRET_KEY`, `STRIPE_PRICE_ID`, `STRIPE_WEBHOOK_SECRET`. Redeploy after
   setting them (functions read `process.env` at cold start).
6. Test with [Stripe's test card numbers](https://docs.stripe.com/testing) before switching the secret key and
   webhook to live mode.

To change the daily limits or add more plans, edit `PLANS` in [`billing.js`](billing.js) and redeploy — nothing
else needs to change. Canceling a subscription in Stripe (or the customer doing it from their receipt email)
fires `customer.subscription.deleted`/`updated`, which deactivates that key the same way.

## Reading the numbers

- TTL is what the answering server reports: for a recursive resolver, the time left in its cache (at most the
  zone's TTL); an authoritative server reports the zone's TTL.
- Load-balanced and geo-DNS names can return different addresses from one query to the next, and different
  servers can legitimately disagree.
- Response times are measured from the machine running `node server.js` (through the proxy when one is used).
  DNS-over-HTTPS lookups show no time, because each opens a fresh connection.

## Verification

Checked against `dig` (UDP, straight to each domain's authoritative servers and to 8.8.8.8 / 1.1.1.1 / 9.9.9.9):

- 20 domains x 8 record types x 2 resolvers through the page's own lookup code: 548 comparisons, 0 errors.
  The 6 differences were rotating address pools and github.com publishing different SOA records at its two
  DNS providers; both are correct answers.
- The DNS client: answers, status codes, flags, TCP fallback, timeouts: 129 checks.
- DNS servers x proxies x sites through HTTP, SOCKS5 and password-protected tunnels: 511 checks.
- The hosted endpoint: 90+ refused addresses and inputs (private ranges, metadata addresses, octal and mapped
  tricks, malformed requests), range boundaries, caller and size checks, the rate limit, and live answers
  compared with `dig`: 199 checks.
- IP details (reverse DNS, ASN, network, prefix, IPv6 reverse names): 47 checks, plus partial answers (reverse DNS
  can fail while the network owner works).
- The connection panel's logic: 64 checks (proxy and leak decisions, dual-stack machines, WebRTC candidates,
  timezone aliases, wording).
- Proxy DNS-server discovery: three test proxies resolving with different DNS servers (this machine's, Google's
  8.8.8.8, Cloudflare's 1.1.1.1) each reported their own DNS servers (Mobitel's, Google's, Cloudflare's), a proxy
  that never resolves anything reported none, and a dead proxy was skipped; the result parser has 15 checks.
- Proxy traffic is proven to go *through* the proxy: a proxy that carries no data makes lookups time out, and a
  forwarding proxy that counts bytes shows the requests and DNS queries passing through it, over both HTTP
  `CONNECT` and SOCKS5 (with a password). An earlier version opened the tunnel but sent its HTTPS requests
  around it; that is fixed.
- The exit-IP geolocation and WHOIS parsers, and the on-screen resolver-list cap: 42 checks against real
  captured API responses and rendered output.
- Input parsing and record formatting edge cases: 60 checks.

**Checked against a real commercial residential proxy provider** (not just local test doubles): 6 of a batch of
paid Japan-based residential sessions all connected, each with a distinct real exit IP and its ISP's real DNS
servers correctly attributed (JCom, Cable Media WAIWAI, Biglobe, Arteria, NTT Docomo Business); none shared a
DNS server with this machine's own. One of those sessions was then cross-checked against
[browserleaks.com/ip](https://browserleaks.com/ip) (opened through the same proxy in a real browser) as an
independent reference: exit IP, reverse-DNS hostname, ISP, network, timezone and the registry WHOIS record
(registry, network name, CIDR, registration date) all matched exactly; city/coordinates were close but not
identical, expected for two different free geolocation databases; the DNS-leak test found the same DNS servers
browserleaks found, arriving at them a few per check rather than all at once (see "What this cannot show" above
for why the browser-fingerprint fields aren't attempted).

**Comparing against this computer's own connection, at scale:** a proxy whose exit IP happens to match this
computer's own direct connection is not actually changing your address (a broken, misconfigured or transparent
proxy) — flagged with a "no change" pill instead of a silent "changes IP" everywhere. Verified with a proxy
running on this same machine (its exit IP is, by construction, identical to this computer's own — correctly
flagged "no change") alongside a real residential proxy in Japan (correctly flagged "changes IP"); both pills,
the WARP flag, and the export columns (`exit_changes_ip`, `exit_warp`) checked with 24 unit tests plus this live
round-trip.

**Checking multiple proxies at once:** the first version shared one concurrency pool between the DNS-leak
probing (bash.ws) and the exit-IP lookups (ip-api.com, RDAP) — checking several proxies together could queue
lightweight geo/WHOIS lookups behind the slower multi-round DNS probing. Each now has its own pool. A response
that means "geolocation service is rate-limited right now" (distinct from "this address cannot be geolocated")
is also no longer cached as a permanent failure, so a busy moment does not hide an address's location for the
next 10 minutes. Verified with 5 and then 10 real residential proxies checked in a single request: every one
came back with its own distinct, correctly attributed exit IP, city, ISP and WHOIS record (SoftBank/BBTEC,
Chubu/COMMUFA, STNet/PIKARA, NTT/OCN, Sony/So-net, KDDI, JPNE — no cross-contamination between proxies), full
results in 15-17 seconds either way.

Not tested: real proxies outside Japan (only local test proxies for other countries, so "a proxy in use" was
checked there with a simulated proxied browser), and DNS servers reached over IPv6.
