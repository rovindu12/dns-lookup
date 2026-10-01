#!/usr/bin/env bash
# Builds dist/, the folder to deploy to Netlify: the static site in dist/public and the DNS functions
# (with the shared code they need) in dist/netlify/functions. server.js is never included.
#   ./build-netlify.sh                 site + hosted DNS-server lookups
#   STATIC_ONLY=1 ./build-netlify.sh   site only (no functions; the DNS-server box then stays hidden)
set -euo pipefail
cd "$(dirname "$0")"
rm -rf dist
mkdir -p dist/public
cp index.html style.css app.js pricing.html pricing.js dist/public/
printf '/*\n  X-Content-Type-Options: nosniff\n  X-Frame-Options: DENY\n  Referrer-Policy: no-referrer\n' > dist/public/_headers
if [ -z "${STATIC_ONLY:-}" ]; then
  mkdir -p dist/netlify/functions/lib
  cp dns-client.js lookup-common.js hosted-dns.js billing.js stripe.js billing-api.js dist/netlify/functions/lib/
  cp netlify-function/dns.mts netlify-function/status.mts netlify-function/whoami.mts \
     netlify-function/checkout.mts netlify-function/webhook.mts netlify-function/session-key.mts \
     dist/netlify/functions/
  if [ -d netlify-function/node_modules ]; then
    mkdir -p dist/netlify/functions/node_modules
    cp -r netlify-function/node_modules/@netlify dist/netlify/functions/node_modules/
    cp netlify-function/package.json dist/netlify/functions/package.json
  fi
fi
cp netlify.toml dist/netlify.toml
echo "Built dist/${STATIC_ONLY:+ (static only)}:"; (cd dist && find . -type f | sort)
