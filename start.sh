#!/usr/bin/env bash
# Starts the lookup server and opens it in your browser. Press Ctrl+C to stop it.
#   ./start.sh              uses port 8765
#   PORT=9000 ./start.sh    uses another port
cd "$(dirname "$0")" || exit 1
PORT="${PORT:-8765}"
URL="http://127.0.0.1:${PORT}"
up() { curl -s -m 1 -o /dev/null "${URL}/api/status"; }

if up; then
  echo "Already running at ${URL}"
else
  PORT="${PORT}" node server.js &
  SERVER=$!
  trap 'kill "${SERVER}" 2>/dev/null' EXIT INT TERM
  for _ in $(seq 1 50); do up && break; sleep 0.2; done
  up || { echo "The server did not start; see the message above."; exit 1; }
fi

echo "Open ${URL}"
xdg-open "${URL}" >/dev/null 2>&1 || open "${URL}" >/dev/null 2>&1 || true
if [ -n "${SERVER}" ]; then wait "${SERVER}"; fi
