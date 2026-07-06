#!/bin/bash
# One-click local dashboard. Serves the static app and opens it at LOCALHOST —
# NOT 127.0.0.1. WebAuthn scopes passkeys to the exact hostname, so `localhost`
# and `127.0.0.1` are different origins; opening the IP would hide your passkeys
# (and an IP isn't a valid WebAuthn rp.id anyway). The app talks to the ESP32
# directly over HTTP; enter the device's IP in the app's IP box.
cd "$(dirname "$0")/supervisor-web"

url="http://localhost:8080"
# Wait until trunk is actually serving, then open localhost (not trunk --open,
# which uses 127.0.0.1).
(
  for _ in $(seq 1 60); do
    curl -sf -o /dev/null "$url" && break
    sleep 0.5
  done
  command -v open >/dev/null 2>&1 && open "$url" || xdg-open "$url" >/dev/null 2>&1 || true
) &

exec trunk serve --address 127.0.0.1 --port 8080
