#!/bin/bash
# One-click local dashboard: builds + serves the static app on http://localhost
# (a WebAuthn secure context) and opens it in your browser. The app talks to the
# ESP32 directly over HTTP — no proxy. Enter the device's IP in the app's IP box.
cd "$(dirname "$0")/supervisor-web" && exec trunk serve --open
