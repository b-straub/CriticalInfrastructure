#!/bin/bash

# Trap SIGINT and SIGTERM to kill all background child processes when the script exits
trap 'kill 0' EXIT

echo "[+] Starting PHP UDP Proxy on http://localhost:8000"
php -S localhost:8000 proxy.php > proxy.log 2>&1 &
PHP_PID=$!

echo "[+] Starting Yew WebApp Dashboard..."
cd supervisor-web && trunk serve
