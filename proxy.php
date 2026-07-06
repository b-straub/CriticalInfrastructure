<?php
// proxy.php — HTTP→TCP bridge to the ESP32, hardened for internet-facing use.
//
// The WebApp POSTs the encrypted command envelope; this forwards it over TCP to
// the device (port 8080) and returns the signed, encrypted response. Command
// authenticity is enforced by the ESP itself (Ed25519 + roles) — this proxy's
// only job is to forward bytes WITHOUT becoming an open TCP relay.
//
// Dev:  php -S 0.0.0.0:8000 proxy.php   (Trunk proxies /proxy.php to it)
// Prod: drop next to the built dist/ on an Apache/PHP host, served same-origin.

// ============================ CONFIG — edit these ============================

// Exact hosts this proxy may connect to. The client's ?ip= must match one of
// these EXACTLY. THIS IS THE SSRF GUARD: without it, anyone could make the
// server open a TCP socket to any address (your LAN, 169.254.169.254 cloud
// metadata, etc.). Fail-closed — an empty list allows nothing.
//   VPN-reachable device:    '10.8.0.5'   or  '192.168.1.100'
//   Public IP / DynDNS host: 'esp.example.dyndns.org'
$ALLOWED_TARGETS = [
    // 'esp.example.dyndns.org',
    // '192.168.1.100',
];

$ESP_PORT        = 8080;       // fixed device port
$MAX_BODY_BYTES  = 8 * 1024;   // the envelope is small; cap to blunt abuse
$CONNECT_TIMEOUT = 2.0;        // seconds

// Same-origin deploy (app + proxy on one host) needs no CORS — leave null. Set
// to the exact app origin only if the app is served from a DIFFERENT origin.
$ALLOWED_ORIGIN  = null;       // e.g. 'https://dashboard.example.com'

// Optional shared token: the app must send it as the X-Proxy-Token header.
// NOTE: the app is public JS, so a token baked into it is NOT secret — this only
// deters casual drive-by abuse. The real controls are $ALLOWED_TARGETS + HTTPS.
$PROXY_TOKEN     = getenv('PROXY_TOKEN') ?: null;

// ============================================================================

// CORS: only emitted when a cross-origin app is configured.
if ($ALLOWED_ORIGIN !== null && ($_SERVER['HTTP_ORIGIN'] ?? '') === $ALLOWED_ORIGIN) {
    header("Access-Control-Allow-Origin: $ALLOWED_ORIGIN");
    header('Access-Control-Allow-Methods: POST, OPTIONS');
    header('Access-Control-Allow-Headers: X-Proxy-Token');
    header('Vary: Origin');
}
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(204);
    exit;
}

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    header('Allow: POST');
    exit('Method Not Allowed');
}

if ($PROXY_TOKEN !== null && !hash_equals($PROXY_TOKEN, $_SERVER['HTTP_X_PROXY_TOKEN'] ?? '')) {
    http_response_code(401);
    exit('Unauthorized');
}

$target = $_GET['ip'] ?? '';
if (!in_array($target, $ALLOWED_TARGETS, true)) {
    http_response_code(403);
    exit('Target not allowed');
}

// Read the body with a hard cap, then sanity-check its shape. The envelope is
// hex fields joined by ';' (ephemeral;iv;ciphertext) — nothing else is valid.
$payload = file_get_contents('php://input', false, null, 0, $MAX_BODY_BYTES + 1);
if ($payload === false || $payload === '' || strlen($payload) > $MAX_BODY_BYTES
    || !preg_match('/^[0-9a-fA-F;]+$/', $payload)) {
    http_response_code(400);
    exit('Bad payload');
}

$fp = @fsockopen($target, $ESP_PORT, $errno, $errstr, $CONNECT_TIMEOUT);
if (!$fp) {
    http_response_code(504);
    exit('ESP32 TCP Timeout or Connection Refused');
}

stream_set_timeout($fp, 2);
fwrite($fp, $payload);

$buf = '';
while (!feof($fp)) {
    $data = fread($fp, 1024);
    if ($data === false || strlen($data) === 0) {
        break;
    }
    $buf .= $data;
}
fclose($fp);

http_response_code(200);
header('Content-Type: text/plain');
echo $buf;
