<?php
// proxy.php - A simple HTTP-to-UDP bridge for the Critical Infrastructure Dashboard
// 
// Run with: php -S 0.0.0.0:8000
// The webapp can then fetch() from http://localhost:8000/proxy.php

header("Access-Control-Allow-Origin: *");
header("Access-Control-Allow-Methods: POST, OPTIONS");
header("Access-Control-Allow-Headers: *");

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(204);
    exit(0);
}

// The WebApp will send the raw encrypted envelope payload in the body
$payload = file_get_contents('php://input');

// We allow the IP to be passed via query string ?ip=192.168.x.x
$esp_ip = $_GET['ip'] ?? '192.168.1.100';
$port = 8080;

$sock = socket_create(AF_INET, SOCK_DGRAM, SOL_UDP);
if (!$sock) {
    http_response_code(500);
    echo "Could not create UDP socket";
    exit(1);
}

// Aggressive timeout of 2 seconds for embedded robustness
socket_set_option($sock, SOL_SOCKET, SO_RCVTIMEO, ["sec" => 2, "usec" => 0]);

error_log("Sending " . strlen($payload) . " bytes to UDP $esp_ip:$port Payload: $payload");

// Send the raw payload over UDP to the ESP32
socket_sendto($sock, $payload, strlen($payload), 0, $esp_ip, $port);

$buf = '';
// Wait for the ESP32 to reply
$bytes_received = @socket_recvfrom($sock, $buf, 1024, 0, $esp_ip, $port);
socket_close($sock);

if ($bytes_received === false) {
    http_response_code(504); // Gateway Timeout
    echo "ESP32 UDP Timeout";
} else {
    http_response_code(200);
    echo $buf;
}
?>
