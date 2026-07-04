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

$fp = @fsockopen($esp_ip, $port, $errno, $errstr, 2.0);
if (!$fp) {
    http_response_code(504); // Gateway Timeout
    echo "ESP32 TCP Timeout or Connection Refused";
} else {
    stream_set_timeout($fp, 2);
    error_log("Sending " . strlen($payload) . " bytes to TCP $esp_ip:$port Payload: $payload");
    fwrite($fp, $payload);
    
    $buf = '';
    while (!feof($fp)) {
        $data = fread($fp, 1024);
        if ($data === false || strlen($data) == 0) break;
        $buf .= $data;
    }
    fclose($fp);
    
    http_response_code(200);
    echo $buf;
}
?>
