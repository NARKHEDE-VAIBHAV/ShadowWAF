<?php
session_start();
$target = "http://localhost:5000/"; // Change this as per your target

function getClientIP() {
    $headers = [
        'HTTP_CF_CONNECTING_IP',
        'HTTP_X_FORWARDED_FOR',
        'HTTP_X_REAL_IP',
        'HTTP_CLIENT_IP',
        'REMOTE_ADDR'
    ];
    foreach ($headers as $header) {
        if (!empty($_SERVER[$header])) {
            $ip_list = explode(',', $_SERVER[$header]);
            return trim($ip_list[0]);
        }
    }
    return 'Unknown';
}
$client_ip = getClientIP();
$geo_info = getGeoIP($client_ip);
$country = $geo_info['countryCode'] ?? 'Unknown';
header("X-Client-IP: $client_ip");
header("X-Client-Country: $country");

$rate_limit_file = "/tmp/rate_limit_" . md5($client_ip);
$rate_data = file_exists($rate_limit_file) ? json_decode(file_get_contents($rate_limit_file), true) : ["count" => 0, "timestamp" => time()];
if (time() - $rate_data["timestamp"] < 60) {
    $rate_data["count"]++;
    if ($rate_data["count"] > 100) {
        http_response_code(429);
        exit("Too Many Requests");
    }
} else {
    $rate_data = ["count" => 1, "timestamp" => time()];
}
file_put_contents($rate_limit_file, json_encode($rate_data));

$blocked_ips = file_exists("/tmp/blocked_ips") ? file("/tmp/blocked_ips", FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) : [];
if (in_array($client_ip, $blocked_ips)) {
    http_response_code(403);
    exit("Forbidden");
}

function getGeoIP($ip) {
    $api = "https://api.ipgeolocation.io/ipgeo?apiKey=YOUR_API_KEY&ip={$ip}";
    $ch = curl_init($api);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    $response = curl_exec($ch);
    curl_close($ch);
    return json_decode($response, true) ?? null;
}

$request_data = urldecode(file_get_contents('php://input')) . " " . urldecode($_SERVER['REQUEST_URI']) . " " . json_encode($_GET) . " " . json_encode($_POST);
$request_data = str_replace("+", " ", $request_data); // Convert + to space for proper matching
$client_ip = $_SERVER['REMOTE_ADDR'];
$blocked_ips_file = "/tmp/blocked_ips";

$payloads = file("payload.txt", FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
$payloads = array_map(function($payload) {
    return str_replace("+", " ", trim($payload)); // Normalize payloads
}, $payloads);

foreach ($payloads as $line_number => $payload) {
    if (stripos($request_data, $payload) !== false) { // Case-insensitive check
        $line_number += 1; // Adjust for 1-based index (PHP arrays start from 0)

        file_put_contents($blocked_ips_file, "$client_ip $line_number - $payload \n", FILE_APPEND);

        $log_message = "Blocked IP: $client_ip | Matched Payload: Line $line_number - $payload";
        error_log($log_message);
        file_put_contents("php://stderr", "$log_message\n");

        http_response_code(403);
        exit("Suspicious Request Detected - IP Blocked\n$log_message");
    }
}

$user_agent = $_SERVER['HTTP_USER_AGENT'] ?? '';
if (empty($user_agent) || preg_match('/bot|curl|wget|scrapy|python/i', $user_agent)) {
    http_response_code(403);
    exit("Suspicious User-Agent Detected");
}

// Dynamically check if the request is over HTTP or HTTPS
$protocol = isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on' ? 'https' : 'http';

// If the connection is not secure, enforce redirection to HTTPS
if ($protocol === 'http') {
    $redirect_url = "https://" . $_SERVER['HTTP_HOST'] . $_SERVER['REQUEST_URI'];
    header("Location: $redirect_url", true, 301);
    exit();
}

// If it's already over HTTPS, proceed with normal operation
$requestUri = $_SERVER['REQUEST_URI'];
$ch = curl_init();
$headers = [];
foreach (getallheaders() as $name => $value) {
    if (!preg_match('/^Host|X-Forwarded-For|X-Real-IP|Via|Referer|User-Agent/i', $name)) {
        $headers[] = "$name: $value";
    }
}

curl_setopt($ch, CURLOPT_URL, $target . $requestUri);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_HEADER, true);
curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
curl_setopt($ch, CURLOPT_CUSTOMREQUEST, $_SERVER['REQUEST_METHOD']);
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    curl_setopt($ch, CURLOPT_POST, true);
    curl_setopt($ch, CURLOPT_POSTFIELDS, file_get_contents('php://input'));
}

$response = curl_exec($ch);
$headerSize = curl_getinfo($ch, CURLINFO_HEADER_SIZE);
$httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
curl_close($ch);

$headerText = substr($response, 0, $headerSize);
$body = substr($response, $headerSize);
foreach (explode("\r\n", $headerText) as $header) {
    if (!empty($header) && !preg_match('/^Transfer-Encoding:|^Content-Length:|^Server:/i', $header)) {
        header($header);
    }
}

http_response_code($httpCode);
echo $body;
?>
