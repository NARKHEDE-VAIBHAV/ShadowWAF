<?php
session_start();
$target = "http://localhost:4040/";
$filtered_headers[] = "X-Forwarded-For: 127.0.0.1";  


$backend_servers= $target;
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

$payloads = file("payload2.txt", FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
$payloads = array_map(function($payload) {
    return str_replace("+", " ", trim($payload));
}, $payloads);

foreach ($payloads as $line_number => $payload) {
    if (stripos($request_data, $payload) !== false) { 
        $line_number += 1; 

        file_put_contents($blocked_ips_file, "$client_ip $line_number - $payload \n", FILE_APPEND);

        $log_message = "Blocked IP: $client_ip | Matched Payload: Line $line_number - $payload";
        error_log($log_message);
        file_put_contents("php://stderr", "$log_message\n");

        http_response_code(403);
        exit("Suspicious Request Detected - IP Blocked\n$log_message");
    }
}


$sql_keywords = [
    "select", "union", "insert", "drop", "update", "delete", "or", "and", 
    "having", "null", "database", "table", "from", "where", "group", "limit", 
    "like", "order", "by", "concat", "into", "substr", "user", "information_schema", 
    "sleep", "--", "#", ";", "'", "\"", "/*", "*/", "csrf_token", "username", "password"
];

$max_request_length = 5000;


$request_data = file_get_contents('php://input');
$client_ip = getClientIP();


if (strlen($request_data) > $max_request_length) {
    $log_message = "Request data exceeds maximum length from IP: $client_ip";
    error_log($log_message);
    file_put_contents("php://stderr", "$log_message\n");

    file_put_contents("/tmp/blocked_ips", "$client_ip Request Too Large\n", FILE_APPEND);
    http_response_code(413); 
    exit("Request data exceeds allowed size");
}

// Loop through keywords to detect potential SQL injection attempts
foreach ($sql_keywords as $keyword) {
    if (stripos($request_data, $keyword) !== false) {
        
        if (strpos($request_data, 'csrf_token') !== false || strpos($request_data, 'username') !== false || strpos($request_data, 'password') !== false) {
            continue; 


        $log_message = "SQL Injection Detected: Keyword '$keyword' found in request from IP: $client_ip";
        error_log($log_message);
        file_put_contents("/tmp/blocked_ips", "$client_ip SQL Injection: $keyword \n", FILE_APPEND);

        http_response_code(403);
        exit("SQL Injection Suspicion - IP Blocked");
    }
}


if (preg_match('/(\(|\))/i', $request_data) && substr_count($request_data, '(') !== substr_count($request_data, ')')) {
    $log_message = "SQL Injection Detected: Unbalanced parentheses in request from IP: $client_ip";
    error_log($log_message);
    file_put_contents("php://stderr", "$log_message\n");

    file_put_contents("/tmp/blocked_ips", "$client_ip Unbalanced Parentheses\n", FILE_APPEND);
    http_response_code(403);
    exit("SQL Injection Suspicion - Unbalanced Parentheses");
}


if (substr_count($request_data, "--") > 2 || substr_count($request_data, "#") > 2) {
    $log_message = "SQL Injection Detected: Excessive comment markers in request from IP: $client_ip";
    error_log($log_message);
    file_put_contents("php://stderr", "$log_message\n");

    file_put_contents("/tmp/blocked_ips", "$client_ip Excessive Comments\n", FILE_APPEND);
    http_response_code(403);
    exit("SQL Injection Suspicion - Excessive Comments");
}

$user_agent = $_SERVER['HTTP_USER_AGENT'] ?? '';
if (empty($user_agent) || preg_match('/bot|curl|wget|scrapy|python/i', $user_agent)) {
    http_response_code(403);
    exit("Suspicious User-Agent Detected");
}




$use_https = ($protocol === 'https');
$backend_url = $use_https ? $backend_servers[1] : $backend_servers[0];
$target_url = $backend_url . $_SERVER['REQUEST_URI'];  


$ch = curl_init($target_url);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_HEADER, true);
curl_setopt($ch, CURLOPT_FOLLOWLOCATION, false);  

$request_headers = getallheaders();
$filtered_headers = [];
foreach ($request_headers as $key => $value) {
   
    if (!in_array(strtolower($key), ['host', 'referer', 'x-forwarded-for'])) {
        $filtered_headers[] = "$key: $value";
    }
}


$filtered_headers[] = "Host: " . parse_url($backend_url, PHP_URL_HOST);
$filtered_headers[] = "X-Forwarded-For: 127.0.0.1";  
curl_setopt($ch, CURLOPT_HTTPHEADER, $filtered_headers);

if (in_array($_SERVER['REQUEST_METHOD'], ['POST', 'PUT', 'PATCH'])) {
    curl_setopt($ch, CURLOPT_POSTFIELDS, file_get_contents("php://input"));
}


$response = curl_exec($ch);
$header_size = curl_getinfo($ch, CURLINFO_HEADER_SIZE);
$http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
curl_close($ch);


$response_headers = substr($response, 0, $header_size);
$response_body = substr($response, $header_size);








class test {
    private $keyFile = 'challenge_keys.json'; 
    private $keygen = false;  

    public function __construct() {
        $this->cleanExpiredKeys();
        if ($this->verifyChallenge()) {
            $_SESSION['verified'] = true;
            $this->keygen = true; 
        } else {
           
            $this->keygen = false;
            $this->serveChallenge();
        }


        if ($this->keygen) {
            exit; 
        }
    }

    private function generateKeys() {

        $parts = [
            bin2hex(random_bytes(8)),
            bin2hex(random_bytes(8)),
            bin2hex(random_bytes(8))
        ];
        $key = hash('sha256', implode('', $parts)); 

        $this->storeKey($key); 
        $_SESSION['challenge_parts'] = $parts;  
        $_SESSION['challenge_key'] = $key; 
    }

    private function storeKey($key) {
       
        $keys = file_exists($this->keyFile) ? json_decode(file_get_contents($this->keyFile), true) : [];
        $keys[$key] = time() + 120;
        file_put_contents($this->keyFile, json_encode($keys));

    private function cleanExpiredKeys() {

        if (!file_exists($this->keyFile)) return;


        $keys = json_decode(file_get_contents($this->keyFile), true);
        $currentTime = time();
        $keys = array_filter($keys, function ($expiry) use ($currentTime) {
            return $expiry > $currentTime;
        });

        file_put_contents($this->keyFile, json_encode($keys));
    }

    private function verifyChallenge() {
        if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['key'])) {
            $keys = file_exists($this->keyFile) ? json_decode(file_get_contents($this->keyFile), true) : [];

            if (isset($keys[$_POST['key']])) {
                setcookie('challenge_verified', $_POST['key'], time() + 120, '/');  
                return true;
            }
        }


        return false;
    }

    private function serveChallenge() {
       
        if ($this->keygen == false) {
            $this->generateKeys();  
            $parts = $_SESSION['challenge_parts'];  
            header('Content-Type: text/html; charset=UTF-8');
            echo "<script>
if (!document.cookie.includes('challenge_verified=')) {
    async function complexChallenge() {
        let parts = ['{$parts[0]}', '{$parts[1]}', '{$parts[2]}'];
        let solvedKey = '';
        const delay = (ms) => new Promise(resolve => setTimeout(resolve, ms));
        await delay(500 + Math.random() * 1500);  // Simulate some processing delay


        let solvedHash = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(parts.join('')));
        solvedKey = Array.from(new Uint8Array(solvedHash)).map(b => b.toString(16).padStart(2, '0')).join('');

        document.cookie = 'challenge_verified=' + solvedKey + '; path=/; max-age=120';


        let response = await fetch('', {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: 'key=' + encodeURIComponent(solvedKey)
        });

        if (response.ok) {
            window.location.reload();
        }
    }
    complexChallenge();
}
</script>
";
            exit;
        }
    }
}

new test();









$ch = curl_init($backend_url);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_HEADER, true);
curl_setopt($ch, CURLOPT_FOLLOWLOCATION, false); 
$response = curl_exec($ch);
$header_size = curl_getinfo($ch, CURLINFO_HEADER_SIZE);
$http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
curl_close($ch);

$response_headers = substr($response, 0, $header_size);
$response_body = substr($response, $header_size);

// **Force HTTP 200 instead of 302**
if ($http_code == 302) {
    header("HTTP/1.1 200 OK");
} else {
    header("HTTP/1.1 $http_code");
}

// **Filter Headers (Remove Location)**
foreach (explode("\r\n", $response_headers) as $header) {
    if (stripos($header, "Location:") !== false) {
        continue; // Completely drop redirects
    }
    if (!preg_match('/^(X-Powered-By|Content-Length|Server)/i', $header)) {
        header($header);
    }
}

echo $response_body;















// Output the response body
echo $response_body;

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


