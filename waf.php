<?php
session_start();
ob_start();

// Configuration
$config = [
    'target' => "http://localhost:4040/",
    'payload_dir' => __DIR__ . "/payloads",
    'rate_limit_file' => "/tmp/rate_limit_" . md5(getClientIP()),
    'blocked_ips_file' => "/tmp/blocked_ips.json",
    'log_file' => "/tmp/waf_attack_log.txt",
    'geo_api_key' => "YOUR_API_KEY"
];

if (empty($_SESSION['verified']) && empty($_COOKIE['challenge_verified'])) {
    new BrowserChallenge();
}

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

function deepDecode($input) {
    for ($i = 0; $i < 3; $i++) {
        $decoded = urldecode($input);
        $decoded = base64_decode($decoded, true) ?: $decoded;
        if ($decoded === $input) break;
        $input = $decoded;
    }
    return $input;
}

function logAttack($ip, $reason, $payload) {
    global $config;
    $log = date("Y-m-d H:i:s") . " | IP: $ip | Reason: $reason | Payload: " . substr($payload, 0, 200) . " | Agent: " . ($_SERVER['HTTP_USER_AGENT'] ?? '-') . " | URL: {$_SERVER['REQUEST_URI']}
";
    file_put_contents($config['log_file'], $log, FILE_APPEND);
}

function loadPayloads($dir) {
    $types = ["sql", "xss", "lfi", "rce"];
    $payloads = [];
    foreach ($types as $type) {
        $payloads[$type] = file_exists("$dir/{$type}.txt") ? file("$dir/{$type}.txt", FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) : [];
    }
    return $payloads;
}

function detectPayload($data, $patterns) {
    foreach ($patterns as $type => $list) {
        foreach ($list as $payload) {
            if (preg_match("/" . preg_quote($payload, '/') . "/i", $data)) {
                return $type . " match: " . $payload;
            }
        }
    }
    return false;
}

function rateLimit($client_ip) {
    global $config;
    $rate_file = $config['rate_limit_file'];
    $rate_data = file_exists($rate_file) ? json_decode(file_get_contents($rate_file), true) : ["count" => 0, "timestamp" => time()];

    if (time() - $rate_data["timestamp"] > 600) {
        $rate_data = ["count" => 0, "timestamp" => time()];
    }

    if (time() - $rate_data["timestamp"] < 60) {
        $rate_data["count"]++;
        if ($rate_data["count"] > 100) {
            blockIP($client_ip, "Rate Limit Exceeded");
        }
    } else {
        $rate_data["count"] = 1;
    }
    file_put_contents($rate_file, json_encode($rate_data));
}

function blockIP($client_ip, $reason) {
    global $config;
    $blocked_ips = file_exists($config['blocked_ips_file']) ? json_decode(file_get_contents($config['blocked_ips_file']), true) : [];
    $blocked_ips[$client_ip] = $reason;
    file_put_contents($config['blocked_ips_file'], json_encode($blocked_ips));
    logAttack($client_ip, $reason, "BLOCKED");
    http_response_code(403);
    exit("Forbidden: $reason");
}

function checkBlockedIPs($client_ip) {
    global $config;
    if (file_exists($config['blocked_ips_file'])) {
        $blocked_ips = json_decode(file_get_contents($config['blocked_ips_file']), true);
        if (isset($blocked_ips[$client_ip])) {
            blockIP($client_ip, "Previously Blocked");
        }
    }
}

function checkUploads($client_ip) {
    foreach ($_FILES as $file) {
        if (preg_match('/\.(php[0-9]?|exe|sh|bat|pl|cgi)$/i', $file['name'])) {
            logAttack($client_ip, "Malicious upload detected", $file['name']);
            http_response_code(403);
            exit("Malicious file upload blocked");
        }
    }
}

class BrowserChallenge {
    private $keyFile = '/tmp/challenge_keys.json';

    public function __construct() {
        $this->cleanExpiredKeys();
        if ($this->verifyChallenge()) {
            $_SESSION['verified'] = true;
        } elseif (!isset($_COOKIE['challenge_verified'])) {
            $this->generateChallenge();
        }
    }

    private function cleanExpiredKeys() {
        if (!file_exists($this->keyFile)) return;
        $keys = json_decode(file_get_contents($this->keyFile), true);
        $now = time();
        $keys = array_filter($keys, fn($v) => $v > $now);
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

    private function generateChallenge() {
        $parts = [bin2hex(random_bytes(8)), bin2hex(random_bytes(8)), bin2hex(random_bytes(8))];
        $key = hash('sha256', implode('', $parts));
        $this->storeKey($key);
        $_SESSION['challenge_parts'] = $parts;

        // Serve JS challenge page
        echo "<!DOCTYPE html><html><head><title>Verifying...</title></head><body>
        <script>
        async function solve() {
            let parts = ['{$parts[0]}','{$parts[1]}','{$parts[2]}'];
            let msg = parts.join('');
            let hashBuffer = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(msg));
            let hashArray = Array.from(new Uint8Array(hashBuffer));
            let key = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
            document.cookie = 'challenge_verified=' + key + '; path=/; max-age=120';
            await fetch('', {
                method: 'POST',
                headers: {'Content-Type': 'application/x-www-form-urlencoded'},
                body: 'key=' + encodeURIComponent(key)
            });
            location.reload();
        }
        solve();
        </script>
        </body></html>";
        exit;
    }

    private function storeKey($key) {
        $keys = file_exists($this->keyFile) ? json_decode(file_get_contents($this->keyFile), true) : [];
        $keys[$key] = time() + 120;
        file_put_contents($this->keyFile, json_encode($keys));
    }
}


// Start WAF check
$client_ip = getClientIP();
rateLimit($client_ip);
checkBlockedIPs($client_ip);
checkUploads($client_ip);

$data = file_get_contents('php://input') . json_encode($_GET) . json_encode($_POST) . $_SERVER['REQUEST_URI'];
$data = deepDecode($data);
$payloads = loadPayloads($config['payload_dir']);
$reason = detectPayload($data, $payloads);

if ($reason) {
    logAttack($client_ip, $reason, $data);
    http_response_code(403);
    exit("Blocked by WAF: $reason");
}
?>
