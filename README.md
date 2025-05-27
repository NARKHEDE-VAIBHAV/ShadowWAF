Secure PHP Proxy Firewall

this project is under devlopment





This project is a security-enhanced PHP reverse proxy that filters incoming HTTP requests, blocks suspicious activity, and forwards safe traffic to a backend server.
🔐 Features

    IP Geolocation & Rate Limiting

        Detects client IP & country.

        Rate-limits requests per IP (100/min).

        Blocks repeated or large suspicious requests.

    SQL Injection Protection

        Scans requests for common SQLi keywords & patterns.

        Blocks IPs with unbalanced parentheses or excessive comment markers.

    Payload Matching

        Blocks IPs matching malicious payloads listed in payload2.txt.

    Challenge-Response Validation

        JavaScript challenge system to prevent bot attacks.

        Stores hashed challenge keys in challenge_keys.json.

    User-Agent & Header Filtering

        Blocks bots or empty/malicious user agents.

        Filters/rewrites headers for secure proxying.

⚙️ Setup

    Requirements

        PHP 7.4+

        cURL enabled

        Write permissions to /tmp/ and local files

    Configure

        Replace YOUR_API_KEY in the getGeoIP() function with your ipgeolocation.io API key.

        Define the $target backend URL (e.g., http://localhost:4040/).

    Payload File

        Add malicious keywords/payloads line by line in payload2.txt.

    Run

        Host the script via Apache/Nginx with PHP or use PHP’s built-in server:

        php -S localhost:8080

📁 Files

    index.php – Main PHP proxy logic

    payload2.txt – Payloads to match and block

    challenge_keys.json – Stores temporary challenge keys

    /tmp/blocked_ips – Dynamically blocks malicious IPs

📌 Note

    This is a basic WAF-like reverse proxy for educational/demo purposes.
    Not production-hardened — for real security, combine with a proper WAF & server firewall.