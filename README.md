
# 🛡️ ShadowWAF

A stealth PHP-based Web Application Firewall (WAF) for high-risk environments. Blocks bots, filters attacks, verifies browsers silently, and supports payload pattern detection with modular integration. Designed for both standalone PHP projects and reverse-proxy setups with NGINX.

---

## 🚀 Installation

### 1. Clone the Repository

```bash
git clone https://github.com/NARKHEDE-VAIBHAV/ShadowWAF
cd ShadowWAF
````

---

## 🧱 Directory Structure

```
ShadowWAF/
├── waf.php                  # Main WAF logic
├── payloads/                # Attack pattern signatures
│   ├── sql.txt
│   ├── xss.txt
│   ├── lfi.txt
│   ├── rce.txt
│   └── payload.txt
├── nginx/                   # NGINX reverse proxy configs
│   ├── default.conf
│   ├── blacklist.conf
│   └── waf_location.conf
└── README.md
```

---

## ⚙️ NGINX Reverse Proxy Setup (Optional)

To use WAF as a reverse proxy:

1. Add to your NGINX `default.conf`:

```nginx
include /path/to/ShadowWAF/nginx/default.conf;
```

2. Point requests to `waf.php` in that config block.

---

## 🧪 WAF Integration in PHP

Place the following line **at the top of your PHP app's `index.php`**:

```php
include 'waf.php';
```

Make sure the `payloads/` folder is present in the same directory.

---

## 🧠 Features

* ✅ JavaScript Browser Challenge (automatic; no UI)
* 📌 Regex-based Payload Detection (`payloads/*.txt`)
* 🌐 GeoIP Tagging (optional API key)
* 🚦 Rate Limiting per IP
* 🔄 Deep Payload Decoding (Base64, URL, Hex - up to 3 layers)
* 📂 Upload Scanner (blocks `.php`, `.exe`, etc.)
* 🧱 Modular Payload Categories: `SQLi`, `XSS`, `LFI`, `RCE`
* 📑 Centralized Logging (`/tmp/waf_attack_log.txt`)
* ⛔ IP Blocking (stored in `/tmp/blocked_ips.json`)

---

## ✍️ Custom Payloads

You can edit or extend detection rules in:

* `payloads/sql.txt` – SQLi patterns
* `payloads/xss.txt` – Cross-site scripting payloads
* `payloads/lfi.txt` – Local file inclusion
* `payloads/rce.txt` – Remote command/code execution
* `payloads/payload.txt` – General or legacy patterns

Each line is treated as a regex-safe substring match.

---

## 🔐 Browser Challenge Mode

If a request doesn't have the challenge cookie or session:

* A JavaScript SHA-256 challenge is served
* Solved automatically by real browsers
* On success, user gets `challenge_verified` cookie

This blocks bots/cURL/scripts without CAPTCHA or prompts.

---

## 📈 Logging & Blocking

* Logs are saved to `/tmp/waf_attack_log.txt`
* Blocked IPs saved to `/tmp/blocked_ips.json`
* Malicious uploads or repeated requests trigger permanent block

---

## 🧪 Testing the WAF

You can test the firewall using common payloads like:

```
http://yourdomain.com/?q=<script>alert(1)</script>
http://yourdomain.com/?id=1' OR '1'='1
http://yourdomain.com/?file=../../../../etc/passwd
```

If detected, you'll receive a `403 Forbidden` response.

---

## 📜 License

MIT — Free to use, modify, and redistribute.

---

## 🙋 Support

Pull requests and issue reports welcome. Contact [@NARKHEDE-VAIBHAV](https://github.com/NARKHEDE-VAIBHAV) for custom extensions or consulting.




