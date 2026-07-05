# Website Injection Tester

> **Python-based whitehat web security scanner: automated SQL injection & XSS detection via parameter fuzzing and HTML form analysis.**

[![Python](https://img.shields.io/badge/Python-3.8+-3776AB?logo=python&logoColor=white)](https://python.org)
[![Requests](https://img.shields.io/badge/Requests-HTTP-FF6F00?logo=python&logoColor=white)](https://requests.readthedocs.io)
[![BeautifulSoup](https://img.shields.io/badge/BeautifulSoup-4-4B8BBE?logo=python&logoColor=white)](https://www.crummy.com/software/BeautifulSoup/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

---

## How It Works

Two-pass injection testing on any URL:

1. **URL Parameter Fuzzing** — Parses `?key=value` params, sends XSS + SQLi payloads to each via GET, analyzes response for reflection and error patterns.
2. **HTML Form Discovery** — Fetches page, finds `<form>` elements via BeautifulSoup, identifies injectable input fields (`text`, `email`, `password`, `textarea`, `select`), sends payloads via POST/GET.

```
URL Input → parse query params → test each with XSS/SQLi payloads
         → fetch page → discover forms → test each field with payloads
         → analyze responses (reflection, error signatures, length comparison)
```

---

## Quick Start

```bash
pip install requests beautifulsoup4

# Scan URL with query parameters
python injection_tester.py "https://example.com/page?id=1&search=test"

# Scan a page for form-based injection
python injection_tester.py "https://example.com/login"
```

---

## Detection Methods

### XSS — 7 payloads

| Payload | Type |
|---------|------|
| `<script>alert('XSS')</script>` | Classic reflected XSS |
| `'><script>alert(1)</script>` | Attribute breakout |
| `%3Csvg/onload=alert(1)%3E` | URL-encoded SVG |
| `"-alert(document.domain)-"` | Angle-bracket-free |
| `'><img src=x onerror=alert(1)>` | Form img error XSS |
| `<body onload=alert('XSS-Body')>` | Body onload |
| `<script>alert('XSS-Form')</script>` | Form field injection |

**Detection:** Exact reflection → Vuln. Partial (first 20 chars) → Possible. `<script>` tag present → Check execution.

### SQLi — 10 payloads

| Payload | Type |
|---------|------|
| `' OR 1=1--` | Classic tautology |
| `' OR '1'='1` | Tautology (no comment) |
| `' ORDER BY 1--` | Column enumeration |
| `' UNION SELECT NULL, NULL--` | Union-based |
| `1; SELECT SLEEP(5)--` | Time-based blind |
| `admin'--` | Login bypass |
| `' OR 1=1#` | MySQL comment |
| `' UNION SELECT 1,database(),3--` | DB fingerprinting |
| `' and 0 union select null,null,null,null,null --` | Column count brute-force |

**Detection:**
1. **Error-based** — 9 DB error patterns (`SQL syntax`, `ORA-`, `mysql_fetch_array`, `unclosed quotation mark`, etc.)
2. **Boolean-based blind** — Response length comparison with tautology (diff < 200 chars = possible injection)
3. **Time-based** — Response timing analysis

---

## Output Indicators

| Indicator | Meaning |
|-----------|---------|
| `!!! POTENTIAL XSS VULNERABILITY DETECTED !!!` | Payload reflected in page |
| `!!! POTENTIAL SQL INJECTION VULNERABILITY DETECTED !!!` | DB error or blind SQLi |
| `POSSIBLE SQL INJECTION` | Response length anomaly |
| `XSS script tags were reflected` | `<script>` found but not exact payload |
| `Payload was partially reflected` | First 20 chars found in response |

---

## Bug Fixes

- **Fixed duplicate parameter injection**: `send_request` previously appended payloads to URLs that already had query strings, creating duplicate params (server used the original value, not the payload). Now strips query string from URL before sending payload as a fresh parameter.

---

## Legal & Ethical

**For authorized security testing and educational use only.** Only use on systems you own or have explicit written permission to test. Unauthorized use may violate computer fraud and abuse laws.

---

## License

MIT
