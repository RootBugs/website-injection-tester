# Website Injection Tester

> **Python-based whitehat web security scanner: automated SQL injection & XSS detection via parameter fuzzing and HTML form analysis.**

[![Python](https://img.shields.io/badge/Python-3.8+-3776AB?logo=python&logoColor=white)](https://python.org)
[![Requests](https://img.shields.io/badge/Requests-HTTP-FF6F00?logo=python&logoColor=white)](https://requests.readthedocs.io)
[![BeautifulSoup](https://img.shields.io/badge/BeautifulSoup-4-4B8BBE?logo=python&logoColor=white)](https://www.crummy.com/software/BeautifulSoup/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

---

## 🧠 Deep Analysis

A focused web security testing tool that performs two complementary types of injection testing:

### Detection Architecture

```
┌─────────────────────────────────────────────────────┐
│                  URL Input                           │
│   ./injection_tester.py https://target.com           │
└────────────────────────┬────────────────────────────┘
                         │
            ┌────────────┴────────────┐
            ▼                         ▼
┌───────────────────┐     ┌──────────────────────┐
│ URL Parameter     │     │ HTML Form Discovery  │
│ Fuzzing           │     │ & Testing            │
│                   │     │                      │
│ Parses query      │     │ GET / → parse forms  │
│ params (?id=1)    │     │ ← BeautifulSoup      │
│ ─────────────     │     │ ──────────────       │
│ Tests each param  │     │ Tests each input     │
│ with XSS & SQLi   │     │ field with XSS &     │
│ payloads          │     │ SQLi payloads        │
└────────┬──────────┘     └──────────┬───────────┘
         │                           │
         └──────────┬───────────────┘
                    ▼
┌─────────────────────────────────────┐
│       Response Analysis             │
│                                     │
│ • Payload reflection check          │
│ • Database error signature matching │
│   (SQL syntax, ORA-, mysql, etc.)   │
│ • Response length comparison        │
│   (Boolean-based blind SQLi)        │
│ • Script tag reflection detection   │
└─────────────────────────────────────┘
```

---

## 🚀 Quick Start

```bash
# Install dependencies
pip install requests beautifulsoup4

# Scan a URL (with query parameters)
python injection_tester.py "https://example.com/page?id=1&search=test"

# Scan a URL for form-based injection
python injection_tester.py "https://example.com/login"
```

---

## 🔬 Detection Methods

### XSS (Cross-Site Scripting) — 7 payloads

| Payload | Target |
|---------|--------|
| `<script>alert('XSS')</script>` | Classic reflected XSS |
| `'><script>alert(1)</script>` | Breaking out of attributes |
| `%3Csvg/onload=alert(1)%3E` | URL-encoded SVG vector |
| `"-alert(document.domain)-"` | Angle-bracket-free XSS |
| `'><img src=x onerror=alert(1)>` | Form-based img error XSS |
| `<body onload=alert('XSS-Body')>` | Body onload in forms |
| `<script>alert('XSS-Form')</script>` | Form field injection |

**Detection Logic:**
1. Exact payload reflection in response → ✅ `VULNERABILITY DETECTED`
2. Partial reflection (first 20 chars) → ✅ `Partial reflection`
3. `<script>` tag presence in response → ⚠️ Check for execution

### SQL Injection — 10 payloads

| Payload | Type |
|---------|------|
| `' OR 1=1--` | Classic tautology |
| `' OR '1'='1` | Tautology (no comment) |
| `' ORDER BY 1--` | Column enumeration |
| `' UNION SELECT NULL, NULL--` | Union-based extraction |
| `1; SELECT SLEEP(5)--` | Time-based blind |
| `admin'--` | Login bypass |
| `' OR 1=1#` | MySQL comment syntax |
| `' UNION SELECT 1,database(),3--` | Database fingerprinting |
| `' and 0 union select null,null,null,null,null --` | Column count brute-force |

**Detection Logic:**
1. **Error-based**: 9 database error patterns (`SQL syntax`, `ORA-`, `mysql_fetch_array`, `unclosed quotation mark`, etc.)
2. **Boolean-based blind**: Response length comparison between `' OR 1=1--` and original (difference < 200 chars = possible injection)
3. **Time-based**: Payload execution (detected via response timing)

---

## 📋 Options

The script takes a single argument — the target URL:

```bash
python injection_tester.py "https://example.com/search?q=test"
```

It automatically:
1. ✅ Parses URL query parameters (if any)
2. ✅ Fetches the page and discovers HTML forms
3. ✅ Tests all parameters/fields with XSS payloads
4. ✅ Tests all parameters/fields with SQLi payloads
5. ✅ Generates real-time console output for each test

---

## 📝 Output Indicators

| Indicator | Meaning |
|-----------|---------|
| `!!! POTENTIAL XSS VULNERABILITY DETECTED !!!` | Payload reflected in page |
| `!!! POTENTIAL SQL INJECTION VULNERABILITY DETECTED !!!` | Database error or blind SQLi detected |
| `POSSIBLE SQL INJECTION` | Response length anomaly with tautology |
| `XSS script tags were reflected` | `<script>` found but not exact payload |
| `Payload was partially reflected` | First 20 chars of payload found in response |

---

## ⚠️ Legal & Ethical

**For authorized security testing and educational use only.**

This tool sends potentially malicious payloads to target servers. Only use on:
- Systems you own
- Systems you have explicit written permission to test
- Your local development environment

Unauthorized use may violate computer fraud and abuse laws.

---

## 📄 License

MIT
