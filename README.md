# Website Injection Tester

> **Python-based web application security scanner for automated injection vulnerability detection.**

---

## Overview

A penetration testing tool that automates the detection of common injection vulnerabilities in web applications. Supports multiple injection types with intelligent payload delivery and response analysis.

---

## Features

- 🗃️ **SQL Injection** — Detects SQLi vulnerabilities with automated payload testing
- 📝 **XSS Testing** — Cross-site scripting vulnerability detection (reflected & stored)
- ⚙️ **Configurable Payloads** — Custom payload lists and test parameters
- 📊 **Response Analysis** — Intelligent response parsing to detect vulnerabilities
- 🚦 **Rate Limiting** — Configurable delays to avoid detection
- 📋 **Reporting** — Detailed vulnerability reports with evidence

---

## Quick Start

```bash
git clone https://github.com/RootBugs/website-injection-tester.git
cd website-injection-tester

pip install requests beautifulsoup4

# Run against a target
python injection_tester.py -u https://example.com

# With specific injection type
python injection_tester.py -u https://example.com -t sqli

# Custom payload file
python injection_tester.py -u https://example.com -p payloads.txt
```

---

## Options

| Flag | Description | Default |
|------|-------------|---------|
| `-u, --url` | Target URL | Required |
| `-t, --type` | Injection type (sqli, xss, all) | `all` |
| `-p, --payloads` | Custom payload file | Built-in |
| `-d, --delay` | Delay between requests (sec) | `1` |
| `-o, --output` | Report output file | `report.txt` |
| `-v, --verbose` | Verbose output | `false` |

---

## Supported Injection Types

- **SQL Injection (SQLi)** — Classic, blind, time-based, error-based
- **Cross-Site Scripting (XSS)** — Reflected, stored, DOM-based
- **Command Injection** — OS command injection detection
- **LDAP Injection** — LDAP query injection
- **XXE** — XML External Entity injection

---

## Detection Methods

- 🔎 **Pattern Matching** — Signature-based vulnerability detection
- 🧠 **Heuristic Analysis** — Behavioral analysis of responses
- ⏱️ **Timing Attacks** — Time-based blind detection
- 🔄 **Error-Based** — Database error message analysis

---

## ⚠️ Legal Notice

Only use this tool on systems you own or have explicit permission to test. Unauthorized testing may be illegal.

---

## License

MIT
