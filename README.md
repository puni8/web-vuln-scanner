#  Web Vulnerability Scanner

> A custom Python-based web vulnerability scanner that autonomously detects **SQL Injection**, **Reflected XSS**, and **IDOR** in authenticated web applications — and produces a professional pentest report as HTML.

[![Python](https://img.shields.io/badge/Python-3.11+-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Status](https://img.shields.io/badge/Status-v1.0-success.svg)]()

---

## 📋 Table of Contents

- [Features](#-features)
- [Architecture](#-architecture)
- [Demo](#-demo)
- [Installation](#-installation)
- [Usage](#-usage)
- [Sample Output](#-sample-output)
- [How It Works](#-how-it-works)
- [Tested Against](#-tested-against)
- [Tech Stack](#-tech-stack)
- [Project Structure](#-project-structure)
- [Roadmap](#-roadmap)
- [License](#-license)

---

## ✨ Features

- 🔐 **Authenticated scanning** — Handles login flows including dynamic CSRF token extraction
- 🗺️ **Automated attack surface mapping** — Crawls protected pages, extracts every form and input
- 💉 **SQL Injection detection** — Error-based detection across MySQL, PostgreSQL, Oracle, MSSQL, SQLite
- 🎯 **Cross-Site Scripting (XSS)** — Reflective payload detection with 8 bypass variants
- 🔑 **IDOR detection** — Sequential ID enumeration with MD5 content-hash comparison
- 📄 **Professional HTML pentest report** — Jinja2-templated, recruiter-ready output with CVSS scores, PoC payloads, OWASP references, and remediation guidance
- 🧱 **Modular architecture** — Each scanner is independent; add new vulnerability classes without touching existing code
- ⚡ **One-command pipeline** — `python3 main.py --url <target>` runs the entire scan and produces the report in seconds

---

## 🏗️ Architecture

┌──────────────┐    ┌────────────────┐    ┌──────────────────┐    ┌──────────────────┐
│  crawler.py  │───▶│ crawl_results  │───▶│ Detection Modules│───▶│   findings.json  │
│              │    │     .json      │    │  (SQLi/XSS/IDOR) │    │                  │
└──────────────┘    └────────────────┘    └──────────────────┘    └──────────────────┘
│
▼
┌────────────────────┐
│     report.py      │
│  (Jinja2 → HTML)   │
└────────────────────┘
│
▼
┌────────────────────┐
│    report.html     │
└────────────────────┘

Each module reads structured input and produces structured output. This makes the tool **extensible** — you can swap in a Burp proxy log as input, or add new detection modules without changing any existing code.

---

## 🎬 Demo

**Run it:**
```bash
$ python3 main.py --url http://localhost:8080
```

**Output (truncated for brevity):**

============================================================

PHASE 1: CRAWLING & MAPPING
[+] Mapped http://localhost:8080/vulnerabilities/sqli/: 1 forms, 12 links
[+] Mapped http://localhost:8080/vulnerabilities/xss_r/: 1 forms, 12 links
[+] Mapped http://localhost:8080/vulnerabilities/exec/: 1 forms, 12 links

============================================================

PHASE 2: SQL INJECTION SCAN
[] Testing http://localhost:8080/vulnerabilities/sqli/
[] Testing input: id
[!] VULNERABLE: payload "'" triggered "you have an error in your sql syntax"
... (XSS and IDOR phases) ...

============================================================

SCAN COMPLETE
Total findings:   3
By vulnerability: SQLi: 1  |  XSS: 1  |  IDOR: 1
By severity:      Critical: 0  |  High: 3  |  Medium: 0  |  Low: 0
Time elapsed:     8.3 seconds
Report file:      report.html

---

## 📦 Installation

### Requirements
- Python 3.11+
- A target web application (default config points to DVWA on `http://localhost:8080`)

### Setup

```bash
# Clone the repository
git clone git@github.com:puni8/web-vuln-scanner.git
cd web-vuln-scanner

# Install dependencies
pip install -r requirements.txt
```

### Start DVWA (for testing)

```bash
docker run -d -p 8080:80 --name dvwa vulnerables/web-dvwa
```

Wait ~60 seconds, then open `http://localhost:8080`, click "Create / Reset Database", log in with `admin` / `password`, and set security to **Low**.

---

## 🚀 Usage

```bash
# Basic scan with defaults
python3 main.py

# Specify target URL
python3 main.py --url http://localhost:8080

# Custom output filename
python3 main.py --url http://localhost:8080 --output myreport.html

# View all options
python3 main.py --help
```

### Output files produced
- `crawl_results.json` — Attack surface map (forms, inputs, links per page)
- `findings.json` — Structured vulnerability findings
- `report.html` — Polished HTML pentest report (open in any browser)

---

## 📊 Sample Output

The HTML report includes:

- **Cover page** with target, date, tester, finding count
- **Executive summary** written in plain English for non-technical stakeholders
- **Methodology section** describing how each vulnerability class is detected
- **Severity grid** — at-a-glance counts (Critical/High/Medium/Low)
- **Per-finding detail blocks** with:
  - Severity badge & CVSS 3.1 score
  - URL, parameter, HTTP method
  - Proof-of-concept payload
  - Evidence observed in response
  - Real-world impact in plain English
  - Specific remediation guidance
  - References (OWASP cheat sheets, CWE entries)

> See `notes/screenshots/` for sample report screenshots.

---

## 🔬 How It Works

### Detection Techniques by Vulnerability Class

| Vulnerability | Technique | Signal |
|---|---|---|
| **SQL Injection** | Error-based payload injection | Match response against 15+ database error patterns (`mysql_fetch_array`, `ORA-00933`, etc.) |
| **Reflected XSS** | Multi-payload reflection testing | Detect unencoded payload appearance in response body |
| **IDOR** | Sequential ID enumeration | MD5 content-hash comparison across IDs — 3+ unique hashes signal unauthorized data access |

### Why Hash-Based IDOR Detection?
Early versions of the IDOR scanner used response **size** comparison, which produced false negatives when responses differed by only a few bytes (e.g., different user names wrapped in identical HTML). Switching to MD5 content hashing catches any character-level difference — the same approach used by Burp Suite's "Compare Site Maps" feature.

### Why Modular Architecture?
Adding a new vulnerability class (e.g., Command Injection) requires only:
1. Creating `cmdi_scanner.py` with the same `scan_page()` signature
2. Adding one line in `main.py` to invoke it
3. Adding metadata in `report.py` `VULN_METADATA` dict

No changes to crawler, auth, or report rendering. **This is the Unix philosophy applied to security tooling.**

---

## ✅ Tested Against

- **DVWA (Damn Vulnerable Web Application)** at security level Low
  - ✅ SQL Injection in `id` parameter — detected with payload `'`
  - ✅ Reflected XSS in `name` parameter — detected with payload `<script>alert(1)</script>`
  - ✅ IDOR in `id` parameter — detected via 6 unique response hashes

Reproduces vulnerabilities I'd previously found manually using Burp Suite, but autonomously and in under 10 seconds.

---

## 🛠️ Tech Stack

- **Language:** Python 3.11+
- **HTTP client:** `requests` (with `Session()` for cookie persistence)
- **HTML parsing:** `beautifulsoup4`
- **URL handling:** `urllib.parse`
- **Report templating:** `jinja2`
- **CLI:** `argparse`
- **Standard library:** `json`, `hashlib`, `os`, `sys`, `time`, `datetime`

---

## 📁 Project Structure

web-vuln-scanner/
├── main.py                  # Entry point + CLI orchestrator
├── crawler.py               # Authentication + attack surface mapping
├── sqli_scanner.py          # SQL Injection detection
├── xss_scanner.py           # Cross-Site Scripting detection
├── idor_scanner.py          # Insecure Direct Object Reference detection
├── report.py                # HTML report generation
├── templates/
│   └── report.html.j2       # Jinja2 template for the report
├── requirements.txt         # Python dependencies
├── notes/
│   ├── daily-logs/          # Build journal — one entry per day
│   └── screenshots/         # Evidence + report screenshots
├── README.md                # You are here
└── LICENSE                  # MIT License

---

## 🗺️ Roadmap

Future iterations may include:
- 🕓 **Time-based blind SQLi** detection (currently only error-based)
- 🌐 **WAF bypass payloads** (URL/Unicode encoding variants)
- 🤖 **Headless browser support** (Selenium/Playwright for JS-heavy SPAs)
- 📦 **Stored XSS** detection (multi-page payload tracking)
- 🆔 **UUID-based IDOR** detection (currently only sequential integers)
- 📄 **PDF report export** (via WeasyPrint)
- 📋 **Multiple target config file** support

---

## 📚 Build Journal

This scanner was built over 7 days as Day 1–7 of a 28-day cybersecurity portfolio sprint. Each day's progress is documented in `notes/daily-logs/`:

- **Day 1:** Lab setup + manual exploitation (SQLi, XSS, Command Injection)
- **Day 2:** Authenticated crawler with CSRF token handling
- **Day 3:** SQL Injection detection module
- **Day 4:** Reflected XSS detection module
- **Day 5:** IDOR detection module (with hash-based comparison fix)
- **Day 6:** HTML pentest report generator
- **Day 7:** Orchestrator + CLI + this README — Project 1 shipped 🚢

---

## 👤 Author

**Puneeth Gowda** — Cybersecurity Graduate, Building in Public
- GitHub: [@puni8](https://github.com/puni8)
- Focus: Red Team, Web Pentesting, Bug Bounty

---

## 📜 License

This project is licensed under the MIT License — see [LICENSE](LICENSE) for details.

---

## ⚠️ Disclaimer

This tool is intended for **authorized security testing only**. Use only against systems you own or have explicit written permission to test. The author assumes no liability for misuse.