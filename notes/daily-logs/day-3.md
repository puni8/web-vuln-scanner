# Day 3 — SQL Injection Detection Module

**Date:** May 17, 2026
**Time spent:** ~2 hours
**Project:** Project 1 — Vulnerability Scanner

---

## 🎯 Today's Goal
Build a SQL Injection detection module that reads `crawl_results.json`, injects SQLi payloads into every input field, watches for database error patterns in responses, and reports vulnerabilities with full evidence — turning my scanner from a mapper into a hunter.

---

## ✅ What I accomplished today

- [x] Switched VS Code from snap to .deb install for reliability on Kali
- [x] Recreated DVWA container cleanly (fixed Apache restart issues)
- [x] Created `sqli_scanner.py` (~170 lines)
- [x] Reused authentication logic from crawler (modular code)
- [x] Built payload list of 8 representative SQLi payloads
- [x] Implemented `detect_sql_errors()` with 15+ database error patterns
- [x] Wrote `test_input_for_sqli()` to fuzz one input at a time
- [x] Added per-input filtering — only test text/search/email/url/textarea fields
- [x] Output structured findings to `findings.json`
- [x] **Scanner autonomously detected the DVWA SQLi vulnerability**
- [x] Committed and pushed to GitHub
- [x] Posted Day 3 update on LinkedIn

---

## 🔧 Code I built today

### File: `sqli_scanner.py` (~170 lines)

**Functions written:**
- `detect_sql_errors(response_text)` — pattern matching across multiple DB engines
- `test_input_for_sqli(session, page_url, form, target_input)` — injects payloads per input
- `scan_page(session, page_data)` — orchestrates all forms on a single page

**Reused from crawler:**
- `get_csrf_token()` and `login_to_dvwa()` (modular architecture pays off)

**Output:** `findings.json` containing 1 confirmed SQLi finding with payload, evidence, and CVSS score.

---

## 🧠 Key concepts I learned today

### 1. Payload lists are the foundation of every scanner
Tools like sqlmap, Burp, and nuclei work on the same principle — large libraries of attack payloads tried systematically. Today I built a tiny version. Tomorrow I'll add XSS payloads. By Week 4, I could swap in a 10,000-payload list and the architecture wouldn't change.

### 2. Error-based detection is the most reliable SQLi technique
When a database receives malformed SQL, it leaks an error message that's nearly impossible to fake. By matching common error strings (`you have an error in your sql syntax`, `mysql_fetch_array`, `ora-00933`), I can catch SQLi across MySQL, PostgreSQL, Oracle, MSSQL, and SQLite — all with one detection function.

### 3. GET vs POST handling matters
HTML forms use either `method="get"` or `method="post"`. In Python's `requests` library, GET uses `params=` (URL query string) and POST uses `data=` (request body). My scanner now handles both transparently, which means it works on real bug bounty targets, not just lab apps.

### 4. The "fuzz one parameter at a time" methodology
When testing a form with multiple inputs, I keep all OTHER inputs at default values and vary only ONE at a time. This is called isolation testing — if a payload triggers an error, I know exactly which input is vulnerable. No ambiguity, no false attribution.

### 5. Module chaining is professional architecture
Crawler.py outputs JSON. Sqli_scanner.py reads that JSON as input. Tomorrow's XSS scanner will too. Same for the report generator on Day 6. This is the Unix philosophy: each tool does ONE thing well, tools chain together via files. Real pentest tools (recon-ng, sqlmap, nuclei) all use this pattern.

---

## 🚧 What I struggled with

- DVWA container had a stale Apache PID after reboot — "Connection reset by peer" errors. Solved by force-removing and recreating the container cleanly.
- VS Code snap install kept failing with AppArmor errors on Kali. Switched to Microsoft's official .deb repository — now installs and updates cleanly via `apt`.
- Took me a minute to realize my first scan returned 0 findings because I had forgotten to set DVWA security back to "Low" after recreating the container. Lesson: when results don't match expectations, check the target's state before assuming code bugs.
- Initially didn't filter inputs by type — the scanner was injecting payloads into `submit` buttons and `hidden` fields, wasting requests. Added a type filter to focus only on real injection points.

---

## 🔍 Sample finding the scanner produced

```json
{
  "vulnerability": "SQL Injection (Error-based)",
  "url": "http://localhost:8080/vulnerabilities/sqli/",
  "parameter": "id",
  "method": "GET",
  "payload": "'",
  "evidence": "you have an error in your sql syntax",
  "severity": "High",
  "cvss_score": 8.6
}
```

This is the same bug I exploited manually on Day 1 — but now the tool produces a structured, machine-readable, evidence-backed finding in 3 seconds.

---

## ❓ Questions I want to research / ask my mentor

- **Boolean-based blind SQLi:** when a site hides errors, how do I detect SQLi by comparing response sizes/content between true vs false conditions?
- **Time-based blind SQLi:** payloads like `'; SELECT SLEEP(5)--` — how do I reliably measure the delay without false positives from network jitter?
- **WAF evasion:** how would my scanner handle a target with a web application firewall that blocks obvious payloads like `'`?

---

## 📌 Tomorrow's plan (Day 4)

Build the **XSS detection module** (`xss_scanner.py`):
- Same JSON-input / JSON-output architecture as today
- Payload list of reflective XSS variants: `<script>`, `<img onerror>`, `<svg onload>`, `<body onload>`, `"><script>`
- Detection: check if payload appears unencoded in response body
- Handle URL encoding edge cases
- Goal: scanner autonomously finds the Reflected XSS I manually exploited on Day 1

---

## 🎯 Progress check

**Days completed:** 3 / 28 (11%)
**Project 1 progress:** Mapping ✅ Authentication ✅ SQLi detection ✅ — half the scanner is done
**Confidence level:** 8/10 — the pattern is clicking. XSS tomorrow will reuse 80% of today's code structure.
**Energy level for tomorrow:** 9/10 — momentum building, code working, ideas flowing

---

## 💭 Reflection — the unexpected lesson

Today I learned that **most of "hacking" is patient pattern matching.** My scanner doesn't think. It doesn't reason. It just tries 8 payloads on every input and looks for 15 error patterns in responses. That's it.

But that boring, mechanical loop catches a vulnerability that would let an attacker dump an entire database.

The hackers I admire on YouTube make it look like magic. Today I realized it's not magic — it's just *not skipping the boring step*. Most defenders never run those 8 payloads on every input. Most attackers do. That's the entire game.

---

## 📷 Screenshots saved

- `day3-sqli-vuln-found.png` — terminal output showing `[!] VULNERABLE`
- `day3-findings-json.png` — cat output of `findings.json` structure
