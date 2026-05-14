# Day 1 — DVWA Setup & First Manual Bugs

**Date:** [Fill in today's date]
**Time spent:** [Total hours]
**Project:** Project 1 — Vulnerability Scanner

---

## 🎯 Today's Goal
Set up the lab environment (DVWA + Juice Shop in Docker) and find 3 vulnerabilities manually using Burp Suite — to understand how bugs actually behave before automating their detection.

---

## ✅ What I accomplished today

- [ ] Installed Docker on Kali Linux
- [ ] Installed Python 3 + pip
- [ ] Got DVWA running on `http://localhost:8080`
- [ ] Got Juice Shop running on `http://localhost:3000`
- [ ] Set Burp Suite to intercept browser traffic
- [ ] Found a SQL Injection bug manually
- [ ] Found a Reflected XSS bug manually
- [ ] Found a third bug (specify type): _______________

---

## 🔍 Manual Bug #1 — SQL Injection (DVWA)

**Page:** SQL Injection (`http://localhost:8080/vulnerabilities/sqli/`)

**Payload I used:**
```
' OR '1'='1
```

**What happened:**
When I entered this command it gave me the results of all users credentials like user ID and passwords.

**Why it's dangerous:**
Assume that this vulnerability was found in any online banking sites then the attacker can login to any users account without password and can do any thing.

**Screenshots:**
- `day1-sqli-before.png` — page before attack
- `day1-sqli-payload.png` — payload typed in
- `day1-sqli-result.png` — exposed user data

---

## 🔍 Manual Bug #2 — Reflected XSS (DVWA)

**Page:** XSS (Reflected) (`http://localhost:8080/vulnerabilities/xss_r/`)

**Payload I used:**
```
<script>alert('XSS by PUNEETH')</script>
```

**What happened:**
When I entered the script a popup appered named XSS by PUNEETH.

**Why it's dangerous:**
By using XSS attack an attacker can steal cookies, hijack sessions.

**Screenshots:**
- `day1-xss-payload.png` — input field with payload
- `day1-xss-popup.png` — alert box firing

---

## 🔍 Manual Bug #3 — Command Injection (RCE)

**Page:** Command Injection (`http://localhost:8080/vulnerabilities/exec/`)

**Payloads I used:**

# Payload 1 - Identify the user running the web server
127.0.0.1; whoami

# Payload 2 - List files in current directory
127.0.0.1; ls

# Payload 3 - Read system user accounts
127.0.0.1; cat /etc/passwd

# Payload 4 - Identify OS version
127.0.0.1; uname -a

**What happened:**
The website's IP input field passes whatever I type into a system-level ping command. By adding a semicolon (`;`) after a valid IP, I was able to chain my own Linux commands and the server executed them. The page showed me the ping output PLUS the output of my injected commands — username (`www-data`), file listings, and contents of `/etc/passwd`.

**Why it's dangerous:**
This is Remote Code Execution (RCE) — the most critical web vulnerability class. With this single bug, an attacker can:
- Read any file the web server has access to (configuration files, credentials, source code)
- Enumerate the operating system and find known exploits for that version
- Potentially escalate to a full reverse shell — taking complete control of the server
- Pivot to other systems on the internal network

**CVSS 3.1 Score (estimate):** 9.8 (Critical)
- Attack Vector: Network
- Attack Complexity: Low
- Privileges Required: None
- User Interaction: None
- Impact: Full Confidentiality + Integrity + Availability

**Remediation:**
- Never pass user input directly to system commands
- Use language-native APIs instead of shell calls (e.g., Python's `socket` library instead of calling `ping`)
- Whitelist allowed input (e.g., regex for valid IP format only)
- Run the web server with minimum required privileges

**Screenshots:**
- `day1-cmdi-page-before.png` — Empty Command Injection page
- `day1-cmdi-whoami.png` — Server running `whoami` and revealing user
- `day1-cmdi-passwd.png` — Reading `/etc/passwd` showing all system users
---

## 🧠 What I learned today

- I now understand that SQL injection happens when user input is concatenated directly into a database query.
- SQL injection isn't about magic payloads it's about injecting logic. Any condition that's always true (like '2'='2' or 'a'='a') will cause the database to return all matching data. Any condition that's always false returns nothing.
- XSS happens when a website trusts user input and inserts it directly into the page's HTML. The browser then executes my JavaScript as if it came from the legitimate site. This is why filters like <script> blacklisting are insufficient — alternative tags like <img> and <svg> can also execute JavaScript.
- Command Injection is the most dangerous of the three — a single semicolon turned a ping function into a way to read system files. This taught me to look for OS command chaining characters (;, &&, |) wherever a web app interacts with the operating system.
- Documentation matters as much as exploitation. Pentesting is half hacking, half communication.

---

## 🚧 What I struggled with

- I struggled with the VirtualBox keyboard capture issue — Win + Shift + S didn't work in full screen mode. Solved it by releasing focus with Right Ctrl before using Windows shortcuts.
- Docker permissions confused me at first — kept needing sudo until I logged out and back in.
---

## ❓ Questions I want to research / ask my mentor

- What's the difference between Reflected XSS and Stored XSS — and which one is more dangerous in practice?
- Could I have gotten a reverse shell from the command injection bug? How does that work?

---

## 📌 Tomorrow's plan (Day 2)

Start building the Python crawler — the first part of the automated scanner that will visit every page on a target website and extract all forms, inputs, and links into a structured JSON file. Setting up requests + BeautifulSoup and writing the first 100 lines of code.

---