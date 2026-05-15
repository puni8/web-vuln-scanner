# Day 2 — Building the Authenticated Crawler

**Date:** May 15, 2026
**Time spent:** ~2 hours
**Project:** Project 1 — Vulnerability Scanner

---

## 🎯 Today's Goal
Build a Python crawler that authenticates to DVWA and extracts the attack surface (all forms, inputs, and links) from protected vulnerability pages — saving the output as structured JSON for the upcoming attack modules to consume.

---

## ✅ What I accomplished today

- [x] Installed VS Code on Kali Linux (via snap, fixed PATH for /snap/bin)
- [x] Set up Git + SSH on Kali with a separate SSH key from Windows
- [x] Cloned the `web-vuln-scanner` repo on Kali
- [x] Installed Python dependencies (`requests`, `beautifulsoup4`) with `--break-system-packages`
- [x] Wrote a function to fetch any URL and return HTML
- [x] Implemented dynamic CSRF token extraction from DVWA login page
- [x] Implemented session-based authentication (POST with credentials + token)
- [x] Verified authenticated access to protected pages (SQLi, XSS, Command Injection)
- [x] Wrote `extract_forms()` function — parses every form, input, textarea, select
- [x] Wrote `extract_links()` function — finds internal links + handles relative URLs
- [x] Saved structured output to `crawl_results.json`
- [x] Pushed Day 2 commit to GitHub
- [x] Fixed the corrupted `~/.zsh_history` warning on Kali

---

## 🔧 Code I built today

### File: `crawler.py` (~100 lines)

**Functions written:**
- `get_csrf_token(session, url)` — extracts `user_token` from any DVWA page
- `login_to_dvwa()` — full authentication flow (GET token → POST credentials)
- `extract_forms(soup)` — parses HTML, returns list of forms with their inputs
- `extract_links(soup, base_url)` — extracts internal links, converts relative to absolute
- `crawl_page(session, url)` — orchestrates extraction for a single page

**Output:** `crawl_results.json` — structured map of attack surface across 3 DVWA pages (SQLi, Reflected XSS, Command Injection).

---

## 🧠 Key concepts I learned today

### 1. HTTP Sessions
A session is how a website remembers I'm logged in across multiple requests. Python's `requests.Session()` object automatically stores and sends cookies, so once I log in, every subsequent request "remembers" me. Without sessions, my scanner would have to re-authenticate before every single page request — totally inefficient.

### 2. CSRF tokens
A CSRF token is a unique random string that DVWA generates every time the login page is loaded. When I submit a form, I must include the token that came with that specific page — otherwise the server rejects the request as a forgery attempt. This is why I had to scrape the token from the GET response FIRST, then submit the login POST with that exact token. It taught me that real-world authentication scripting is more nuanced than just sending username + password.

### 3. BeautifulSoup parsing
BeautifulSoup turns raw HTML into a tree I can search. `soup.find_all("form")` returns every form on the page in one call. `soup.find("input", {"name": "user_token"})` finds a specific input by its attribute. Way cleaner than trying to do this with regex — regex on HTML is famously fragile.

### 4. urllib.parse.urljoin
Web pages have both absolute (`http://...`) and relative (`/page.php`) links. `urljoin(base, href)` correctly combines them into a full URL — even handles weird edge cases like `../` paths and query strings without me writing any custom logic.

### 5. Modular architecture
Today I built the "mapping" phase as its own module. Tomorrow's scanner will read my JSON output as input. This separation matters — each module does ONE thing well. It's how real pentesting tools (like Burp Suite or sqlmap) are structured under the hood.

### 6. Two SSH keys, one GitHub account
I learned you can add multiple SSH keys to one GitHub account — one per machine. My Windows key handles journal commits; my Kali key handles code commits. Both push to the same repo. This is how professional devs work with multiple machines.

---

## 🚧 What I struggled with

- Initially confused why the login flow needed two requests (GET then POST). Realized that the CSRF token must be fetched fresh per session — you can't reuse a stale token.
- VS Code install via snap added it to `/snap/bin` which wasn't in my PATH. Had to manually append it to `~/.zshrc` and reload shell. Lesson: not every install "just works" — sometimes you have to tell the system where things live.
- Got a `zsh: corrupt history file` warning every time I opened a terminal on Kali. Took me a second to realize it wasn't a security issue, just a damaged log file from improper VM shutdown. Fixed by deleting and recreating the file.
- The first time I ran the crawler, I forgot to add `--break-system-packages` to pip and got a confusing "externally-managed-environment" error. Kali's newer Python protections require this flag for global installs.

---

## 🔍 Sample output from `crawl_results.json`

```json
{
  "url": "http://localhost:8080/vulnerabilities/sqli/",
  "status_code": 200,
  "forms": [
    {
      "action": "#",
      "method": "get",
      "inputs": [
        {"name": "id", "type": "text", "value": ""},
        {"name": "Submit", "type": "submit", "value": "Submit"}
      ]
    }
  ],
  "links": ["http://localhost:8080/vulnerabilities/sqli/?id=Submit", "..."]
}
```

Each form's `inputs` list is a goldmine — every entry is a potential injection point that tomorrow's scanner will attack automatically.

---

## ❓ Questions I want to research / ask my mentor

- How does my scanner handle JavaScript-rendered pages (SPAs like React)? `requests` doesn't execute JS — would I need Selenium or Playwright for that?
- How do I make the crawler "smart" enough to skip logout links so it doesn't kill its own session mid-crawl?
- What's the difference between detecting Reflected XSS on the immediate response vs. detecting blind XSS that fires later in an admin panel?

---

## 📌 Tomorrow's plan (Day 3)

Build the **SQL Injection detection module**:
- Read `crawl_results.json` as input
- For every text input found, inject a list of SQLi payloads (`'`, `' OR 1=1--`, `'+OR+'1'='1`, etc.)
- Watch for telltale database error strings in the response (`SQL syntax`, `mysql_fetch`, `ORA-`, `Warning: pg_`)
- Report each vulnerable input with: URL, parameter name, payload, evidence
- Goal: scanner autonomously finds the SQLi I exploited manually on Day 1

---

## 🎯 Progress check

**Days completed:** 2 / 28 (7%)
**Project 1 progress:** Foundation complete — crawler working, authentication scripted, attack surface mapped. Ready to bolt on attack modules tomorrow.
**Confidence level:** 7/10 — Python flowed easier than I expected, especially with BeautifulSoup
**Energy level for tomorrow:** 8/10 — excited to write the first attack module

---

## 💭 Reflection — the unexpected lesson

The biggest realization today: **pentesting is just thoughtful programming.** I always thought "writing a scanner" would feel different from "writing a normal app" — but it's not. It's just choosing the right libraries, structuring code well, and thinking carefully about what a website is doing under the hood.

The hacking mindset is in the *what* I'm coding (looking for weakness, anticipating server behavior), not the *how* I'm coding it. Code is code.
