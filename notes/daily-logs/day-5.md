# Day 5 — IDOR Detection Module

**Date:** May 20, 2026
**Time spent:** ~75 minutes
**Project:** Project 1 — Vulnerability Scanner

---

## 🎯 Today's Goal
Build the third (and final) attack module for Project 1 — Insecure Direct Object Reference (IDOR) detection. Unlike SQLi and XSS which inject payloads, IDOR detection works by manipulating identifier values and comparing response content. Today also became a lesson in iterating detection logic when the first version produced false negatives.

---

## ✅ What I accomplished today

- [x] Created `idor_scanner.py` (~150 lines)
- [x] Reused authentication + form handling from previous scanners (modular wins again)
- [x] Implemented `is_id_parameter()` heuristic — checks if a parameter name matches common ID patterns
- [x] First version used size-based response comparison — **produced false negatives**
- [x] Diagnosed: size deltas of 1-4 bytes were below my noise threshold
- [x] **Iterated** detection logic to use MD5 hash-based content comparison
- [x] Second version correctly detected IDOR on DVWA SQLi page (6 unique response hashes)
- [x] Updated `findings.json` to contain 3 distinct vulnerability classes
- [x] Committed and pushed to GitHub
- [x] Posted Day 5 update on LinkedIn with debugging story angle
- [x] Saved Day 5 screenshots to repo

---

## 🔧 Code I built today

### File: `idor_scanner.py` (~150 lines)

**New functions:**
- `is_id_parameter(input_field)` — heuristic: parameter name matches `id`, `user`, `account`, etc.
- `test_for_idor()` — baseline + enumeration + hash comparison

**New detection technique introduced:**
- MD5 content hashing for response comparison (instead of size delta)
- Counts unique hashes — 3+ unique responses for sequential IDs = strong IDOR signal

**Reused infrastructure:**
- Authentication (CSRF token + session)
- Form data construction
- Findings merge pattern (read existing → append → write)

---

## 🧠 Key concepts I learned today

### 1. IDOR detection works differently from SQLi/XSS
SQLi/XSS = inject *payloads* into inputs and look for evidence (errors or reflections).
IDOR = manipulate *identifier values* and compare responses across them.

The mental model shift: I'm not asking *"is this input poorly sanitized?"* — I'm asking *"can I access data I shouldn't be able to?"* That's an **authorization** question, not an **input validation** question. Different bug class entirely.

### 2. Size-based comparison is a beginner's signal
My first version flagged responses as "different" only if they differed in size by 5+ bytes. This produced false negatives because DVWA's SQLi page returns different user names (admin/Gordon/etc.) wrapped in 4500+ bytes of identical HTML — total size differences were 1-4 bytes. My threshold filtered out the real signal.

### 3. Content hashing is the professional approach
Switched to MD5 hash of the full response text. Any character-level difference produces a completely different hash. This is exactly how Burp Suite's "Compare Site Maps" and nuclei's response matching work under the hood. The lesson: **pick detection signals that don't rely on arbitrary thresholds.**

### 4. Authorization bugs > input validation bugs in bug bounty
IDOR is the #1 most-reported bug class on HackerOne (per their annual report). Why? Because companies pour effort into sanitizing inputs (preventing SQLi/XSS), but neglect to consistently enforce authorization on every endpoint. A single missed check = full data leak. This is why IDOR pays well — and why knowing how to find them automatically is a hireable skill.

### 5. Iteration is the actual development loop
Today I shipped my first wrong version, debugged it from real evidence (the byte counts), and shipped a better version. That's not failure — that's the actual scanner development process. Every professional security tool went through dozens of these iterations.

---

## 🚧 What I struggled with

- **First detection version produced 0 findings on a target I knew was vulnerable.** Spent some time confused before realizing it wasn't a code bug — it was a *threshold bug*. The code worked exactly as written; the comparison signal was just wrong.
- Initially considered using string similarity ratios (`difflib.SequenceMatcher`) instead of hashing, but that's slower and produces fuzzy results. Hashing is faster and gives a clean binary answer: different or not.
- Almost added too many ID-parameter names to my heuristic (`id`, `pk`, `key`, `ref`, `target`, etc.) — would have caused false positives on non-IDOR pages. Stuck with a tight list of 10 most common names.

---

## 🔍 Sample finding the IDOR scanner produced

```json
{
  "vulnerability": "Insecure Direct Object Reference (IDOR)",
  "url": "http://localhost:8080/vulnerabilities/sqli/",
  "parameter": "id",
  "method": "GET",
  "payload": "Enumerated id=1..6",
  "evidence": "6 unique response contents returned for sequential IDs - possible unauthorized data access across different objects",
  "severity": "High",
  "cvss_score": 7.7
}
```

And the merged `findings.json` now contains all three classes — SQLi + XSS + IDOR — produced by three different scanner modules using three different detection philosophies, all sharing the same auth/form/I/O infrastructure.

---

## ❓ Questions I want to research / ask my mentor

- **UUID-based IDOR:** modern apps use UUIDs (`?id=550e8400-e29b-41d4-a716-446655440000`) instead of sequential integers. How do I detect IDOR when I can't enumerate IDs?
- **Differential authorization testing:** how can my scanner test with TWO sessions (e.g., User A's cookies + User B's IDs) to confirm cross-user access? This is the real "horizontal privilege escalation" test.
- **GraphQL IDOR:** when targets use GraphQL instead of REST, the IDOR surface is in resolver functions, not URL parameters. How do I extend the scanner for that?

---

## 📌 Tomorrow's plan (Day 6)

Build the **HTML report generator** (`report.py`):
- Read `findings.json` (now contains 3 vuln classes)
- Use Jinja2 templating to produce a professional pentest report
- Sections: executive summary, methodology, technical findings, risk matrix, remediation
- Per-finding details: severity badge, CVSS score, PoC, evidence, references
- Style with clean CSS (or simple inline styles) — recruiter-ready
- Output: `report.html` viewable in any browser

After tomorrow: the scanner produces both raw `findings.json` (for tools) AND `report.html` (for humans). That's the complete pipeline.

---

## 🎯 Progress check

**Days completed:** 5 / 28 (18%)
**Project 1 progress:** Crawler ✅ Auth ✅ SQLi ✅ XSS ✅ IDOR ✅ — all detection modules done!
**Confidence level:** 9/10 — debugging the first IDOR version actually built confidence (I can diagnose AND fix my own code)
**Energy level for tomorrow:** 9/10 — the polish phase begins, this is where the project starts looking like a real product

---

## 💭 Reflection — the unexpected lesson

Today taught me something I didn't expect: **the first failure of a feature is more valuable than its eventual success.**

If my IDOR scanner had worked on the first try (using size comparison), I'd have shipped a fragile detector that would silently miss real bugs in production. I would never have learned that content hashing is the better signal.

The 0-findings result forced me to investigate, learn a better technique, and ship a more robust tool. That bug saved me from a worse bug.

**Lesson:** when something doesn't work the way you expected, the temptation is to feel stupid. The professional response is: *"interesting — what is this trying to teach me?"*

I'll bring this mindset into the rest of the 28 days.

---

## 📷 Screenshots saved

- `day5-idor-detected.png` — `[!] VULNERABLE: 6 unique response hashes - clear IDOR signal`
- `day5-three-vuln-classes.png` — terminal final line "TOTAL findings: 3 (SQLi: 1, XSS: 1, IDOR: 1)"
- `day5-all-findings-json.png` — full `cat findings.json` output
