# Day 6 — HTML Pentest Report Generator

**Date:** May 21, 2026
**Time spent:** ~90 minutes
**Project:** Project 1 — Vulnerability Scanner

---

## 🎯 Today's Goal
Transform `findings.json` (machine-readable output) into a professional HTML pentest report (human-readable deliverable) — the file a security consultant would hand to a client and the document a recruiter will actually open from my GitHub.

---

## ✅ What I accomplished today

- [x] Installed Jinja2 templating library (`pip3 install jinja2`)
- [x] Created `templates/` folder for HTML templates (separation of concerns)
- [x] Built `templates/report.html.j2` (~250 lines of HTML + CSS)
- [x] Designed: cover page, executive summary, severity grid, methodology, per-finding details, conclusion, footer
- [x] Created `report.py` (~150 lines)
- [x] Built `enrich_findings()` to add impact, remediation, and references per vulnerability type
- [x] Implemented severity counting and vulnerability class counting
- [x] Used Jinja2's `Environment` + `FileSystemLoader` for template rendering
- [x] **Generated a clean, professional `report.html` from my 3 findings**
- [x] Verified the report renders correctly in Firefox
- [x] Captured full-page screenshot for LinkedIn + portfolio
- [x] Committed and pushed to GitHub
- [x] Posted Day 6 update on LinkedIn

---

## 🔧 Code I built today

### File: `templates/report.html.j2` (~250 lines)
HTML template with embedded CSS. Uses Jinja2 placeholders:
- `{{ variable }}` for single values
- `{% for finding in findings %}...{% endfor %}` for the findings loop
- `{{ finding.severity | lower }}` for filter usage (lowercase for CSS class names)

Color-coded severity (red for Critical/High, orange Medium, green Low), monospace code blocks for payloads, print-friendly media query for PDF export.

### File: `report.py` (~150 lines)
**Functions written:**
- `enrich_findings(findings)` — adds impact/remediation/references based on vuln type lookup
- `count_severities(findings)` — counts findings per severity for the summary grid
- `count_vulnerability_classes(findings)` — counts distinct vuln types
- `render_report(findings)` — Jinja2 rendering with all context variables

**`VULN_METADATA` dictionary** — stores per-vulnerability impact descriptions, remediation guidance, and OWASP/CWE references. This is a "knowledge layer" — separate from scanning logic.

**Output:** `report.html` (~30 KB) — a complete pentest report viewable in any browser.

---

## 🧠 Key concepts I learned today

### 1. Separation of design from logic
Today I learned why professional codebases use templating engines instead of f-strings or string concatenation. With Jinja2:
- The Python code only handles data (reading JSON, computing counts)
- The HTML template only handles presentation (layout, styling, structure)
- I can redesign the report without touching Python; I can swap data sources without touching HTML

This is the **Model-View** part of MVC architecture. Worth doing even on small projects.

### 2. The knowledge layer is part of the tool
Detection logic answers *"is this vulnerable?"*. The knowledge layer (`VULN_METADATA`) answers *"what does that mean, and how do you fix it?"*. Both are essential. Most beginner scanners only do the first part. Real tools do both. Today I built both.

### 3. Reports are written for THREE audiences simultaneously
A pentest report has to serve:
- The **developer** who needs to fix the bug (needs PoC + remediation)
- The **manager** who decides priorities (needs CVSS + impact in plain language)
- The **auditor** who verifies compliance (needs OWASP + CWE references)

A good report doesn't pick one — it gives each audience what they need in clearly-labeled sections. That's why every professional report has both "Executive Summary" AND "Technical Findings."

### 4. CVSS scoring isn't arbitrary
I assigned CVSS scores in earlier modules (8.6 for SQLi, 7.4 for XSS, 7.7 for IDOR). These aren't random — they follow CVSS 3.1 base metrics: Attack Vector + Complexity + Privileges Required + User Interaction + Impact on CIA. For a network-accessible, low-complexity, no-auth-needed bug like SQLi, the score lands in the 7-9 range. This standardization lets organizations prioritize remediation across all their tools' findings.

### 5. The deliverable IS half the project
After 5 days I had working detection code. Today I added 400 lines (template + Python). The result feels like a different product — even though no new bugs are detected. **What you build matters. How you present it matters just as much.** Same lesson scales to resumes, GitHub READMEs, LinkedIn posts. Presentation is engineering.

---

## 🚧 What I struggled with

- Initially put `report.py` inside the `templates/` folder by mistake. Jinja2 then couldn't find its own template files because the lookup path was wrong. Lesson: keep code at project root; assets in subfolders.
- First template render produced raw `{{ finding.url }}` text in the output instead of values. Turned out I had typo'd `{{ findings.url }}` (plural) — should be `finding.url` (singular, since we're inside the loop). Jinja2 silently fails on undefined variables by default.
- CSS for the severity badges initially had all four colors set, but I forgot to handle the `lower()` filter — was generating class names like `Severity-High` instead of `severity-high`, which my CSS didn't match. Added `| lower` in the template.
- Almost made the report too "designer-y" with gradients and shadows. Pulled back to clean, minimal styling. Pentest reports should look like security documents, not marketing brochures.

---

## 🔍 What the rendered report contains

```
report.html (~30 KB)
├── Cover page (target, date, tester, finding count)
├── Executive summary (3 paragraphs, plain English)
├── Findings summary (4-card severity grid)
├── Methodology (3-phase approach explained)
├── Technical findings:
│   ├── Finding 1: SQL Injection (Error-based)
│   │   ├── CVSS 8.6, High severity badge
│   │   ├── PoC payload in code block
│   │   ├── Evidence, Impact, Remediation
│   │   └── References (OWASP cheat sheet, CWE-89)
│   ├── Finding 2: Reflected Cross-Site Scripting
│   │   └── ... (same structure)
│   └── Finding 3: Insecure Direct Object Reference
│       └── ... (same structure)
├── Conclusion
└── Footer with GitHub link
```

This IS the file recruiters will actually open from my repo. Code shows I can build. The report shows I can communicate.

---

## ❓ Questions I want to research / ask my mentor

- **PDF export:** my report has print CSS but I haven't tested PDF generation. Would `weasyprint` or browser print-to-PDF produce a better-looking PDF? Worth doing for Day 7?
- **Charts:** would a severity distribution chart (bar or pie) add value, or is the 4-card grid enough? Some real pentest reports include charts, some don't.
- **Versioned reports:** if I scan the same target on different dates, how would I diff two reports to show "what got fixed since last test"? That's a feature real tools have.

---

## 📌 Tomorrow's plan (Day 7) — Project 1 SHIPS

Final day of Project 1:
- Build `main.py` — orchestrator that runs the entire pipeline with one command (crawl → scan SQLi → scan XSS → scan IDOR → generate report)
- Write a **strong README.md** for the GitHub repo with: project overview, installation, usage, sample output screenshot, architecture diagram, technologies used
- Add `argparse` for CLI usage: `python3 main.py --url http://target.com --report output.html`
- Polish: docstrings, error messages, edge case handling
- Final commit + LinkedIn post: "Project 1 v1.0 SHIPPED"
- Then Saturday → Week 2 begins (recon pipeline)

---

## 🎯 Progress check

**Days completed:** 6 / 28 (21%)
**Project 1 progress:** All detection ✅ + Report generator ✅ — only orchestrator + README left
**Confidence level:** 9/10 — the report changed my whole feeling about this project. It's real now.
**Energy level for tomorrow:** 10/10 — shipping a complete product tomorrow

---

## 💭 Reflection — the unexpected lesson

Today taught me that **the same data can feel completely different depending on how it's presented.**

Yesterday's `findings.json`:
```json
[{"vulnerability": "SQL Injection (Error-based)", ...}]
```

Today's `report.html` shows that same finding with:
- A red severity badge that catches the eye
- The payload in a dark code block that says "I'm important"
- An impact paragraph that explains the business risk
- Clickable references that say "I did my homework"

**Same finding. Same evidence. Totally different perceived professionalism.**

This is a life lesson, not just a code lesson. My code, my journal entries, my LinkedIn posts, my future resume — all of these are "raw findings" until I present them well. Building the substance is necessary. Presenting it well is what gets it noticed.

Investing in presentation isn't vanity. It's amplification of work I already did.

---

## 📷 Screenshots saved

- `day6-report-cover.png` — Cover page of the rendered report
- `day6-report-severity-grid.png` — 4-card severity summary
- `day6-report-finding-detail.png` — One full finding with all sections
- `day6-report-fullpage.png` — Complete report as a tall image (Firefox full-page screenshot)
