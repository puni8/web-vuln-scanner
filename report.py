"""
Web Vulnerability Scanner - HTML Report Generator
Author: Puneeth Gowda
Purpose: Read findings.json and produce a professional HTML pentest report
         suitable for client delivery or portfolio presentation.
"""

import json
from datetime import datetime
from jinja2 import Environment, FileSystemLoader

# === Configuration ===
FINDINGS_INPUT_FILE = "findings.json"
TEMPLATE_FILE = "report.html.j2"
TEMPLATE_DIR = "templates"
OUTPUT_FILE = "report.html"

REPORT_TITLE = "DVWA Security Assessment"
TARGET = "http://localhost:8080 (DVWA)"
TESTER_NAME = "Puneeth Gowda"
GITHUB_USER = "puni8"


# === Finding Enrichment ===
# Adds impact descriptions, remediation guidance, and references based on
# vulnerability type. This separates "what was found" from "what it means".

VULN_METADATA = {
    "SQL Injection (Error-based)": {
        "impact": "An attacker can extract arbitrary data from the backend database including user credentials, personal information, and business data. In some cases, attackers can modify or delete data, or execute OS commands via database functionality. SQL Injection is consistently ranked in the OWASP Top 10 as one of the most critical web application vulnerabilities.",
        "remediation": "Use parameterized queries (prepared statements) instead of string concatenation when building SQL queries. Implement input validation with strict allow-lists where applicable. Apply the principle of least privilege to the database user account used by the application. Consider using an ORM that handles parameterization automatically.",
        "references": [
            {"title": "OWASP - SQL Injection Prevention Cheat Sheet", "url": "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html"},
            {"title": "CWE-89: Improper Neutralization of Special Elements used in an SQL Command", "url": "https://cwe.mitre.org/data/definitions/89.html"},
            {"title": "OWASP Top 10 2021 - A03 Injection", "url": "https://owasp.org/Top10/A03_2021-Injection/"},
        ],
    },
    "Reflected Cross-Site Scripting (XSS)": {
        "impact": "An attacker can craft malicious URLs that, when clicked by a victim, execute JavaScript in the victim's browser within the trusted context of the vulnerable site. This enables session hijacking via cookie theft, credential phishing via fake login overlays, keylogging, defacement, and forced actions on behalf of the victim.",
        "remediation": "Apply context-aware output encoding when reflecting user input into responses (HTML encoding for body content, JavaScript encoding for script contexts, URL encoding for URL parameters). Implement a strict Content Security Policy (CSP) to prevent inline script execution. Use security headers like X-XSS-Protection and X-Content-Type-Options. Use frameworks that auto-escape output (e.g., React, Vue, Django templates).",
        "references": [
            {"title": "OWASP - Cross Site Scripting Prevention Cheat Sheet", "url": "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html"},
            {"title": "CWE-79: Improper Neutralization of Input During Web Page Generation", "url": "https://cwe.mitre.org/data/definitions/79.html"},
            {"title": "OWASP Top 10 2021 - A03 Injection", "url": "https://owasp.org/Top10/A03_2021-Injection/"},
        ],
    },
    "Insecure Direct Object Reference (IDOR)": {
        "impact": "An attacker with a valid user account can access, modify, or delete data belonging to other users by manipulating object identifiers in requests. The impact scales with the data accessible — from minor information disclosure to full unauthorized access to all user accounts in the system. IDOR is the #1 most-reported bug class on bug bounty platforms.",
        "remediation": "Implement consistent authorization checks on every endpoint that accesses an object — never rely on the secrecy of identifiers. Use indirect object references (e.g., random UUIDs scoped per-session) where possible. Apply the principle of least privilege at the data access layer. Log and alert on access pattern anomalies (e.g., enumeration attempts).",
        "references": [
            {"title": "OWASP - Insecure Direct Object Reference Prevention", "url": "https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html"},
            {"title": "CWE-639: Authorization Bypass Through User-Controlled Key", "url": "https://cwe.mitre.org/data/definitions/639.html"},
            {"title": "OWASP Top 10 2021 - A01 Broken Access Control", "url": "https://owasp.org/Top10/A01_2021-Broken_Access_Control/"},
        ],
    },
}


def enrich_findings(findings):
    """Add impact, remediation, and references to each finding based on its type."""
    for finding in findings:
        vuln_type = finding["vulnerability"]
        metadata = VULN_METADATA.get(vuln_type, {})
        finding["impact"] = metadata.get("impact", "Impact information not available.")
        finding["remediation"] = metadata.get("remediation", "Refer to OWASP guidelines for this vulnerability class.")
        finding["references"] = metadata.get("references", [])
    return findings


def count_severities(findings):
    """Count findings per severity level."""
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for finding in findings:
        sev = finding["severity"].lower()
        if sev in counts:
            counts[sev] += 1
    return counts


def count_vulnerability_classes(findings):
    """Count distinct vulnerability classes."""
    return len(set(f["vulnerability"] for f in findings))


def render_report(findings):
    """Render findings into the HTML template."""
    env = Environment(loader=FileSystemLoader(TEMPLATE_DIR))
    template = env.get_template(TEMPLATE_FILE)

    severity_counts = count_severities(findings)
    vuln_class_count = count_vulnerability_classes(findings)

    rendered = template.render(
        report_title=REPORT_TITLE,
        target=TARGET,
        test_date=datetime.now().strftime("%B %d, %Y"),
        tester_name=TESTER_NAME,
        github_user=GITHUB_USER,
        total_findings=len(findings),
        vuln_class_count=vuln_class_count,
        severity_counts=severity_counts,
        findings=findings,
    )
    return rendered


# === Main ===
if __name__ == "__main__":
    # Load findings
    print(f"[*] Loading findings from {FINDINGS_INPUT_FILE}")
    try:
        with open(FINDINGS_INPUT_FILE, "r") as f:
            findings = json.load(f)
    except FileNotFoundError:
        print(f"[-] Could not find {FINDINGS_INPUT_FILE}. Run scanners first.")
        exit(1)

    print(f"[+] Loaded {len(findings)} findings")

    # Enrich with metadata
    print(f"[*] Enriching findings with impact/remediation/references...")
    findings = enrich_findings(findings)

    # Show severity breakdown
    counts = count_severities(findings)
    print(f"[+] Breakdown: Critical: {counts['critical']}, High: {counts['high']}, Medium: {counts['medium']}, Low: {counts['low']}")

    # Render report
    print(f"[*] Rendering report from template...")
    html = render_report(findings)

    # Save output
    with open(OUTPUT_FILE, "w") as f:
        f.write(html)

    import os
    size_kb = os.path.getsize(OUTPUT_FILE) // 1024

    print(f"\n{'='*60}")
    print(f"[+] Report saved: {OUTPUT_FILE} ({size_kb} KB)")
    print(f"[+] Open in browser: file://{os.path.abspath(OUTPUT_FILE)}")
    print(f"{'='*60}")