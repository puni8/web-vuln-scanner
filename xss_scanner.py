"""
Web Vulnerability Scanner - XSS Detection Module
Author: Puneeth Gowda
Purpose: Reads crawler output, injects XSS payloads into discovered inputs,
         detects unencoded payload reflection in responses, and reports findings.
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

# === XSS Payloads ===
# Each payload is a different reflection technique - if one is filtered,
# another may slip through. This mimics how real attackers bypass naive
# input sanitization (blacklist-based filters).
XSS_PAYLOADS = [
    "<script>alert(1)</script>",                # Classic - blocked by most filters
    "<img src=x onerror=alert(1)>",             # Image-based bypass
    "<svg onload=alert(1)>",                    # SVG-based bypass (very effective)
    "<body onload=alert(1)>",                   # Body tag bypass
    "\"><script>alert(1)</script>",             # Quote-breakout from attribute
    "'><script>alert(1)</script>",              # Single-quote breakout
    "<iframe src=javascript:alert(1)>",         # iframe injection
    "<input onfocus=alert(1) autofocus>",       # Event handler injection
]


# === Helper Functions (same auth flow as SQLi scanner) ===
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
def detect_xss_reflection(response_text, payload):
    """
    Check if the payload appears UNENCODED in the response.
    If yes, the server didn't sanitize input - it's vulnerable.
    """
    # The most reliable check: is the raw payload present in the HTML body?
    if payload in response_text:
        return True

    # Some apps lowercase input - check that too
    if payload.lower() in response_text.lower():
        return True

    return False


def test_input_for_xss(session, page_url, form, target_input):
    """
    Inject XSS payloads into one specific input field of a form
    and check if the payload reflects unencoded in the response.
    """
    findings = []

    for payload in XSS_PAYLOADS:
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

        # Check if payload reflected unencoded
        if detect_xss_reflection(response.text, payload):
            finding = {
                "vulnerability": "Reflected Cross-Site Scripting (XSS)",
                "url": page_url,
                "parameter": target_input["name"],
                "method": form["method"].upper(),
                "payload": payload,
                "evidence": f"Payload reflected unencoded in response body",
                "severity": "High",
                "cvss_score": 7.4,
            }
            findings.append(finding)
            print(f"        [!] VULNERABLE: payload '{payload}' reflected unencoded!")
            return findings  # Stop on first hit per input

    return findings


def scan_page(session, page_data):
    """Test all inputs of all forms on a page for XSS."""
    page_url = page_data["url"]
    print(f"\n[*] Testing {page_url}")
    page_findings = []

    for form in page_data["forms"]:
        for input_field in form["inputs"]:
            if input_field["type"] not in ["text", "search", "email", "url", "textarea"]:
                continue
            if not input_field["name"]:
                continue

            print(f"    [*] Testing input: {input_field['name']} (type: {input_field['type']})")
            findings = test_input_for_xss(session, page_url, form, input_field)
            page_findings.extend(findings)

            if not findings:
                print(f"        [-] No XSS reflection found")

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
    all_xss_findings = []
    for page_data in crawl_data:
        findings = scan_page(session, page_data)
        all_xss_findings.extend(findings)

    # Merge with existing findings (from SQLi scanner)
    try:
        with open(FINDINGS_OUTPUT_FILE, "r") as f:
            existing_findings = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        existing_findings = []

    # Combine - keep all SQLi findings + add new XSS findings
    all_findings = existing_findings + all_xss_findings

    # Save merged findings
    with open(FINDINGS_OUTPUT_FILE, "w") as f:
        json.dump(all_findings, f, indent=2)

    # Final report
    sqli_count = sum(1 for f in all_findings if "SQL Injection" in f["vulnerability"])
    xss_count = sum(1 for f in all_findings if "XSS" in f["vulnerability"])

    print(f"\n{'='*60}")
    print(f"[+] XSS Scan complete!")
    print(f"[+] Found {len(all_xss_findings)} XSS vulnerabilit{'y' if len(all_xss_findings) == 1 else 'ies'}")
    print(f"[+] Total findings: {len(all_findings)} (SQLi: {sqli_count}, XSS: {xss_count})")
    print(f"[+] Results saved to {FINDINGS_OUTPUT_FILE}")
    print(f"{'='*60}")python3 xss_scanner.py