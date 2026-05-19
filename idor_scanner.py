"""
Web Vulnerability Scanner - IDOR Detection Module
Author: Puneeth Gowda
Purpose: Detect Insecure Direct Object Reference vulnerabilities by
         enumerating numeric ID parameters and comparing responses
         to detect unauthorized data access.
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

# === IDOR Detection Configuration ===
# Common parameter names that often carry object IDs
ID_PARAM_NAMES = ["id", "user", "user_id", "userid", "account",
                  "account_id", "profile", "uid", "doc", "document_id"]

# How many IDs to enumerate around the baseline (e.g., baseline=1, test 2-6)
ENUMERATION_RANGE = 5

# Minimum response-size difference to count as "different content"
# (avoids false positives from tiny dynamic content changes)
MIN_SIZE_DIFF_BYTES = 5


# === Helper Functions (same as other scanners) ===
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
def is_id_parameter(input_field):
    """
    Check if an input field looks like an object ID parameter.
    We're looking for: numeric input + name suggests an identifier.
    """
    name = input_field.get("name", "").lower()
    input_type = input_field.get("type", "").lower()

    # Skip non-data inputs
    if input_type in ["submit", "button", "hidden"]:
        return False
    if not name:
        return False

    # Check if name matches common ID parameter patterns
    for id_name in ID_PARAM_NAMES:
        if id_name in name:
            return True

    return False


def test_for_idor(session, page_url, form, id_input):
    """
    Enumerate IDs through a parameter and compare responses.
    Uses content hashing to detect different responses even when sizes are similar.
    """
    import hashlib

    findings = []
    param_name = id_input["name"]

    print(f"    [*] Testing parameter: {param_name} (numeric ID candidate)")

    # Make a baseline request with id=1
    baseline_form_data = {}
    for input_field in form["inputs"]:
        field_name = input_field["name"]
        if not field_name:
            continue
        if field_name == param_name:
            baseline_form_data[field_name] = "1"
        else:
            baseline_form_data[field_name] = input_field.get("value", "test")

    try:
        if form["method"] == "post":
            baseline_resp = session.post(page_url, data=baseline_form_data, timeout=10)
        else:
            baseline_resp = session.get(page_url, params=baseline_form_data, timeout=10)
    except requests.RequestException as e:
        print(f"        [-] Baseline request failed: {e}")
        return findings

    baseline_size = len(baseline_resp.text)
    baseline_hash = hashlib.md5(baseline_resp.text.encode()).hexdigest()
    print(f"        [*] Baseline: {param_name}=1 returns {baseline_size} bytes (hash: {baseline_hash[:8]})")

    # Track distinct response hashes (compares full content, not just size)
    distinct_hashes = set()
    distinct_hashes.add(baseline_hash)

    # Enumerate IDs 2..N and compare
    for test_id in range(2, ENUMERATION_RANGE + 2):
        test_form_data = baseline_form_data.copy()
        test_form_data[param_name] = str(test_id)

        try:
            if form["method"] == "post":
                test_resp = session.post(page_url, data=test_form_data, timeout=10)
            else:
                test_resp = session.get(page_url, params=test_form_data, timeout=10)
        except requests.RequestException as e:
            print(f"        [-] Request id={test_id} failed: {e}")
            continue

        test_hash = hashlib.md5(test_resp.text.encode()).hexdigest()
        test_size = len(test_resp.text)

        if test_hash != baseline_hash:
            print(f"        [*] Testing {param_name}={test_id} → {test_size} bytes (hash: {test_hash[:8]} - DIFFERENT)")
            distinct_hashes.add(test_hash)
        else:
            print(f"        [*] Testing {param_name}={test_id} → {test_size} bytes (same as baseline)")

    # If we got 3+ distinct content hashes, different user data is being returned
    if len(distinct_hashes) >= 3:
        finding = {
            "vulnerability": "Insecure Direct Object Reference (IDOR)",
            "url": page_url,
            "parameter": param_name,
            "method": form["method"].upper(),
            "payload": f"Enumerated {param_name}=1..{ENUMERATION_RANGE + 1}",
            "evidence": f"{len(distinct_hashes)} unique response contents returned for sequential IDs - possible unauthorized data access across different objects",
            "severity": "High",
            "cvss_score": 7.7,
        }
        findings.append(finding)
        print(f"        [!] VULNERABLE: {len(distinct_hashes)} unique response hashes - clear IDOR signal")
    else:
        print(f"        [-] Only {len(distinct_hashes)} distinct response(s) - likely not IDOR")

    return findings

def scan_page(session, page_data):
    """Test all numeric ID inputs of all forms on a page for IDOR."""
    page_url = page_data["url"]
    print(f"\n[*] Testing {page_url}")
    page_findings = []

    for form in page_data["forms"]:
        for input_field in form["inputs"]:
            if not is_id_parameter(input_field):
                continue

            findings = test_for_idor(session, page_url, form, input_field)
            page_findings.extend(findings)

    if not page_findings:
        print(f"    [-] No IDOR-suspicious parameters found on this page")

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
    all_idor_findings = []
    for page_data in crawl_data:
        findings = scan_page(session, page_data)
        all_idor_findings.extend(findings)

    # Merge with existing findings (SQLi + XSS already there)
    try:
        with open(FINDINGS_OUTPUT_FILE, "r") as f:
            existing_findings = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        existing_findings = []

    all_findings = existing_findings + all_idor_findings

    # Save merged findings
    with open(FINDINGS_OUTPUT_FILE, "w") as f:
        json.dump(all_findings, f, indent=2)

    # Final report
    sqli_count = sum(1 for f in all_findings if "SQL Injection" in f["vulnerability"])
    xss_count = sum(1 for f in all_findings if "XSS" in f["vulnerability"])
    idor_count = sum(1 for f in all_findings if "IDOR" in f["vulnerability"])

    print(f"\n{'='*60}")
    print(f"[+] IDOR Scan complete!")
    print(f"[+] Found {len(all_idor_findings)} IDOR vulnerabilit{'y' if len(all_idor_findings) == 1 else 'ies'}")
    print(f"[+] TOTAL findings: {len(all_findings)} (SQLi: {sqli_count}, XSS: {xss_count}, IDOR: {idor_count})")
    print(f"[+] Results saved to {FINDINGS_OUTPUT_FILE}")
    print(f"{'='*60}")