"""
Web Vulnerability Scanner - Crawler Module
Author: Puneeth Gowda
Purpose: Authenticate to DVWA, then crawl protected pages to extract
         all forms, inputs, and links - mapping the attack surface.
"""

import json
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin

# Configuration
TARGET_BASE = "http://localhost:8080"
LOGIN_URL = f"{TARGET_BASE}/login.php"
USERNAME = "admin"
PASSWORD = "password"
OUTPUT_FILE = "crawl_results.json"


def get_csrf_token(session, url):
    """Visit a page and extract the user_token (CSRF token) from it."""
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
        print("[-] Cannot find CSRF token on login page")
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


def extract_forms(soup):
    """Extract all forms from a BeautifulSoup-parsed page."""
    forms = []
    for form in soup.find_all("form"):
        form_data = {
            "action": form.get("action", ""),
            "method": form.get("method", "get").lower(),
            "inputs": []
        }
        # Extract all input fields, textareas, and selects
        for input_tag in form.find_all(["input", "textarea", "select"]):
            input_data = {
                "name": input_tag.get("name", ""),
                "type": input_tag.get("type", input_tag.name),  # textarea/select have no "type"
                "value": input_tag.get("value", "")
            }
            form_data["inputs"].append(input_data)
        forms.append(form_data)
    return forms


def extract_links(soup, base_url):
    """Extract all internal links from a page."""
    links = []
    for a_tag in soup.find_all("a", href=True):
        href = a_tag["href"]
        # Convert relative URLs to absolute
        absolute_url = urljoin(base_url, href)
        # Only keep links pointing to our target
        if absolute_url.startswith(TARGET_BASE):
            links.append(absolute_url)
    return list(set(links))  # deduplicate


def crawl_page(session, url):
    """Fetch a page and extract forms + links from it."""
    print(f"[*] Crawling: {url}")
    response = session.get(url)
    soup = BeautifulSoup(response.text, "html.parser")

    page_data = {
        "url": url,
        "status_code": response.status_code,
        "forms": extract_forms(soup),
        "links": extract_links(soup, url)
    }
    return page_data


if __name__ == "__main__":
    # Authenticate
    session = login_to_dvwa()
    if not session:
        print("[-] Login failed. Exiting.")
        exit(1)

    # Pages to crawl - DVWA's vulnerability pages
    target_pages = [
        f"{TARGET_BASE}/vulnerabilities/sqli/",
        f"{TARGET_BASE}/vulnerabilities/xss_r/",
        f"{TARGET_BASE}/vulnerabilities/exec/",
    ]

    all_results = []
    for url in target_pages:
        page_data = crawl_page(session, url)
        all_results.append(page_data)
        print(f"[+] Found {len(page_data['forms'])} forms, {len(page_data['links'])} links")

    # Save results to JSON
    with open(OUTPUT_FILE, "w") as f:
        json.dump(all_results, f, indent=2)

    print(f"\n[+] Crawl complete. Results saved to {OUTPUT_FILE}")
    print(f"[+] Total pages crawled: {len(all_results)}")
    print(f"[+] Total forms found: {sum(len(p['forms']) for p in all_results)}")