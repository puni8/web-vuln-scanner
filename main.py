"""
Web Vulnerability Scanner - Main Entry Point
Author: Puneeth Gowda
Repository: https://github.com/puni8/web-vuln-scanner

Orchestrates the full vulnerability scanning pipeline:
    1. Authenticated crawler maps the attack surface
    2. SQLi scanner injects payloads, detects database errors
    3. XSS scanner injects payloads, detects unencoded reflection
    4. IDOR scanner enumerates IDs, compares response hashes
    5. Report generator produces a professional HTML pentest report

Usage:
    python3 main.py --url http://localhost:8080
    python3 main.py --url http://target.com --output myreport.html
"""

import argparse
import json
import os
import sys
import time

# Import the scanner modules
from crawler import login_to_dvwa, crawl_page
from sqli_scanner import scan_page as scan_sqli
from xss_scanner import scan_page as scan_xss
from idor_scanner import scan_page as scan_idor
from report import enrich_findings, render_report, count_severities


# === ASCII Banner ===
BANNER = r"""
 _    _      _   __     __    _         _____                                 
| |  | |    | |  \ \   / /   | |       / ____|                                
| |  | | ___| |__ \ \ / /   _| |_ __  | (___   ___ __ _ _ __  _ __   ___ _ __ 
| |/\| |/ _ \ '_ \ \ V / | | | | '_ \  \___ \ / __/ _` | '_ \| '_ \ / _ \ '__|
\  /\  /  __/ |_) | \ | |_| | | | | | |____) | (_| (_| | | | | | | |  __/ |   
 \/  \/ \___|_.__/   \_/\__,_|_|_| |_| |_____/ \___\__,_|_| |_|_| |_|\___|_|   

         Web Vulnerability Scanner v1.0  |  by Puneeth Gowda
         Detects: SQL Injection  |  XSS  |  IDOR
"""


def print_section(title):
    """Print a clearly-marked section header."""
    print(f"\n{'='*60}")
    print(f"  {title}")
    print(f"{'='*60}")


def crawl_target(session, base_url, paths):
    """Phase 1: Crawl the target and produce attack surface map."""
    print_section("PHASE 1: CRAWLING & MAPPING")
    crawl_data = []
    for path in paths:
        full_url = f"{base_url}{path}"
        page_data = crawl_page(session, full_url)
        crawl_data.append(page_data)
        print(f"[+] Mapped {full_url}: {len(page_data['forms'])} forms, {len(page_data['links'])} links")
    return crawl_data


def run_all_scanners(session, crawl_data):
    """Phases 2-4: Run all detection modules and collect findings."""
    all_findings = []

    print_section("PHASE 2: SQL INJECTION SCAN")
    for page_data in crawl_data:
        findings = scan_sqli(session, page_data)
        all_findings.extend(findings)
    print(f"\n[+] SQLi scan complete: {sum(1 for f in all_findings if 'SQL Injection' in f['vulnerability'])} findings")

    print_section("PHASE 3: REFLECTED XSS SCAN")
    xss_start = len(all_findings)
    for page_data in crawl_data:
        findings = scan_xss(session, page_data)
        all_findings.extend(findings)
    print(f"\n[+] XSS scan complete: {len(all_findings) - xss_start} findings")

    print_section("PHASE 4: IDOR SCAN")
    idor_start = len(all_findings)
    for page_data in crawl_data:
        findings = scan_idor(session, page_data)
        all_findings.extend(findings)
    print(f"\n[+] IDOR scan complete: {len(all_findings) - idor_start} findings")

    return all_findings


def generate_report(findings, output_file):
    """Phase 5: Produce the HTML pentest report."""
    print_section("PHASE 5: REPORT GENERATION")
    findings = enrich_findings(findings)
    html = render_report(findings)
    with open(output_file, "w") as f:
        f.write(html)
    size_kb = os.path.getsize(output_file) // 1024
    print(f"[+] HTML report saved: {output_file} ({size_kb} KB)")


def print_summary(findings, output_file, elapsed):
    """Print final scan summary."""
    counts = count_severities(findings)
    sqli_count = sum(1 for f in findings if "SQL Injection" in f["vulnerability"])
    xss_count = sum(1 for f in findings if "XSS" in f["vulnerability"])
    idor_count = sum(1 for f in findings if "IDOR" in f["vulnerability"])

    print_section("SCAN COMPLETE")
    print(f"  Total findings:   {len(findings)}")
    print(f"  By vulnerability: SQLi: {sqli_count}  |  XSS: {xss_count}  |  IDOR: {idor_count}")
    print(f"  By severity:      Critical: {counts['critical']}  |  High: {counts['high']}  |  Medium: {counts['medium']}  |  Low: {counts['low']}")
    print(f"  Time elapsed:     {elapsed:.1f} seconds")
    print(f"  Report file:      {output_file}")
    print(f"  Findings JSON:    findings.json")
    print(f"\n  Open report:      file://{os.path.abspath(output_file)}")
    print(f"{'='*60}\n")


def main():
    # === Parse CLI arguments ===
    parser = argparse.ArgumentParser(
        description="Web Vulnerability Scanner - Detects SQLi, XSS, and IDOR",
        epilog="Example: python3 main.py --url http://localhost:8080 --output report.html"
    )
    parser.add_argument("--url", default="http://localhost:8080",
                        help="Target base URL (default: http://localhost:8080)")
    parser.add_argument("--output", default="report.html",
                        help="Output HTML report filename (default: report.html)")
    parser.add_argument("--findings-json", default="findings.json",
                        help="Output JSON findings filename (default: findings.json)")
    parser.add_argument("--no-banner", action="store_true",
                        help="Suppress the ASCII banner")
    args = parser.parse_args()

    # === Banner ===
    if not args.no_banner:
        print(BANNER)

    print(f"[*] Target: {args.url}")
    print(f"[*] Output: {args.output}")

    start_time = time.time()

    # === Authenticate ===
    print_section("AUTHENTICATION")
    print("[*] Authenticating to target...")
    session = login_to_dvwa()
    if not session:
        print("[-] Authentication failed. Verify target is reachable and credentials are correct.")
        sys.exit(1)

    # === Define paths to scan ===
    # In a future version, this could come from a config file or crawler-discovered links
    paths_to_scan = [
        "/vulnerabilities/sqli/",
        "/vulnerabilities/xss_r/",
        "/vulnerabilities/exec/",
    ]

    # === Run the pipeline ===
    crawl_data = crawl_target(session, args.url, paths_to_scan)

    # Save crawl results (for inspection / reuse)
    with open("crawl_results.json", "w") as f:
        json.dump(crawl_data, f, indent=2)
    print(f"\n[+] Crawl map saved to crawl_results.json")

    findings = run_all_scanners(session, crawl_data)

    # Save findings JSON
    with open(args.findings_json, "w") as f:
        json.dump(findings, f, indent=2)
    print(f"\n[+] Findings saved to {args.findings_json}")

    # Generate report
    generate_report(findings, args.output)

    elapsed = time.time() - start_time
    print_summary(findings, args.output, elapsed)


if __name__ == "__main__":
    main()