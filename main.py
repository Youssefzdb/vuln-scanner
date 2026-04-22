#!/usr/bin/env python3
"""
vuln-scanner - Automated Vulnerability Discovery & Assessment Framework
Author: Security Research Tool
"""
import argparse
import sys
from modules.port_scanner import PortScanner
from modules.web_scanner import WebScanner
from modules.cve_checker import CVEChecker
from modules.report import ReportGenerator

def main():
    parser = argparse.ArgumentParser(description="vuln-scanner - Vulnerability Assessment Framework")
    parser.add_argument("target", help="Target IP or domain")
    parser.add_argument("--mode", choices=["quick", "full", "web"], default="quick")
    parser.add_argument("--output", default="report.html", help="Output report file")
    parser.add_argument("--ports", default="1-1024", help="Port range to scan")
    args = parser.parse_args()

    print(f"[*] Starting vulnerability scan on: {args.target}")
    print(f"[*] Mode: {args.mode}")

    results = {}

    # Port scanning
    scanner = PortScanner(args.target, args.ports)
    results["ports"] = scanner.scan()

    # Web scanning if mode is web or full
    if args.mode in ["web", "full"]:
        web = WebScanner(f"http://{args.target}")
        results["web"] = web.scan()

    # CVE checking
    cve = CVEChecker(results["ports"])
    results["cves"] = cve.check()

    # Generate report
    report = ReportGenerator(args.target, results)
    report.save(args.output)
    print(f"[+] Report saved to: {args.output}")

if __name__ == "__main__":
    main()

