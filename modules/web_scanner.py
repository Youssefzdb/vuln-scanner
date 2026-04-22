#!/usr/bin/env python3
"""Web Vulnerability Scanner - XSS, SQLi, Header checks"""
import requests
from bs4 import BeautifulSoup

class WebScanner:
    def __init__(self, target_url):
        self.target = target_url
        self.session = requests.Session()
        self.session.headers["User-Agent"] = "Mozilla/5.0 (Security Scanner)"
        self.vulnerabilities = []

    def _test_sqli(self, url, param):
        payloads = ["'", "1 OR 1=1", "\" OR \"1\"=\"1"]
        for payload in payloads:
            try:
                r = self.session.get(url, params={param: payload}, timeout=5)
                errors = ["sql syntax", "mysql_fetch", "ORA-", "sqlite", "syntax error"]
                for err in errors:
                    if err.lower() in r.text.lower():
                        self.vulnerabilities.append({"type": "SQLi", "url": url, "param": param, "payload": payload})
                        print(f"[!] SQLi found: {url}?{param}={payload}")
                        return
            except:
                pass

    def _test_xss(self, url, param):
        payload = '<script>alert("XSS")</script>'
        try:
            r = self.session.get(url, params={param: payload}, timeout=5)
            if payload in r.text:
                self.vulnerabilities.append({"type": "XSS", "url": url, "param": param})
                print(f"[!] XSS found: {url}?{param}")
        except:
            pass

    def _check_headers(self):
        try:
            r = self.session.get(self.target, timeout=5)
            security_headers = ["X-Frame-Options", "X-XSS-Protection", "Content-Security-Policy", "Strict-Transport-Security"]
            for h in security_headers:
                if h not in r.headers:
                    self.vulnerabilities.append({"type": "Missing Header", "header": h})
                    print(f"[!] Missing security header: {h}")
        except:
            pass

    def scan(self):
        print(f"[*] Web scanning: {self.target}")
        self._check_headers()
        try:
            r = self.session.get(self.target, timeout=10)
            soup = BeautifulSoup(r.text, "html.parser")
            for form in soup.find_all("form"):
                for inp in form.find_all("input"):
                    name = inp.get("name", "")
                    if name:
                        self._test_sqli(self.target, name)
                        self._test_xss(self.target, name)
        except Exception as e:
            print(f"[-] Error: {e}")
        return self.vulnerabilities
