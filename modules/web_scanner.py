import requests
from bs4 import BeautifulSoup
from colorama import Fore, Style

COMMON_PATHS = [
    "/admin", "/login", "/wp-admin", "/phpmyadmin",
    "/.env", "/config.php", "/backup.zip", "/robots.txt",
    "/api/v1", "/.git/config", "/server-status"
]

class WebScanner:
    def __init__(self, target_url):
        self.target = target_url
        self.findings = []
        self.headers = {"User-Agent": "VulnScanner/1.0 Security-Research"}

    def check_headers(self, response):
        missing = []
        security_headers = [
            "X-Frame-Options", "X-XSS-Protection",
            "Content-Security-Policy", "Strict-Transport-Security",
            "X-Content-Type-Options"
        ]
        for h in security_headers:
            if h not in response.headers:
                missing.append(h)
                print(f"{Fore.YELLOW}[!] Missing header: {h}{Style.RESET_ALL}")
        return missing

    def check_paths(self):
        exposed = []
        for path in COMMON_PATHS:
            try:
                r = requests.get(self.target + path, headers=self.headers, timeout=3, allow_redirects=False)
                if r.status_code in [200, 301, 302]:
                    exposed.append({"path": path, "status": r.status_code})
                    print(f"{Fore.RED}[!] Exposed path: {path} ({r.status_code}){Style.RESET_ALL}")
            except:
                pass
        return exposed

    def scan(self):
        print(f"[*] Scanning web target: {self.target}")
        try:
            r = requests.get(self.target, headers=self.headers, timeout=5)
            missing_headers = self.check_headers(r)
            exposed_paths = self.check_paths()
            return {
                "status_code": r.status_code,
                "missing_headers": missing_headers,
                "exposed_paths": exposed_paths,
                "server": r.headers.get("Server", "unknown")
            }
        except Exception as e:
            print(f"[-] Web scan failed: {e}")
            return {}

