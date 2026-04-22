import requests
from colorama import Fore, Style

SERVICE_CVE_MAP = {
    "ftp": ["CVE-2021-3129", "CVE-2020-7247"],
    "ssh": ["CVE-2023-38408", "CVE-2021-41617"],
    "http": ["CVE-2021-41773", "CVE-2022-22965"],
    "https": ["CVE-2022-22965", "CVE-2021-44228"],
    "smtp": ["CVE-2020-7247", "CVE-2019-10149"],
    "mysql": ["CVE-2021-2307", "CVE-2020-14765"],
}

class CVEChecker:
    def __init__(self, open_ports):
        self.open_ports = open_ports

    def check(self):
        findings = []
        print("[*] Checking known CVEs for detected services...")
        for port_info in self.open_ports:
            service = port_info.get("service", "").lower()
            if service in SERVICE_CVE_MAP:
                for cve in SERVICE_CVE_MAP[service]:
                    findings.append({"service": service, "port": port_info["port"], "cve": cve})
                    print(f"{Fore.RED}[!] Potential {cve} on {service}:{port_info[\"port\"]}{Style.RESET_ALL}")
        return findings

