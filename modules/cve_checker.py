#!/usr/bin/env python3
"""CVE Checker - Match open ports with known CVEs"""

SERVICE_CVE_MAP = {
    21: [{"id": "CVE-2010-4221", "desc": "ProFTPD mod_sql SQL injection", "severity": "HIGH"}],
    22: [{"id": "CVE-2018-10933", "desc": "libssh authentication bypass", "severity": "CRITICAL"}],
    80: [{"id": "CVE-2021-41773", "desc": "Apache path traversal RCE", "severity": "CRITICAL"}],
    443: [{"id": "CVE-2014-0160", "desc": "OpenSSL Heartbleed info leak", "severity": "CRITICAL"}],
    3306: [{"id": "CVE-2012-2122", "desc": "MySQL authentication bypass", "severity": "HIGH"}],
    6379: [{"id": "CVE-2022-0543", "desc": "Redis Lua sandbox escape", "severity": "CRITICAL"}],
    27017: [{"id": "CVE-2019-2386", "desc": "MongoDB post-auth RCE", "severity": "HIGH"}],
}

class CVEChecker:
    def __init__(self, open_ports):
        self.open_ports = open_ports

    def check(self):
        findings = []
        for port_info in self.open_ports:
            port = port_info["port"]
            if port in SERVICE_CVE_MAP:
                for cve in SERVICE_CVE_MAP[port]:
                    print(f"[!] Port {port} - {cve['id']} ({cve['severity']}): {cve['desc']}")
                    findings.append({"port": port, **cve})
        return findings
