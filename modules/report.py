#!/usr/bin/env python3
"""HTML Report Generator"""
from datetime import datetime

class ReportGenerator:
    def __init__(self, target, results):
        self.target = target
        self.results = results

    def save(self, filename):
        ports_html = "".join(f"<tr><td>{p['port']}</td><td>{p.get('banner','')}</td></tr>" for p in self.results.get("ports", []))
        cves_html = "".join(f"<p><b>{c['id']}</b> ({c['severity']}) port {c['port']}: {c['desc']}</p>" for c in self.results.get("cves", []))
        web_html = "".join(f"<p><b>{v['type']}</b>: {v.get('url','')}</p>" for v in self.results.get("web", []))
        
        html = f"""<!DOCTYPE html>
<html>
<head><title>Vuln Report - {self.target}</title>
<style>body{{font-family:Arial;background:#1a1a2e;color:#eee;padding:20px}}h1{{color:#e94560}}.card{{background:#16213e;border-radius:8px;padding:15px;margin:10px 0}}table{{width:100%;border-collapse:collapse}}td,th{{padding:8px;border:1px solid #333}}th{{background:#0f3460}}</style>
</head>
<body>
<h1>Vulnerability Report</h1>
<p>Target: <b>{self.target}</b> | {datetime.now().strftime('%Y-%m-%d %H:%M')}</p>
<div class="card"><h2>Open Ports ({len(self.results.get('ports',[]))})</h2>
<table><tr><th>Port</th><th>Banner</th></tr>{ports_html}</table></div>
<div class="card"><h2>CVE Findings</h2>{cves_html}</div>
<div class="card"><h2>Web Vulnerabilities</h2>{web_html}</div>
</body></html>"""
        with open(filename, "w") as f:
            f.write(html)
        print(f"[+] Report saved: {filename}")
