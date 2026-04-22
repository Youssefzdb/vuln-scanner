import json
from datetime import datetime

class ReportGenerator:
    def __init__(self, target, results):
        self.target = target
        self.results = results
        self.timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def save(self, filename="report.html"):
        html = f"""<!DOCTYPE html>
<html>
<head><title>Vulnerability Report - {self.target}</title>
<style>
  body {{ font-family: monospace; background: #0d0d0d; color: #00ff00; padding: 20px; }}
  h1 {{ color: #ff4444; }} h2 {{ color: #ffaa00; }}
  table {{ border-collapse: collapse; width: 100%; }}
  th, td {{ border: 1px solid #333; padding: 8px; text-align: left; }}
  .critical {{ color: #ff4444; }} .warning {{ color: #ffaa00; }}
</style></head>
<body>
<h1>🔍 Vulnerability Scan Report</h1>
<p>Target: <b>{self.target}</b> | Date: {self.timestamp}</p>
<h2>Open Ports</h2>
<table><tr><th>Port</th><th>Service</th><th>State</th></tr>
{"".join(f"<tr><td>{p[port]}</td><td>{p[service]}</td><td class=warning>{p[state]}</td></tr>" for p in self.results.get("ports", []))}
</table>
<h2>CVE Findings</h2>
<table><tr><th>CVE</th><th>Service</th><th>Port</th></tr>
{"".join(f"<tr><td class=critical>{c[cve]}</td><td>{c[service]}</td><td>{c[port]}</td></tr>" for c in self.results.get("cves", []))}
</table>
<pre>{json.dumps(self.results.get("web", {}), indent=2)}</pre>
</body></html>"""
        with open(filename, "w") as f:
            f.write(html)

