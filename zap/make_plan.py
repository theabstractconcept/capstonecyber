"""Log in as the demo admin, grab the session cookie and write a ZAP automation plan.
Scans ONLY the local server https://127.0.0.1:5443."""
import http.cookiejar, re, ssl, sys, urllib.parse, urllib.request
from pathlib import Path

BASE = "https://127.0.0.1:5443"
ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
jar = http.cookiejar.CookieJar()
op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar),
                                 urllib.request.HTTPSHandler(context=ctx))
html = op.open(BASE + "/login").read().decode()
tok = re.search(r'name="csrf_token" value="([^"]+)"', html).group(1)
data = urllib.parse.urlencode({"username": "admin", "password": "Admin@12345",
                               "csrf_token": tok}).encode()
op.open(BASE + "/login", data)
cookie = next(c for c in jar if c.name == "__Host-swfts")
out = Path(sys.argv[1]); out.mkdir(exist_ok=True, parents=True)
plan = f"""env:
  contexts:
    - name: swfts
      urls: ["{BASE}"]
      includePaths: ["{BASE}.*"]
      excludePaths: [".*/logout", ".*/delete/.*"]
  parameters:
    failOnError: false
    progressToStdout: true
jobs:
  - type: replacer
    parameters: {{deleteAllRules: true}}
    rules:
      - description: authenticated admin session
        matchType: req_header
        matchString: Cookie
        matchRegex: false
        replacementString: "{cookie.name}={cookie.value}"
  - type: spider
    parameters: {{context: swfts, url: "{BASE}/dashboard", maxDuration: 2}}
  - type: passiveScan-wait
    parameters: {{maxDuration: 2}}
  - type: activeScan
    parameters: {{context: swfts, maxScanDurationInMins: 6, maxRuleDurationInMins: 1}}
  - type: report
    parameters:
      template: traditional-html
      reportDir: {out}
      reportFile: zap_report.html
      reportTitle: SWFTS - OWASP ZAP scan (local)
  - type: report
    parameters:
      template: traditional-json
      reportDir: {out}
      reportFile: zap_report.json
"""
(out / "plan.yaml").write_text(plan); print("plan written")
