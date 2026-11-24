# OWASP ZAP Scan Summary

* **Tool:** OWASP ZAP 2.17.0, headless Automation Framework (`zap/plan.yaml`)
* **Target:** `https://127.0.0.1:5443` only (local demo, no public sites)
* **Mode:** authenticated as demo `admin` (session cookie injected), spider + passive scan + active scan
* **Active scan limit:** 6 minutes (≈4,900 requests logged by the server). A longer run is recommended before any real deployment.
* **Full reports:** `zap/zap_report.html`, `zap/zap_report.json`

## Result: 0 High, 0 Medium, 0 Low, 5 Informational

| Alert | Risk | Count | Assessment |
|---|---|---|---|
| Authentication Request Identified | Info | 1 | Expected – ZAP recognised `/login`. |
| Session Management Response Identified | Info | 17 | Expected – `__Host-swfts` cookie is Secure, HttpOnly, SameSite=Strict. |
| User Agent Fuzzer | Info | 3 | Responses identical across user agents; no UA-dependent behaviour. |
| Re-examine Cache-control Directives | Info | 5 | Reviewed. Pages already send `Cache-Control: no-store` deliberately, because they contain private data. No change needed. |
| User Controllable HTML Element Attribute (Potential XSS) | Info | 1 | Hidden `csrf_token` field on `/password`. Output is auto-escaped by Jinja2 and no script execution was confirmed (see TC23). False positive. |

## Fixes made during development that this scan reflects
* Duplicate `Server` header leaking `Werkzeug/3.x Python/3.x` was removed (version-disclosure finding avoided).
* Strict CSP (`default-src 'self'`, `frame-ancestors 'none'`) made possible by keeping all JS/CSS external.
* Missing-anti-clickjacking, nosniff, HSTS, referrer and permissions headers added.

## Known limitations of the scan
Self-signed certificates are expected to be untrusted; ZAP does not rate that as an alert on localhost.
Automated scanning does not replace manual testing for business-logic flaws – see TC11–TC17.
