# OWASP Top 10 (2021) – Basic Check Mapping

| OWASP risk | Control in SWFTS | Evidence |
|---|---|---|
| A01 Broken Access Control | `permission_required` decorator, department check on every download/delete, server-side only; 403 + audit entry on denial | TC11–TC17, screenshots 05, 07 |
| A02 Cryptographic Failures | TLS 1.3 (self-signed), AES-256-GCM at rest, scrypt password hashes, `Secure`/`HttpOnly`/`SameSite=Strict` cookie, HSTS | TC07–TC10, TC25 |
| A03 Injection | All SQL is parameterised (`?` placeholders); Jinja2 auto-escaping; stored filename is a random UUID, user filename sanitised | TC20, TC22, TC23 |
| A04 Insecure Design | Least-privilege role matrix, lockout, upload size/type limits, authenticated encryption (GCM tag) detects tampering | TC03, TC19–TC21, TC10 |
| A05 Security Misconfiguration | Debug off, strict CSP, nosniff, X-Frame-Options DENY, no-store cache, server version banner hidden, localhost binding | TC24, ZAP report |
| A06 Vulnerable Components | Few dependencies (Flask, cryptography); `pip list --outdated` / `pip-audit` recommended before release | requirements.txt |
| A07 Identification & Auth Failures | Password policy, lockout, generic error messages, session regeneration on login (fixation), 15-min timeout, disabled accounts blocked | TC01–TC06, TC27 |
| A08 Software & Data Integrity | GCM authentication tag with file-specific AAD; SHA-256 recorded at upload | TC10 |
| A09 Logging & Monitoring | `audit` table (login, upload, download, delete, denied, CSRF) viewable by admin | TC26, screenshot 11 |
| A10 SSRF | Application makes no outbound requests | n/a |
| CSRF (classic) | Per-session token on every POST, constant-time compare | TC18 |
