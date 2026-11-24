# Test Cases

Automated in `tests/test_app.py` (`python -m pytest -v` → **27 passed**). Manual verification screenshots are in `screenshots/`.

| ID | Category | Test | Expected result | Result |
|---|---|---|---|---|
| TC01 | Auth | Login with valid credentials | Redirect to dashboard | Pass |
| TC02 | Auth | Wrong password / unknown user | 401, identical generic message | Pass |
| TC03 | Auth | 5 failed logins, then correct password | 429 account locked | Pass |
| TC04 | Auth | Access protected URLs without login | Redirect to /login | Pass |
| TC05 | Auth | Logout | Session ended | Pass |
| TC06 | Auth | Create user with weak password | Rejected with policy message | Pass |
| TC07 | Auth | Inspect stored password | scrypt hash, not plaintext | Pass |
| TC08 | Encryption | Upload, read stored `.enc` file | Plaintext not present | Pass |
| TC09 | Encryption | Download uploaded file | Original bytes restored | Pass |
| TC10 | Encryption | Flip one byte in ciphertext | Download fails (integrity error) | Pass |
| TC11 | RBAC | Staff opens /admin/users, /admin/audit | 403 | Pass |
| TC12 | RBAC | HR user downloads Finance file | 403 | Pass |
| TC13 | RBAC | Finance manager downloads Finance file | 200 | Pass |
| TC14 | RBAC | Admin downloads any file | 200 | Pass |
| TC15 | RBAC | Staff deletes colleague's file / own file | 403 / success | Pass |
| TC16 | RBAC | Manager deletes department file | Success | Pass |
| TC17 | RBAC | HR dashboard lists Finance files | Not listed | Pass |
| TC18 | OWASP | POST without CSRF token | 400 | Pass |
| TC19 | OWASP | Upload .php/.exe/.html/.sh/no extension | Rejected, nothing stored | Pass |
| TC20 | OWASP | Filename `../../etc/passwd.txt` | Sanitised; stored under UUID in storage/ | Pass |
| TC21 | OWASP | 11 MB upload | 413 | Pass |
| TC22 | OWASP | SQL injection in username | Login fails | Pass |
| TC23 | OWASP | `<script>` in filename | Output escaped | Pass |
| TC24 | OWASP | Response headers | CSP, XFO, nosniff, HSTS, Referrer-Policy, no-store | Pass |
| TC25 | OWASP | Session cookie | Secure, HttpOnly, SameSite=Strict | Pass |
| TC26 | Logging | Admin views audit log | LOGIN_OK, UPLOAD, DOWNLOAD present | Pass |
| TC27 | Auth | Disabled user logs in | Rejected | Pass |

## Manual / environment checks

| ID | Test | Evidence |
|---|---|---|
| M01 | TLS 1.3 with `TLS_AES_256_GCM_SHA384`, self-signed cert (CN=localhost, SAN localhost/127.0.0.1) | `openssl s_client` output; screenshot 01 |
| M02 | Plain HTTP request to the HTTPS port is refused | `curl http://127.0.0.1:5443` → connection failure |
| M03 | Stored file is ciphertext (hexdump shows random bytes; `grep` for plaintext finds 0 matches) | terminal capture, see final report |
| M04 | Server banner does not reveal Werkzeug/Python versions | `Server: SWFTS` |
