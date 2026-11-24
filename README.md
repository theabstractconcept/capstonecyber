# Secure Web-Based File Transfer System (SWFTS)

A small, local file-sharing portal for departments. Built with **Python / Flask / SQLite**.

| Requirement | Implementation |
|---|---|
| Authenticate users | Username + password, `scrypt` hashing, account lockout (5 fails → 5 min), 15-min session timeout, password policy |
| Encrypt uploaded files | **AES-256-GCM** per file, random 96-bit nonce, authenticated (tamper detection) |
| Role-based access | `admin`, `manager`, `staff` + department scoping (matrix below) |
| HTTPS, self-signed cert | RSA-2048 / SHA-256 cert for `localhost`, served over TLS 1.3 |
| Basic OWASP checks | CSRF tokens, parameterised SQL, output escaping, upload validation, security headers, audit log, ZAP scan |

> ⚠️ **Local demo only.** Bind address is `127.0.0.1`. Use dummy files; do not upload sensitive data, and
> never point ZAP at a public website.

## 1. Setup

```bash
python -m venv venv && source venv/bin/activate      # Windows: venv\Scripts\activate
pip install -r requirements.txt
python gen_cert.py        # creates certs/cert.pem + certs/key.pem (self-signed)
python seed.py            # creates demo users
python app.py             # https://127.0.0.1:5443
```

Open **https://127.0.0.1:5443** — the browser warns about the self-signed certificate
(expected). Choose *Advanced → Proceed*.

Equivalent OpenSSL command for the certificate:
```bash
openssl req -x509 -newkey rsa:2048 -nodes -keyout certs/key.pem -out certs/cert.pem \
  -days 365 -subj "/C=IN/O=SWFTS Demo/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"
```

## 2. Demo accounts (dummy passwords)

| Username | Password | Role | Department |
|---|---|---|---|
| `admin` | `Admin@12345` | admin | Administration |
| `fin_mgr` | `Manager@12345` | manager | Finance |
| `fin_staff` | `Staff@123456` | staff | Finance |
| `hr_staff` | `Staff@123456` | staff | HR |

## 3. Role-based access matrix

| Action | admin | manager | staff |
|---|:--:|:--:|:--:|
| Upload (to own dept; admin chooses dept) | ✔ | ✔ | ✔ |
| Download files | any dept | own dept | own dept |
| Delete files | any | own dept | own uploads only |
| Manage users / view audit log | ✔ | ✘ | ✘ |

## 4. Project layout

```
app.py                 application (routes, RBAC, crypto, headers)
gen_cert.py            self-signed certificate generator
seed.py                demo users
templates/ static/     UI (no inline JS/CSS, so a strict CSP can be used)
tests/test_app.py      27 automated test cases (pytest)
capture_screenshots.py Playwright script that produced screenshots/
zap/                   ZAP automation plan + scan reports
docs/                  test cases, OWASP checklist, ZAP notes, final report
screenshots/           evidence images
```

## 5. Run the tests

```bash
python -m pytest -v          # 27 passed
```

## 6. Run the OWASP ZAP scan (local target only)

1. Start the app (`python app.py`) and make sure `seed.py` was run.
2. Install ZAP and Java 17+. Then:
   ```bash
   python zap/make_plan.py zap          # logs in as demo admin, writes zap/plan.yaml
   /path/to/ZAP/zap.sh -cmd -autorun $(pwd)/zap/plan.yaml
   ```
3. Reports are written to `zap/zap_report.html` and `zap/zap_report.json`.
   (GUI alternative: *Quick Start → Automated Scan → https://127.0.0.1:5443*.)

See `docs/ZAP_SUMMARY.md` for the findings and how they were handled.

## 7. Security design notes and known limitations

* **Key management:** the AES key lives in `data/master.key` (mode 0600) or the `PORTAL_MASTER_KEY`
  env var (64 hex chars). In production use a KMS/HSM. Losing the key makes files unrecoverable.
* **Self-signed certificate** gives encryption but not identity assurance; use a CA-issued cert in production.
* Flask's built-in server is for demos; production should use gunicorn/nginx.
* Not implemented (out of scope): MFA, password reset by email, antivirus scanning, per-IP rate limiting,
  file versioning, HTTP→HTTPS redirect listener.
* Session cookies are signed client-side; logout clears the cookie but cannot revoke a stolen cookie
  before its 15-min expiry (server-side sessions would fix this).
