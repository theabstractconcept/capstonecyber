"""Automated test cases (pytest). Run:  python -m pytest -v"""
import io
import re
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app import create_app  # noqa: E402

PW = {"admin": "Admin@12345", "mgr": "Manager@12345", "staff": "Staff@123456"}


@pytest.fixture()
def app(tmp_path):
    app = create_app({"DATA_DIR": tmp_path, "TESTING": True})
    with app.app_context(), app.test_request_context():
        app.create_user_internal("admin", PW["admin"], "admin", "Administration")
        app.create_user_internal("fin_mgr", PW["mgr"], "manager", "Finance")
        app.create_user_internal("fin_staff", PW["staff"], "staff", "Finance")
        app.create_user_internal("fin_staff2", PW["staff"], "staff", "Finance")
        app.create_user_internal("hr_staff", PW["staff"], "staff", "HR")
    return app


def new_client(app):
    # base_url https so the Secure cookie is sent, as a real browser would
    return app.test_client(), "https://localhost"


def csrf(client, base, path="/login"):
    html = client.get(path, base_url=base).get_data(as_text=True)
    return re.search(r'name="csrf_token" value="([^"]+)"', html).group(1)


def login(client, base, user, pw):
    return client.post("/login", base_url=base, data={
        "username": user, "password": pw, "csrf_token": csrf(client, base)})


def upload(client, base, name="report.txt", content=b"secret payroll data"):
    tok = csrf(client, base, "/dashboard")
    return client.post("/upload", base_url=base, data={
        "csrf_token": tok, "file": (io.BytesIO(content), name)},
        content_type="multipart/form-data")


def as_user(app, user, pw):
    c, b = new_client(app)
    r = login(c, b, user, pw)
    assert r.status_code == 302, "login should succeed"
    return c, b


# ---------------------------------------------------------- authentication
def test_TC01_valid_login(app):
    c, b = new_client(app)
    r = login(c, b, "fin_staff", PW["staff"])
    assert r.status_code == 302 and r.headers["Location"].endswith("/dashboard")


def test_TC02_wrong_password_generic_message(app):
    c, b = new_client(app)
    r = login(c, b, "fin_staff", "wrong")
    assert r.status_code == 401
    r2 = login(c, b, "nobody", "wrong")
    # same message for unknown user and bad password (no user enumeration)
    assert b"Invalid username or password" in r.data
    assert b"Invalid username or password" in r2.data


def test_TC03_lockout_after_5_failures(app):
    c, b = new_client(app)
    for _ in range(5):
        login(c, b, "fin_staff", "bad")
    r = login(c, b, "fin_staff", PW["staff"])      # correct pw but locked
    assert r.status_code == 429


def test_TC04_protected_pages_require_login(app):
    c, b = new_client(app)
    for p in ("/dashboard", "/admin/users", "/admin/audit", "/download/1", "/password"):
        r = c.get(p, base_url=b)
        assert r.status_code == 302 and "/login" in r.headers["Location"]


def test_TC05_logout_ends_session(app):
    c, b = as_user(app, "fin_staff", PW["staff"])
    c.post("/logout", base_url=b, data={"csrf_token": csrf(c, b, "/dashboard")})
    assert c.get("/dashboard", base_url=b).status_code == 302


def test_TC06_password_policy_enforced(app):
    c, b = as_user(app, "admin", PW["admin"])
    r = c.post("/admin/users", base_url=b, follow_redirects=True, data={
        "csrf_token": csrf(c, b, "/admin/users"), "username": "weak1",
        "password": "short", "role": "staff", "department": "IT"})
    assert b"at least 10 characters" in r.data


def test_TC07_passwords_stored_hashed(app):
    import sqlite3
    row = sqlite3.connect(app.config["DB_PATH"]).execute(
        "SELECT pw_hash FROM users WHERE username='admin'").fetchone()
    assert PW["admin"] not in row[0] and row[0].startswith(("scrypt:", "pbkdf2:"))


# ------------------------------------------------------------- encryption
def test_TC08_file_encrypted_at_rest(app):
    c, b = as_user(app, "fin_staff", PW["staff"])
    upload(c, b, content=b"TOP-SECRET-PAYROLL-12345")
    blobs = list((Path(app.config["DATA_DIR"]) / "storage").glob("*.enc"))
    assert len(blobs) == 1
    assert b"TOP-SECRET-PAYROLL" not in blobs[0].read_bytes()


def test_TC09_download_decrypts_correctly(app):
    c, b = as_user(app, "fin_staff", PW["staff"])
    upload(c, b, content=b"hello-world-data")
    r = c.get("/download/1", base_url=b)
    assert r.status_code == 200 and r.data == b"hello-world-data"
    assert "attachment" in r.headers["Content-Disposition"]


def test_TC10_tampered_ciphertext_detected(app):
    c, b = as_user(app, "fin_staff", PW["staff"])
    upload(c, b, content=b"integrity test")
    f = next((Path(app.config["DATA_DIR"]) / "storage").glob("*.enc"))
    raw = bytearray(f.read_bytes())
    raw[-1] ^= 0x01
    f.write_bytes(bytes(raw))
    assert c.get("/download/1", base_url=b).status_code == 500


# ------------------------------------------------------------------- RBAC
def test_TC11_staff_cannot_open_admin_pages(app):
    c, b = as_user(app, "fin_staff", PW["staff"])
    assert c.get("/admin/users", base_url=b).status_code == 403
    assert c.get("/admin/audit", base_url=b).status_code == 403


def test_TC12_cross_department_download_denied(app):
    c, b = as_user(app, "fin_staff", PW["staff"])
    upload(c, b)
    h, hb = as_user(app, "hr_staff", PW["staff"])
    assert h.get("/download/1", base_url=hb).status_code == 403


def test_TC13_same_department_download_allowed(app):
    c, b = as_user(app, "fin_staff", PW["staff"])
    upload(c, b)
    m, mb = as_user(app, "fin_mgr", PW["mgr"])
    assert m.get("/download/1", base_url=mb).status_code == 200


def test_TC14_admin_can_download_any(app):
    c, b = as_user(app, "fin_staff", PW["staff"])
    upload(c, b)
    a, ab = as_user(app, "admin", PW["admin"])
    assert a.get("/download/1", base_url=ab).status_code == 200


def test_TC15_staff_can_delete_only_own_files(app):
    c1, b1 = as_user(app, "fin_staff", PW["staff"])
    upload(c1, b1)
    c2, b2 = as_user(app, "fin_staff2", PW["staff"])
    r = c2.post("/delete/1", base_url=b2,
                data={"csrf_token": csrf(c2, b2, "/dashboard")})
    assert r.status_code == 403
    r = c1.post("/delete/1", base_url=b1,
                data={"csrf_token": csrf(c1, b1, "/dashboard")})
    assert r.status_code == 302


def test_TC16_manager_can_delete_department_files(app):
    c, b = as_user(app, "fin_staff", PW["staff"])
    upload(c, b)
    m, mb = as_user(app, "fin_mgr", PW["mgr"])
    r = m.post("/delete/1", base_url=mb,
               data={"csrf_token": csrf(m, mb, "/dashboard")})
    assert r.status_code == 302


def test_TC17_dashboard_hides_other_department_files(app):
    c, b = as_user(app, "fin_staff", PW["staff"])
    upload(c, b, name="finance_only.txt")
    h, hb = as_user(app, "hr_staff", PW["staff"])
    assert b"finance_only.txt" not in h.get("/dashboard", base_url=hb).data


# --------------------------------------------------------- OWASP controls
def test_TC18_csrf_token_required(app):
    c, b = as_user(app, "fin_staff", PW["staff"])
    r = c.post("/upload", base_url=b, data={"file": (io.BytesIO(b"x"), "a.txt")},
               content_type="multipart/form-data")
    assert r.status_code == 400


def test_TC19_dangerous_extension_rejected(app):
    c, b = as_user(app, "fin_staff", PW["staff"])
    for bad in ("shell.php", "run.exe", "page.html", "x.sh", "noext"):
        upload(c, b, name=bad)
    assert list((Path(app.config["DATA_DIR"]) / "storage").glob("*.enc")) == []


def test_TC20_path_traversal_filename_sanitised(app):
    c, b = as_user(app, "fin_staff", PW["staff"])
    upload(c, b, name="../../etc/passwd.txt")
    stored = list((Path(app.config["DATA_DIR"]) / "storage").glob("*.enc"))
    assert len(stored) == 1 and stored[0].parent.name == "storage"
    assert b"../" not in c.get("/dashboard", base_url=b).data


def test_TC21_oversize_upload_rejected(app):
    c, b = as_user(app, "fin_staff", PW["staff"])
    r = upload(c, b, content=b"A" * (11 * 1024 * 1024))
    assert r.status_code == 413


def test_TC22_sql_injection_login_fails(app):
    c, b = new_client(app)
    r = login(c, b, "admin' OR '1'='1' --", "anything")
    assert r.status_code == 401


def test_TC23_xss_filename_is_escaped(app):
    c, b = as_user(app, "fin_staff", PW["staff"])
    upload(c, b, name="<script>alert(1)</script>.txt")
    html = c.get("/dashboard", base_url=b).get_data(as_text=True)
    assert "<script>alert(1)" not in html


def test_TC24_security_headers_present(app):
    c, b = new_client(app)
    h = c.get("/login", base_url=b).headers
    for name in ("Content-Security-Policy", "X-Content-Type-Options",
                 "X-Frame-Options", "Strict-Transport-Security",
                 "Referrer-Policy", "Cache-Control"):
        assert name in h, name
    assert "frame-ancestors 'none'" in h["Content-Security-Policy"]


def test_TC25_session_cookie_flags(app):
    c, b = new_client(app)
    login(c, b, "fin_staff", PW["staff"])
    cookie = [v for k, v in c.get("/dashboard", base_url=b).headers
              if k == "Set-Cookie"]
    r = login(c, b, "fin_staff", PW["staff"])
    sc = " ".join(v for k, v in r.headers if k == "Set-Cookie")
    assert "Secure" in sc and "HttpOnly" in sc and "SameSite=Strict" in sc


def test_TC26_audit_log_records_events(app):
    c, b = as_user(app, "fin_staff", PW["staff"])
    upload(c, b)
    c.get("/download/1", base_url=b)
    a, ab = as_user(app, "admin", PW["admin"])
    page = a.get("/admin/audit", base_url=ab).get_data(as_text=True)
    for ev in ("LOGIN_OK", "UPLOAD", "DOWNLOAD"):
        assert ev in page


def test_TC27_disabled_user_cannot_login(app):
    a, ab = as_user(app, "admin", PW["admin"])
    a.post("/admin/users/3/toggle", base_url=ab,
           data={"csrf_token": csrf(a, ab, "/admin/users")})
    c, b = new_client(app)
    assert login(c, b, "fin_staff", PW["staff"]).status_code == 401
