"""
Secure Web-Based File Transfer System (SWFTS)
---------------------------------------------
A small departmental file-sharing portal that demonstrates:
  * Authentication      - scrypt-hashed passwords, lockout, session timeout
  * Encryption at rest  - AES-256-GCM per file (random nonce, authenticated)
  * RBAC                - admin / manager / staff + department scoping
  * Transport security  - HTTPS with a self-signed certificate
  * OWASP basics        - CSRF tokens, parameterised SQL, output escaping,
                          upload validation, security headers, audit log
"""
import hashlib
import os
import re
import secrets
import sqlite3
import uuid
from datetime import datetime, timedelta, timezone
from functools import wraps
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from flask import (Flask, abort, flash, g, redirect, render_template, request,
                   send_file, session, url_for)
from io import BytesIO
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

BASE_DIR = Path(__file__).resolve().parent

ROLES = ("admin", "manager", "staff")
DEPARTMENTS = ("Finance", "HR", "IT", "Academics", "Administration")
ALLOWED_EXT = {"pdf", "txt", "csv", "png", "jpg", "jpeg", "docx", "xlsx", "pptx"}
MAX_FAILED = 5
LOCK_MINUTES = 5
USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{3,32}$")

# Role -> permissions (the RBAC matrix; also documented in the report)
PERMISSIONS = {
    "admin":   {"upload", "download_any", "delete_any", "manage_users", "view_audit"},
    "manager": {"upload", "download_dept", "delete_dept"},
    "staff":   {"upload", "download_dept", "delete_own"},
}


def now():
    return datetime.now(timezone.utc)


def iso(dt):
    return dt.strftime("%Y-%m-%d %H:%M:%S")


# ----------------------------------------------------------------- crypto
def load_or_create_key(path: Path, nbytes: int) -> bytes:
    """Read a random key from disk, creating it (mode 0600) on first run."""
    if path.exists():
        return path.read_bytes()
    key = secrets.token_bytes(nbytes)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(key)
    return key


def encrypt_bytes(key: bytes, data: bytes, aad: bytes) -> bytes:
    nonce = os.urandom(12)                       # unique per file
    return nonce + AESGCM(key).encrypt(nonce, data, aad)


def decrypt_bytes(key: bytes, blob: bytes, aad: bytes) -> bytes:
    return AESGCM(key).decrypt(blob[:12], blob[12:], aad)


# --------------------------------------------------------------- app factory
def create_app(test_config=None):
    app = Flask(__name__)
    app.config.update(
        DATA_DIR=BASE_DIR / "data",
        MAX_CONTENT_LENGTH=10 * 1024 * 1024,           # 10 MB upload cap
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SECURE=True,                    # HTTPS only
        SESSION_COOKIE_SAMESITE="Strict",
        SESSION_COOKIE_NAME="__Host-swfts",
        PERMANENT_SESSION_LIFETIME=timedelta(minutes=15),
    )
    if test_config:
        app.config.update(test_config)

    data_dir = Path(app.config["DATA_DIR"])
    (data_dir / "storage").mkdir(parents=True, exist_ok=True)
    app.config["DB_PATH"] = data_dir / "portal.db"

    app.secret_key = load_or_create_key(data_dir / "flask_secret.key", 32)
    env_key = os.environ.get("PORTAL_MASTER_KEY")
    master = bytes.fromhex(env_key) if env_key else load_or_create_key(
        data_dir / "master.key", 32)
    if len(master) != 32:
        raise RuntimeError("Master key must be 32 bytes (AES-256)")
    app.config["MASTER_KEY"] = master

    # ------------------------------------------------------------ database
    def get_db():
        if "db" not in g:
            g.db = sqlite3.connect(app.config["DB_PATH"])
            g.db.row_factory = sqlite3.Row
        return g.db

    @app.teardown_appcontext
    def close_db(_exc):
        db = g.pop("db", None)
        if db is not None:
            db.close()

    def init_db():
        db = sqlite3.connect(app.config["DB_PATH"])
        db.executescript("""
        CREATE TABLE IF NOT EXISTS users(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            pw_hash TEXT NOT NULL,
            role TEXT NOT NULL CHECK(role IN ('admin','manager','staff')),
            department TEXT NOT NULL,
            active INTEGER NOT NULL DEFAULT 1,
            failed_attempts INTEGER NOT NULL DEFAULT 0,
            locked_until TEXT,
            created_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS files(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            stored_name TEXT UNIQUE NOT NULL,
            orig_name TEXT NOT NULL,
            department TEXT NOT NULL,
            uploader_id INTEGER NOT NULL REFERENCES users(id),
            size INTEGER NOT NULL,
            sha256 TEXT NOT NULL,
            uploaded_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS audit(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT NOT NULL, username TEXT, action TEXT NOT NULL,
            detail TEXT, ip TEXT);
        """)
        db.commit()
        db.close()
    init_db()

    def audit(action, detail="", username=None):
        user = username or (g.user["username"] if g.get("user") else "-")
        get_db().execute(
            "INSERT INTO audit(ts,username,action,detail,ip) VALUES(?,?,?,?,?)",
            (iso(now()), user, action, detail[:300], request.remote_addr))
        get_db().commit()

    # --------------------------------------------------------- validation
    def password_ok(pw: str):
        if len(pw) < 10:
            return "Password must be at least 10 characters."
        if not (re.search(r"[a-z]", pw) and re.search(r"[A-Z]", pw)
                and re.search(r"\d", pw)):
            return "Password needs upper-case, lower-case and a digit."
        return None

    def create_user(username, password, role, department):
        if not USERNAME_RE.match(username):
            return "Username: 3-32 chars (letters, digits, . _ -)."
        if role not in ROLES or department not in DEPARTMENTS:
            return "Invalid role or department."
        err = password_ok(password)
        if err:
            return err
        try:
            get_db().execute(
                "INSERT INTO users(username,pw_hash,role,department,created_at)"
                " VALUES(?,?,?,?,?)",
                (username, generate_password_hash(password), role, department,
                 iso(now())))
            get_db().commit()
        except sqlite3.IntegrityError:
            return "Username already exists."
        return None
    app.create_user_internal = create_user   # used by seed script / tests

    # ------------------------------------------------- request lifecycle
    @app.before_request
    def load_user_and_check_csrf():
        g.user = None
        uid = session.get("uid")
        if uid is not None:
            row = get_db().execute(
                "SELECT * FROM users WHERE id=? AND active=1", (uid,)).fetchone()
            if row is None:
                session.clear()
            else:
                g.user = row
                session.permanent = True      # sliding 15-minute timeout
        if request.method == "POST":
            token = session.get("csrf")
            if not token or not secrets.compare_digest(
                    token, request.form.get("csrf_token", "")):
                audit("CSRF_REJECTED", request.path)
                abort(400, "Invalid or missing CSRF token")

    @app.after_request
    def security_headers(resp):
        resp.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; style-src 'self'; "
            "img-src 'self' data:; object-src 'none'; base-uri 'self'; "
            "form-action 'self'; frame-ancestors 'none'")
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Referrer-Policy"] = "no-referrer"
        resp.headers["Permissions-Policy"] = "geolocation=(), camera=(), microphone=()"
        resp.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        resp.headers["Cross-Origin-Resource-Policy"] = "same-origin"
        resp.headers["Cross-Origin-Opener-Policy"] = "same-origin"
        if not request.path.startswith("/static"):
            resp.headers["Cache-Control"] = "no-store"
        return resp

    @app.context_processor
    def inject():
        if "csrf" not in session:
            session["csrf"] = secrets.token_urlsafe(32)
        return {"csrf_token": session["csrf"], "user": g.get("user"),
                "departments": DEPARTMENTS, "roles": ROLES}

    # -------------------------------------------------------- decorators
    def login_required(fn):
        @wraps(fn)
        def wrapper(*a, **kw):
            if g.user is None:
                return redirect(url_for("login"))
            return fn(*a, **kw)
        return wrapper

    def permission_required(perm):
        def deco(fn):
            @wraps(fn)
            @login_required
            def wrapper(*a, **kw):
                if perm not in PERMISSIONS[g.user["role"]]:
                    audit("ACCESS_DENIED", f"{request.path} needs {perm}")
                    abort(403)
                return fn(*a, **kw)
            return wrapper
        return deco

    def can_download(f):
        p = PERMISSIONS[g.user["role"]]
        return "download_any" in p or (
            "download_dept" in p and f["department"] == g.user["department"])

    def can_delete(f):
        p = PERMISSIONS[g.user["role"]]
        if "delete_any" in p:
            return True
        if "delete_dept" in p and f["department"] == g.user["department"]:
            return True
        return "delete_own" in p and f["uploader_id"] == g.user["id"]

    # ------------------------------------------------------------ routes
    @app.route("/")
    def index():
        return redirect(url_for("dashboard" if g.user else "login"))

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "POST":
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "")
            row = get_db().execute(
                "SELECT * FROM users WHERE username=?", (username,)).fetchone()
            generic = "Invalid username or password."
            if row is None:
                # dummy hash check keeps response time similar
                check_password_hash(generate_password_hash("x"), password)
                audit("LOGIN_FAIL", "unknown user", username[:32] or "-")
                flash(generic, "error")
                return render_template("login.html"), 401
            if row["locked_until"] and row["locked_until"] > iso(now()):
                audit("LOGIN_BLOCKED", "account locked", username)
                flash("Account temporarily locked. Try again later.", "error")
                return render_template("login.html"), 429
            if row["active"] and check_password_hash(row["pw_hash"], password):
                get_db().execute(
                    "UPDATE users SET failed_attempts=0, locked_until=NULL WHERE id=?",
                    (row["id"],))
                get_db().commit()
                session.clear()                       # prevent session fixation
                session["uid"] = row["id"]
                session["csrf"] = secrets.token_urlsafe(32)
                g.user = row
                audit("LOGIN_OK")
                return redirect(url_for("dashboard"))
            fails = row["failed_attempts"] + 1
            locked = None
            if fails >= MAX_FAILED:
                locked = iso(now() + timedelta(minutes=LOCK_MINUTES))
                fails = 0
            get_db().execute(
                "UPDATE users SET failed_attempts=?, locked_until=? WHERE id=?",
                (fails, locked, row["id"]))
            get_db().commit()
            audit("LOGIN_FAIL", "bad password", username)
            flash(generic, "error")
            return render_template("login.html"), 401
        return render_template("login.html")

    @app.route("/logout", methods=["POST"])
    @login_required
    def logout():
        audit("LOGOUT")
        session.clear()
        return redirect(url_for("login"))

    @app.route("/dashboard")
    @login_required
    def dashboard():
        p = PERMISSIONS[g.user["role"]]
        q = ("SELECT f.*, u.username AS uploader FROM files f "
             "JOIN users u ON u.id=f.uploader_id ")
        if "download_any" in p:
            rows = get_db().execute(q + "ORDER BY f.id DESC").fetchall()
        else:
            rows = get_db().execute(
                q + "WHERE f.department=? ORDER BY f.id DESC",
                (g.user["department"],)).fetchall()
        files = [{"row": r, "can_delete": can_delete(r)} for r in rows]
        return render_template("dashboard.html", files=files)

    @app.route("/upload", methods=["POST"])
    @permission_required("upload")
    def upload():
        f = request.files.get("file")
        if not f or not f.filename:
            flash("Choose a file to upload.", "error")
            return redirect(url_for("dashboard"))
        name = secure_filename(f.filename)
        ext = name.rsplit(".", 1)[-1].lower() if "." in name else ""
        if ext not in ALLOWED_EXT:
            audit("UPLOAD_REJECTED", f"type .{ext}")
            flash("File type not allowed. Allowed: "
                  + ", ".join(sorted(ALLOWED_EXT)), "error")
            return redirect(url_for("dashboard"))
        dept = g.user["department"]
        if g.user["role"] == "admin":
            dept = request.form.get("department", dept)
            if dept not in DEPARTMENTS:
                abort(400)
        data = f.read()
        if not data:
            flash("Empty files are not accepted.", "error")
            return redirect(url_for("dashboard"))
        stored = uuid.uuid4().hex + ".enc"
        blob = encrypt_bytes(app.config["MASTER_KEY"], data, stored.encode())
        (data_dir / "storage" / stored).write_bytes(blob)
        get_db().execute(
            "INSERT INTO files(stored_name,orig_name,department,uploader_id,"
            "size,sha256,uploaded_at) VALUES(?,?,?,?,?,?,?)",
            (stored, name, dept, g.user["id"], len(data),
             hashlib.sha256(data).hexdigest(), iso(now())))
        get_db().commit()
        audit("UPLOAD", f"{name} -> {dept} ({len(data)} bytes, encrypted)")
        flash(f"'{name}' uploaded and encrypted.", "ok")
        return redirect(url_for("dashboard"))

    def get_file_or_404(fid):
        row = get_db().execute("SELECT * FROM files WHERE id=?", (fid,)).fetchone()
        if row is None:
            abort(404)
        return row

    @app.route("/download/<int:fid>")
    @login_required
    def download(fid):
        f = get_file_or_404(fid)
        if not can_download(f):
            audit("ACCESS_DENIED", f"download file {fid}")
            abort(403)
        blob = (data_dir / "storage" / f["stored_name"]).read_bytes()
        try:
            data = decrypt_bytes(app.config["MASTER_KEY"], blob,
                                 f["stored_name"].encode())
        except Exception:
            audit("INTEGRITY_FAIL", f"file {fid}")
            abort(500, "File integrity check failed")
        audit("DOWNLOAD", f["orig_name"])
        return send_file(BytesIO(data), as_attachment=True,
                         download_name=f["orig_name"],
                         mimetype="application/octet-stream")

    @app.route("/delete/<int:fid>", methods=["POST"])
    @login_required
    def delete(fid):
        f = get_file_or_404(fid)
        if not can_delete(f):
            audit("ACCESS_DENIED", f"delete file {fid}")
            abort(403)
        (data_dir / "storage" / f["stored_name"]).unlink(missing_ok=True)
        get_db().execute("DELETE FROM files WHERE id=?", (fid,))
        get_db().commit()
        audit("DELETE", f["orig_name"])
        flash("File deleted.", "ok")
        return redirect(url_for("dashboard"))

    @app.route("/admin/users", methods=["GET", "POST"])
    @permission_required("manage_users")
    def users():
        if request.method == "POST":
            err = create_user(request.form.get("username", "").strip(),
                              request.form.get("password", ""),
                              request.form.get("role", ""),
                              request.form.get("department", ""))
            if err:
                flash(err, "error")
            else:
                audit("USER_CREATED", request.form["username"])
                flash("User created.", "ok")
            return redirect(url_for("users"))
        rows = get_db().execute("SELECT * FROM users ORDER BY id").fetchall()
        return render_template("users.html", rows=rows)

    @app.route("/admin/users/<int:uid>/toggle", methods=["POST"])
    @permission_required("manage_users")
    def toggle_user(uid):
        if uid == g.user["id"]:
            flash("You cannot disable your own account.", "error")
            return redirect(url_for("users"))
        get_db().execute("UPDATE users SET active=1-active WHERE id=?", (uid,))
        get_db().commit()
        audit("USER_TOGGLED", f"user id {uid}")
        return redirect(url_for("users"))

    @app.route("/admin/audit")
    @permission_required("view_audit")
    def audit_log():
        rows = get_db().execute(
            "SELECT * FROM audit ORDER BY id DESC LIMIT 200").fetchall()
        return render_template("audit.html", rows=rows)

    @app.route("/password", methods=["GET", "POST"])
    @login_required
    def change_password():
        if request.method == "POST":
            cur = request.form.get("current", "")
            new = request.form.get("new", "")
            if not check_password_hash(g.user["pw_hash"], cur):
                flash("Current password is incorrect.", "error")
            elif (err := password_ok(new)):
                flash(err, "error")
            else:
                get_db().execute("UPDATE users SET pw_hash=? WHERE id=?",
                                 (generate_password_hash(new), g.user["id"]))
                get_db().commit()
                audit("PASSWORD_CHANGED")
                flash("Password changed.", "ok")
                return redirect(url_for("dashboard"))
        return render_template("password.html")

    # ------------------------------------------------------ error pages
    @app.errorhandler(400)
    @app.errorhandler(403)
    @app.errorhandler(404)
    @app.errorhandler(413)
    @app.errorhandler(500)
    def err(e):
        code = getattr(e, "code", 500)
        msg = {400: "Bad request", 403: "Access denied", 404: "Not found",
               413: "File too large (limit 10 MB)",
               500: "Internal error"}.get(code, "Error")
        return render_template("error.html", code=code, msg=msg), code

    return app


if __name__ == "__main__":
    from werkzeug.serving import WSGIRequestHandler
    WSGIRequestHandler.server_version = "SWFTS"   # hide Werkzeug/Python versions
    WSGIRequestHandler.sys_version = ""
    app = create_app()
    cert, key = BASE_DIR / "certs" / "cert.pem", BASE_DIR / "certs" / "key.pem"
    if not cert.exists():
        raise SystemExit("No certificate found. Run:  python gen_cert.py")
    # Bind to localhost only - this is a local demo.
    app.run(host="127.0.0.1", port=5443, ssl_context=(str(cert), str(key)),
            debug=False)
