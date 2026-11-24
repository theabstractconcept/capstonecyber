"""Capture demo screenshots with Playwright (server must be running on :5443)."""
import io, tempfile, os
from pathlib import Path
from playwright.sync_api import sync_playwright

URL = "https://127.0.0.1:5443"
OUT = Path(__file__).parent / "screenshots"
tmp = Path(tempfile.mkdtemp())
(tmp / "Q3_budget.txt").write_text("Finance Q3 budget draft - confidential\n" * 20)
(tmp / "malware.exe").write_bytes(b"MZ fake")

def login(page, u, p):
    page.goto(f"{URL}/login")
    page.fill("input[name=username]", u); page.fill("input[name=password]", p)
    page.click("button.btn"); page.wait_for_load_state()

def logout(page):
    page.click("button.link"); page.wait_for_load_state()

with sync_playwright() as pw:
    b = pw.chromium.launch()
    ctx = b.new_context(ignore_https_errors=True, viewport={"width": 1100, "height": 720})
    page = ctx.new_page()

    page.goto(f"{URL}/login"); page.screenshot(path=OUT/"01_login_https.png")
    login(page, "fin_staff", "wrong"); page.screenshot(path=OUT/"02_login_failed.png")

    login(page, "fin_staff", "Staff@123456")
    page.set_input_files("input[type=file]", str(tmp/"malware.exe")); page.click("button.btn")
    page.wait_for_load_state(); page.screenshot(path=OUT/"03_upload_type_rejected.png")
    page.set_input_files("input[type=file]", str(tmp/"Q3_budget.txt")); page.click("button.btn")
    page.wait_for_load_state(); page.screenshot(path=OUT/"04_upload_encrypted_ok.png")
    page.goto(f"{URL}/admin/users"); page.screenshot(path=OUT/"05_rbac_staff_denied.png")
    logout(page)

    login(page, "hr_staff", "Staff@123456")
    page.screenshot(path=OUT/"06_other_department_sees_nothing.png")
    page.goto(f"{URL}/download/1"); page.screenshot(path=OUT/"07_cross_dept_download_403.png")
    logout(page)

    login(page, "fin_mgr", "Manager@12345"); page.screenshot(path=OUT/"08_manager_dashboard.png"); logout(page)

    login(page, "admin", "Admin@12345"); page.screenshot(path=OUT/"09_admin_all_files.png")
    page.goto(f"{URL}/admin/users"); page.screenshot(path=OUT/"10_admin_user_management.png")
    page.goto(f"{URL}/admin/audit"); page.screenshot(path=OUT/"11_audit_log.png")
    b.close()
print("screenshots saved:", sorted(p.name for p in OUT.glob("*.png")))
