"""Create demo users. Demo passwords only - never reuse them."""
from app import create_app

app = create_app()
demo = [
    ("admin",    "Admin@12345",   "admin",   "Administration"),
    ("fin_mgr",  "Manager@12345", "manager", "Finance"),
    ("fin_staff","Staff@123456",  "staff",   "Finance"),
    ("hr_staff", "Staff@123456",  "staff",   "HR"),
]
with app.app_context(), app.test_request_context():
    for u, p, r, d in demo:
        err = app.create_user_internal(u, p, r, d)
        print(f"{u:10} {r:8} {d:15}", "created" if not err else f"skipped ({err})")
