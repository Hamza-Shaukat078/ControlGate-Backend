"""Clean counterpart of the vulnerable sample app — every issue fixed.

ASVS 5.0.0 L1 test fixture (Section G): same shape as ../vulnerable/app/main.py,
used to confirm the detection engine doesn't false-positive on safe code.
"""
import os
import re
from pathlib import Path

import bcrypt
import jwt
from defusedxml import ElementTree as ET
from flask import Flask, request
from flask_limiter import Limiter
from flask_wtf import CSRFProtect

app = Flask(__name__)
csrf = CSRFProtect(app)
limiter = Limiter(app)  # V6.3.1 — rate limiting configured

SECRET_KEY = os.environ["SECRET_KEY"]  # V7.2.2 — loaded from environment, not hardcoded

UPLOAD_ROOT = Path("/var/app/uploads").resolve()
ALLOWED_EXTENSIONS = {".png", ".jpg", ".pdf"}


@app.route("/users")
def get_user():
    # V1.2.4 — parameterized query
    user_id = request.args.get("id")
    cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))


@app.route("/ping")
def ping():
    # V1.2.5 — no shell, argument list, no injection surface
    import subprocess
    host = request.args.get("host")
    return subprocess.check_output(["ping", "-c", "1", host])


@app.route("/file")
def read_file():
    # V5.3.2 — resolved path must stay within the upload root
    filename = os.path.basename(request.args.get("name", ""))
    target = (UPLOAD_ROOT / filename).resolve()
    if not str(target).startswith(str(UPLOAD_ROOT)):
        return "invalid path", 400
    return open(target).read()


@app.route("/xml", methods=["POST"])
def parse_xml():
    # V1.5.1 — defusedxml disables external entity resolution by default
    tree = ET.parse(request.data)
    return str(tree)


def hash_password(password: str) -> bytes:
    # V11.4.1 — approved password hashing (bcrypt), not a bare fast hash
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt())


def verify_token(token: str) -> dict:
    # V7.2.1 / V9.2.1 — signature and expiry verification both enabled (defaults)
    # V9.2.3 — audience validated against this service's identifier
    return jwt.decode(token, SECRET_KEY, algorithms=["HS256"], audience="controlgate-api")


def issue_token(payload: dict) -> str:
    # V9.1.1 — signed with the real, environment-provided secret
    return jwt.encode(payload, SECRET_KEY, algorithm="HS256")


@app.route("/register", methods=["POST"])
def register():
    password = request.form.get("password", "")
    # V6.2.1 — recommended minimum length, no composition rule (V6.2.5)
    if len(password) < 15:
        return "too short", 400
    return "ok"


@app.route("/admin/users")
def admin_users():
    # V8.2.1 / V8.2.2 — explicit permission check before returning data
    user = get_current_user(request)
    if not user or not user.is_admin:
        return "forbidden", 403
    return {"users": ["all", "of", "them"]}


@app.route("/transfer", methods=["POST"])
def transfer_funds():
    # V3.5.1 — protected by the app-wide CSRFProtect(app) instance above, no exemption
    return {"status": "transferred"}


def get_current_user(req):
    return None  # stub for fixture purposes
