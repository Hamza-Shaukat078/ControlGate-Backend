"""Deliberately vulnerable sample Flask app — ASVS 5.0.0 L1 test fixture.

Every issue below is intentional and exists solely to exercise the
detection engine's rule catalog (Section G). Do not deploy.
"""
import hashlib
import os
import subprocess
import xml.etree.ElementTree as ET

import jwt
from flask import Flask, request, redirect

app = Flask(__name__)

# V7.2.2 — static, hardcoded session/signing secret
SECRET_KEY = "dev-secret-please-change"

# V6.3.2 — default account credentials left in place
admin_password = "admin"


@app.route("/users")
def get_user():
    # V1.2.4 — SQL injection via string concatenation
    user_id = request.args.get("id")
    query = "SELECT * FROM users WHERE id = '" + user_id + "'"
    cursor.execute(query)


@app.route("/ping")
def ping():
    # V1.2.5 — OS command injection
    host = request.args.get("host")
    return subprocess.check_output(f"ping -c 1 {host}", shell=True)


@app.route("/file")
def read_file():
    # V5.3.2 — path traversal, user-controlled filename
    filename = request.args.get("name")
    return open(os.path.join("/var/app/uploads", filename)).read()


@app.route("/fetch")
def fetch():
    # SSRF — user-controlled URL fetched server-side
    import requests
    target = request.args.get("url")
    return requests.get(target).text


@app.route("/xml", methods=["POST"])
def parse_xml():
    # V1.5.1 — XXE, stdlib parser without hardening
    tree = ET.parse(request.data)
    return str(tree)


@app.route("/run")
def run_code():
    # V1.3.2 — dynamic code execution of user input
    expr = request.args.get("expr")
    return str(eval(expr))


def hash_password(password):
    # V11.4.1 — disallowed weak hash function
    return hashlib.md5(password.encode()).hexdigest()


def verify_token(token):
    # V7.2.1 / V9.2.1 — signature and expiry verification disabled
    return jwt.decode(token, options={"verify_signature": False, "verify_exp": False})


def verify_token_jku(token, header):
    # V9.1.3 — jku header trusted without an allowlist check
    key = header.get("jku")
    return jwt.decode(token, key=key)


def issue_token(payload):
    # V9.1.1 — token signed with a short, weak secret
    return jwt.encode(payload, "abc123")


def issue_unsigned_token(payload):
    # V9.1.2 — "none" algorithm explicitly permitted
    return jwt.encode(payload, key=None, algorithm="none")


@app.route("/transfer", methods=["POST"])
@csrf_exempt
def transfer_funds():
    # V3.5.1 — sensitive state-changing action exempted from CSRF protection
    return {"status": "transferred"}


@app.route("/register", methods=["POST"])
def register():
    password = request.form.get("password")
    # V6.2.1 — minimum length below 8
    min_length = 4
    if len(password) < min_length:
        return "too short", 400
    # V6.2.5 — mandatory character-composition rule (ASVS 5.0 discourages this)
    import re
    composition_regex = re.compile(r"(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[\W_])")
    if not composition_regex.search(password):
        return "must contain upper/lower/digit/special", 400
    return "ok"


@app.route("/security-question")
def security_question():
    # V6.4.2 — knowledge-based "secret question" auth
    return {"secret_question": "What is your pet's name?"}


@app.route("/redirect")
def open_redirect():
    # V1.2.2 — unsafe URL protocol / unencoded dynamic URL
    target = request.args.get("next")
    return redirect("javascript:" + target)


@app.route("/admin/users")
def admin_users():
    # V8.2.1 / V8.2.2 — admin route with no permission check
    return {"users": ["all", "of", "them"]}


@app.route("/login", methods=["POST"])
def login():
    # V6.3.1 — no rate limiting / brute-force protection on an auth endpoint
    username = request.form.get("username")
    password = request.form.get("password")
    return {"token": "abc"}


@app.route("/reset-link")
def reset_link():
    # V14.2.1 — sensitive token passed via URL query string
    session_token = request.args.get("session_token")
    return redirect("https://example.com/reset?token=" + session_token + "&session_token=" + session_token)
