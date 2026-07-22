"""Clean counterpart of ../vulnerable/app/http_config.py — every issue fixed."""
import imghdr
import os

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from flask import Flask, make_response, request

app = Flask(__name__)

ALLOWED_ORIGINS = {"https://app.example.com", "https://admin.example.com"}


@app.route("/set-cookie")
def set_cookie():
    resp = make_response("ok")
    # V3.3.1 — Secure attribute set, __Secure- prefix used
    resp.set_cookie("__Secure-session", "abc123", secure=True, httponly=True, samesite="Strict")
    return resp


@app.after_request
def add_cors_headers(response):
    # V3.4.2 — CORS validated against an explicit allowlist, not a wildcard
    origin = request.headers.get("Origin")
    if origin in ALLOWED_ORIGINS:
        response.headers["Access-Control-Allow-Origin"] = origin
    return response


def encrypt_record(data: bytes, key: bytes) -> bytes:
    # V11.3.1 / V11.3.2 — AES-GCM, an approved cipher/mode
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)  # fresh nonce per encryption, never hardcoded
    return nonce + aesgcm.encrypt(nonce, data, None)


ALLOWED_UPLOAD_EXTENSIONS = {".png", ".jpg", ".pdf"}


def allowed_file(filename: str) -> bool:
    return os.path.splitext(filename)[1].lower() in ALLOWED_UPLOAD_EXTENSIONS


@app.route("/upload", methods=["POST"])
def upload():
    f = request.files["file"]
    ext = os.path.splitext(f.filename)[1].lower()
    # V5.2.2 — extension allowlist plus a magic-byte content check
    if not allowed_file(f.filename):
        return "unsupported file type", 400
    data = f.read()
    if ext in (".png", ".jpg") and imghdr.what(None, h=data) is None:
        return "file content does not match extension", 400
    safe_name = os.path.basename(f.filename)
    with open(os.path.join("/var/www/uploads", safe_name), "wb") as out:
        out.write(data)
    return "ok"


WS_ENDPOINT = "wss://realtime.example.com/socket"  # V4.4.1 — encrypted WebSocket
