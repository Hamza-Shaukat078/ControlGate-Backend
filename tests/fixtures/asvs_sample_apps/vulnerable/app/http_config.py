"""More deliberate ASVS L1 violations — cookie/CORS/crypto/upload/websocket."""
from Crypto.Cipher import DES
from flask import Flask, make_response

app = Flask(__name__)


@app.route("/set-cookie")
def set_cookie():
    resp = make_response("ok")
    # V3.3.1 — cookie missing the Secure attribute / __Secure- prefix
    resp.set_cookie("session", "abc123")
    return resp


@app.after_request
def add_cors_headers(response):
    # V3.4.2 — wide-open CORS with a fixed wildcard origin
    response.headers["Access-Control-Allow-Origin"] = "*"
    return response


def encrypt_record(data, key):
    # V11.3.1 / V11.3.2 — insecure block cipher (DES) in ECB mode
    cipher = DES.new(key, DES.MODE_ECB)
    return cipher.encrypt(data)


HARD_CODED_IV = b"\x00\x00\x00\x00\x00\x00\x00\x00"


@app.route("/upload", methods=["POST"])
def upload():
    from flask import request
    f = request.files["file"]
    # V5.2.2 — no extension/content-type validation before saving
    f.save("/var/www/uploads/" + f.filename)
    return "ok"


WS_ENDPOINT = "ws://realtime.example.com/socket"  # V4.4.1 — unencrypted WebSocket
