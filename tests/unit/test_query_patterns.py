"""
Unit tests — queries/queries.json regex patterns

Validates that each detection pattern fires on known-vulnerable code
and does NOT fire on the corresponding safe alternative.
"""
import re
import json
from pathlib import Path
import pytest

QUERIES_PATH = Path(__file__).resolve().parents[2] / "queries" / "queries.json"

with QUERIES_PATH.open() as f:
    RULES: dict = json.load(f)


def matches_any(patterns: list[str], code: str) -> bool:
    for pat in patterns:
        try:
            if re.search(pat, code):
                return True
        except re.error:
            pass
    return False


def get_patterns(rule_id: str) -> list[str]:
    return RULES.get(rule_id, {}).get("regex_patterns", [])


# ── SQL Injection ─────────────────────────────────────────────────────────────

class TestSQLInjectionPatterns:
    RULE = "SQL_INJECTION"

    def test_fstring_query_detected(self):
        code = 'query = f"SELECT * FROM users WHERE id={user_id}"'
        pats = get_patterns(self.RULE)
        assert matches_any(pats, code)

    def test_string_concat_detected(self):
        code = 'cursor.execute("SELECT * FROM t WHERE u=" + username)'
        pats = get_patterns(self.RULE)
        assert matches_any(pats, code)

    def test_parameterized_query_not_detected(self):
        code = 'cursor.execute("SELECT * FROM t WHERE u=?", (username,))'
        pats = get_patterns(self.RULE)
        assert not matches_any(pats, code)


# ── Command Injection ─────────────────────────────────────────────────────────

class TestCommandInjectionPatterns:
    RULE = "COMMAND_INJECTION"

    def test_os_system_detected(self):
        assert matches_any(get_patterns(self.RULE), "os.system(cmd)")

    def test_shell_true_detected(self):
        assert matches_any(get_patterns(self.RULE), "subprocess.run(cmd, shell=True)")

    def test_child_process_exec_detected(self):
        assert matches_any(get_patterns(self.RULE), "child_process.exec(cmd)")

    def test_execsync_detected(self):
        assert matches_any(get_patterns(self.RULE), "child_process.execSync(userInput)")

    def test_safe_list_form_not_detected(self):
        # subprocess.run with list — no shell=True — should not fire regex
        code = "subprocess.run(['ls', '-la'], capture_output=True)"
        pats = get_patterns(self.RULE)
        assert not matches_any(pats, code)

    def test_os_popen_detected(self):
        assert matches_any(get_patterns(self.RULE), "os.popen(user_cmd)")


# ── Path Traversal ────────────────────────────────────────────────────────────

class TestPathTraversalPatterns:
    RULE = "PATH_TRAVERSAL"

    def test_open_with_plus_detected(self):
        assert matches_any(get_patterns(self.RULE), 'open("/base/" + filename)')

    def test_open_with_user_param_detected(self):
        assert matches_any(get_patterns(self.RULE), "open(user_path, 'r')")

    def test_send_file_with_request_args_detected(self):
        code = "send_file(request.args.get('f'))"
        assert matches_any(get_patterns(self.RULE), code)

    def test_js_path_join_with_req_query_detected(self):
        code = "path.join(__dirname, req.query.file)"
        assert matches_any(get_patterns(self.RULE), code)

    def test_safe_static_path_not_detected(self):
        code = "open('/var/app/static/logo.png', 'rb')"
        pats = get_patterns(self.RULE)
        assert not matches_any(pats, code)


# ── Insecure Deserialization ──────────────────────────────────────────────────

class TestDeserializationPatterns:
    RULE = "INSECURE_DESERIALIZATION"

    def test_pickle_loads_detected(self):
        assert matches_any(get_patterns(self.RULE), "pickle.loads(data)")

    def test_yaml_load_without_safeloader_detected(self):
        assert matches_any(get_patterns(self.RULE), "yaml.load(data)")

    def test_yaml_load_with_safeloader_not_detected(self):
        code = "yaml.load(data, Loader=SafeLoader)"
        assert not matches_any(get_patterns(self.RULE), code)

    def test_yaml_safe_load_not_detected(self):
        assert not matches_any(get_patterns(self.RULE), "yaml.safe_load(data)")

    def test_json_parse_not_detected(self):
        # JSON.parse is safe — removed from patterns
        assert not matches_any(get_patterns(self.RULE), "JSON.parse(body)")

    def test_marshal_loads_detected(self):
        assert matches_any(get_patterns(self.RULE), "marshal.loads(raw)")

    def test_jsonpickle_decode_detected(self):
        assert matches_any(get_patterns(self.RULE), "jsonpickle.decode(payload)")


# ── Weak Cryptography ─────────────────────────────────────────────────────────

class TestWeakCryptoPatterns:
    RULE = "WEAK_CRYPTO"

    def test_hashlib_md5_detected(self):
        assert matches_any(get_patterns(self.RULE), "hashlib.md5(data)")

    def test_hashlib_sha1_detected(self):
        assert matches_any(get_patterns(self.RULE), "hashlib.sha1(password)")

    def test_createhash_md5_detected(self):
        assert matches_any(get_patterns(self.RULE), "crypto.createHash('md5')")

    def test_rsa_generate_1024_detected(self):
        assert matches_any(get_patterns(self.RULE), "RSA.generate(1024)")

    def test_rsa_generate_512_detected(self):
        assert matches_any(get_patterns(self.RULE), "RSA.generate(512)")

    def test_key_size_1024_detected(self):
        assert matches_any(get_patterns(self.RULE), "key_size=1024")

    def test_rsa_generate_4096_not_detected(self):
        assert not matches_any(get_patterns(self.RULE), "RSA.generate(4096)")

    def test_hashlib_sha256_not_detected(self):
        assert not matches_any(get_patterns(self.RULE), "hashlib.sha256(data)")


# ── Hardcoded Secrets ─────────────────────────────────────────────────────────

class TestHardcodedSecretsPatterns:
    RULE = "HARDCODED_SECRETS"

    def test_jwt_secret_string_detected(self):
        assert matches_any(get_patterns(self.RULE), 'JWT_SECRET = "my-secret-key"')

    def test_api_key_assignment_detected(self):
        assert matches_any(get_patterns(self.RULE), 'api_key = "sk-1234567890abcdef"')

    def test_password_variable_detected(self):
        assert matches_any(get_patterns(self.RULE), 'db_password = "hardcoded_pw"')

    def test_env_var_lookup_not_detected(self):
        code = 'secret = os.environ.get("JWT_SECRET")'
        assert not matches_any(get_patterns(self.RULE), code)


# ── SSRF ──────────────────────────────────────────────────────────────────────

class TestSSRFPatterns:
    RULE = "SSRF"

    def test_requests_get_with_request_args_detected(self):
        code = "requests.get(request.args.get('url'))"
        assert matches_any(get_patterns(self.RULE), code)

    def test_requests_get_with_static_url_not_detected(self):
        # Static URL — not user-controlled
        code = 'requests.get("https://api.internal/health")'
        assert not matches_any(get_patterns(self.RULE), code)

    def test_urllib_with_req_body_detected(self):
        code = "urllib.request.urlopen(req.body)"
        assert matches_any(get_patterns(self.RULE), code)


# ── Debug Mode ────────────────────────────────────────────────────────────────

class TestDebugModePatterns:
    RULE = "INFORMATION_EXPOSURE_ERROR"

    def test_app_run_debug_true_detected(self):
        assert matches_any(get_patterns(self.RULE), "app.run(debug=True)")

    def test_app_run_debug_false_not_detected(self):
        assert not matches_any(get_patterns(self.RULE), "app.run(debug=False)")

    def test_debug_equals_true_standalone_detected(self):
        assert matches_any(get_patterns(self.RULE), "DEBUG = True")


# ── Insecure Cookie ───────────────────────────────────────────────────────────

class TestInsecureCookiePatterns:
    RULE = "INSECURE_COOKIE"

    def test_set_cookie_without_secure_detected(self):
        code = "set_cookie('session', token)"
        assert matches_any(get_patterns(self.RULE), code)

    def test_set_cookie_with_secure_and_httponly_not_detected(self):
        code = "set_cookie('session', token, secure=True, httponly=True)"
        assert not matches_any(get_patterns(self.RULE), code)

    def test_set_cookie_with_secure_only_missing_httponly_detected(self):
        # Broadened Phase-3 coverage: secure alone isn't enough to call a cookie safe —
        # a missing HttpOnly flag still leaves the cookie readable (and stealable) via XSS.
        code = "set_cookie('session', token, secure=True)"
        assert matches_any(get_patterns(self.RULE), code)

    def test_res_cookie_without_secure_detected(self):
        code = "res.cookie('auth', value)"
        assert matches_any(get_patterns(self.RULE), code)

    def test_res_cookie_with_secure_true_not_detected(self):
        code = "res.cookie('auth', value, { secure: true, httpOnly: true })"
        assert not matches_any(get_patterns(self.RULE), code)


# ── Unvalidated Redirect ──────────────────────────────────────────────────────

class TestUnvalidatedRedirectPatterns:
    RULE = "UNVALIDATED_REDIRECT"

    def test_res_redirect_with_req_query_detected(self):
        code = "res.redirect(req.query.next)"
        assert matches_any(get_patterns(self.RULE), code)

    def test_flask_redirect_with_request_args_detected(self):
        code = "redirect(request.args.get('url'))"
        assert matches_any(get_patterns(self.RULE), code)

    def test_static_redirect_not_detected(self):
        code = 'res.redirect("/dashboard")'
        assert not matches_any(get_patterns(self.RULE), code)
