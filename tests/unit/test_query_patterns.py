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


# ── V10 OAuth / OIDC rules ─────────────────────────────────────────────────────

class TestOAuthCallbackStatePatterns:
    RULE = "OAUTH_CALLBACK_STATE_NOT_VALIDATED"

    def test_callback_without_state_check_detected(self):
        code = '''
@app.route("/oauth/callback")
def callback():
    code = request.args.get("code")
    token = exchange_code(code)
'''
        assert matches_any(get_patterns(self.RULE), code)

    def test_callback_with_session_state_check_not_detected(self):
        code = '''
@app.route("/oauth/callback")
def callback():
    code = request.args.get("code")
    state = request.args.get("state")
    if state != session["state"]:
        abort(400)
    token = exchange_code(code)
'''
        assert not matches_any(get_patterns(self.RULE), code)


class TestOIDCIssuerNotValidatedPatterns:
    RULE = "OIDC_ISSUER_NOT_VALIDATED"

    def test_id_token_decode_without_issuer_check_detected(self):
        code = '''
claims = jwt.decode(id_token, key, algorithms=["RS256"])
user = get_user(claims["sub"])
'''
        assert matches_any(get_patterns(self.RULE), code)

    def test_id_token_decode_with_issuer_check_not_detected(self):
        code = '''
claims = jwt.decode(id_token, key, algorithms=["RS256"])
if claims["iss"] == EXPECTED_ISSUER:
    pass
'''
        assert not matches_any(get_patterns(self.RULE), code)


class TestOIDCUserLookupMissingIssuerPatterns:
    RULE = "OIDC_USER_LOOKUP_MISSING_ISSUER"

    def test_lookup_by_sub_only_detected(self):
        code = 'user = User.objects.get(sub=claims.get("sub"))'
        assert matches_any(get_patterns(self.RULE), code)

    def test_lookup_by_sub_and_iss_not_detected(self):
        code = 'user = User.objects.get(sub=claims.get("sub"), iss=claims.get("iss"))'
        assert not matches_any(get_patterns(self.RULE), code)


class TestStepUpClaimsNotValidatedPatterns:
    RULE = "STEPUP_CLAIMS_NOT_VALIDATED"

    def test_transfer_route_without_acr_check_detected(self):
        code = '''
@app.route("/api/transfer", methods=["POST"])
def transfer():
    amount = request.json["amount"]
    do_transfer(amount)
'''
        assert matches_any(get_patterns(self.RULE), code)

    def test_transfer_route_with_acr_check_not_detected(self):
        code = '''
@app.route("/api/transfer", methods=["POST"])
def transfer():
    if claims.get("acr") != "urn:mfa":
        abort(403)
    do_transfer(amount)
'''
        assert not matches_any(get_patterns(self.RULE), code)


class TestOAuthAuthzMissingPKCEPatterns:
    RULE = "OAUTH_AUTHZ_MISSING_PKCE"

    def test_authorize_url_without_pkce_detected(self):
        code = 'url = f"https://as.example.com/authorize?response_type=code&client_id={cid}"'
        assert matches_any(get_patterns(self.RULE), code)

    def test_authorize_url_with_pkce_not_detected(self):
        code = ('url = f"https://as.example.com/authorize?response_type=code&client_id={cid}'
                '&code_challenge={cc}&code_challenge_method=S256"')
        assert not matches_any(get_patterns(self.RULE), code)


class TestRefreshTokenNoExpiryPatterns:
    RULE = "REFRESH_TOKEN_NO_EXPIRY"

    def test_refresh_token_without_expiry_detected(self):
        code = "create_refresh_token(user_id=user.id)"
        assert matches_any(get_patterns(self.RULE), code)

    def test_refresh_token_with_expiry_not_detected(self):
        code = "create_refresh_token(user_id=user.id, expires_in=2592000)"
        assert not matches_any(get_patterns(self.RULE), code)


class TestOIDCClientKeysByEmailPatterns:
    RULE = "OIDC_CLIENT_KEYS_BY_EMAIL_NOT_SUB"

    def test_lookup_by_email_detected(self):
        code = 'user = User.objects.get_or_create(email=claims.get("email"))'
        assert matches_any(get_patterns(self.RULE), code)

    def test_lookup_by_sub_not_detected(self):
        code = 'user = User.objects.get_or_create(sub=claims.get("sub"))'
        assert not matches_any(get_patterns(self.RULE), code)


class TestOIDCDiscoveryPatterns:
    RULE = "OIDC_DISCOVERY_HTTP_OR_UNVALIDATED"

    def test_discovery_over_http_detected(self):
        code = 'doc = requests.get("http://as.example.com/.well-known/openid-configuration")'
        assert matches_any(get_patterns(self.RULE), code)

    def test_discovery_over_https_with_issuer_validation_not_detected(self):
        code = ('doc = requests.get("https://as.example.com/.well-known/openid-configuration")\n'
                'validate_issuer(doc["issuer"])')
        assert not matches_any(get_patterns(self.RULE), code)


class TestIDTokenAudienceNotCheckedPatterns:
    RULE = "ID_TOKEN_AUDIENCE_NOT_CHECKED"

    def test_id_token_decode_without_audience_detected(self):
        code = 'claims = jwt.decode(id_token, key, algorithms=["RS256"])'
        assert matches_any(get_patterns(self.RULE), code)

    def test_id_token_decode_with_audience_not_detected(self):
        code = 'claims = jwt.decode(id_token, key, algorithms=["RS256"], audience=CLIENT_ID)'
        assert not matches_any(get_patterns(self.RULE), code)


class TestLogoutTokenNotValidatedPatterns:
    RULE = "LOGOUT_TOKEN_NOT_VALIDATED"

    def test_logout_token_decode_without_claim_checks_detected(self):
        code = 'claims = jwt.decode(logout_token, key, algorithms=["RS256"])'
        assert matches_any(get_patterns(self.RULE), code)

    def test_logout_token_decode_with_claim_checks_not_detected(self):
        code = ('claims = jwt.decode(logout_token, key, algorithms=["RS256"])\n'
                'assert "sid" in claims["events"]')
        assert not matches_any(get_patterns(self.RULE), code)


class TestOIDCOPFragmentResponsePatterns:
    RULE = "OIDC_OP_ALLOWS_FRAGMENT_RESPONSE"

    def test_allowed_response_types_with_token_detected(self):
        code = 'ALLOWED_RESPONSE_TYPES = ["code", "token"]'
        assert matches_any(get_patterns(self.RULE), code)

    def test_allowed_response_types_code_only_not_detected(self):
        code = 'ALLOWED_RESPONSE_TYPES = ["code"]'
        assert not matches_any(get_patterns(self.RULE), code)


# ── V6 / V11 / V12 / V13 rules ─────────────────────────────────────────────────

class TestWeakKeyGenPatterns:
    RULE = "INSUFFICIENT_CRYPTO_KEY_SIZE"

    def test_weak_ec_curve_python_detected(self):
        code = "key = ec.generate_private_key(ec.SECP192R1())"
        assert matches_any(get_patterns(self.RULE), code)

    def test_strong_ec_curve_python_not_detected(self):
        code = "key = ec.generate_private_key(ec.SECP256R1())"
        assert not matches_any(get_patterns(self.RULE), code)

    def test_weak_ec_curve_node_detected(self):
        code = "crypto.generateKeyPairSync('ec', { namedCurve: 'secp192r1' })"
        assert matches_any(get_patterns(self.RULE), code)

    def test_strong_ec_curve_node_not_detected(self):
        code = "crypto.generateKeyPairSync('ec', { namedCurve: 'secp256r1' })"
        assert not matches_any(get_patterns(self.RULE), code)

    def test_dsa_generation_detected(self):
        assert matches_any(get_patterns(self.RULE), "key = DSA.generate(2048)")

    def test_dsa_generation_node_detected(self):
        code = "crypto.generateKeyPairSync('dsa', { modulusLength: 2048 })"
        assert matches_any(get_patterns(self.RULE), code)


class TestWeakTLSCipherSuitePatterns:
    RULE = "WEAK_TLS_CIPHER_SUITE"

    def test_set_ciphers_with_weak_tokens_detected(self):
        assert matches_any(get_patterns(self.RULE), 'context.set_ciphers("RC4:MD5")')

    def test_set_ciphers_strong_suite_not_detected(self):
        code = 'context.set_ciphers("HIGH:!aNULL:!MD5")'
        assert not matches_any(get_patterns(self.RULE), code)

    def test_node_tls_weak_ciphers_detected(self):
        code = "tls.createServer({ ciphers: 'RC4-SHA:3DES', key, cert })"
        assert matches_any(get_patterns(self.RULE), code)

    def test_node_tls_strong_ciphers_not_detected(self):
        code = "tls.createServer({ ciphers: 'TLS_AES_256_GCM_SHA384', key, cert })"
        assert not matches_any(get_patterns(self.RULE), code)


class TestInternalServicePlaintextHTTPPatterns:
    RULE = "INTERNAL_SERVICE_PLAINTEXT_HTTP"

    def test_private_ip_over_http_detected(self):
        assert matches_any(get_patterns(self.RULE), 'requests.get("http://10.0.4.12/api/data")')

    def test_bare_service_hostname_over_http_detected(self):
        code = 'requests.get("http://payment-service:8080/charge")'
        assert matches_any(get_patterns(self.RULE), code)

    def test_dot_internal_over_http_detected(self):
        code = 'requests.get("http://billing.internal/invoices")'
        assert matches_any(get_patterns(self.RULE), code)

    def test_internal_host_over_https_not_detected(self):
        code = 'requests.get("https://payment-service:8080/charge")'
        assert not matches_any(get_patterns(self.RULE), code)

    def test_external_domain_over_http_not_detected(self):
        # Public, dotted external domain — out of scope for this internal-host rule.
        code = 'requests.get("http://api.example.com/data")'
        assert not matches_any(get_patterns(self.RULE), code)

    def test_axios_bare_hostname_over_http_detected(self):
        code = "axios.get('http://redis-cache:6379/status')"
        assert matches_any(get_patterns(self.RULE), code)


class TestServiceAuthShortLivedCredentialsMarkerPatterns:
    RULE = "SERVICE_AUTH_SHORT_LIVED_CREDENTIALS_MARKER"

    def test_client_credentials_grant_detected(self):
        code = 'data = {"grant_type": "client_credentials"}'
        assert matches_any(get_patterns(self.RULE), code)

    def test_sts_assume_role_detected(self):
        assert matches_any(get_patterns(self.RULE), "creds = sts.assume_role(RoleArn=role_arn)")

    def test_vault_client_detected(self):
        assert matches_any(get_patterns(self.RULE), "client = hvac.Client(url=VAULT_ADDR)")

    def test_static_api_key_not_detected(self):
        code = 'headers = {"Authorization": f"Basic {API_KEY}"}'
        assert not matches_any(get_patterns(self.RULE), code)


class TestStepUpClaimsSSOTagging:
    """V6.8.4 reuses STEPUP_CLAIMS_NOT_VALIDATED's existing detection surface."""
    RULE = "STEPUP_CLAIMS_NOT_VALIDATED"

    def test_rule_tagged_with_both_controls(self):
        assert set(RULES[self.RULE]["asvs_controls"]) >= {"V10.3.4", "V6.8.4"}

    def test_withdraw_route_without_acr_check_detected(self):
        code = '''
@app.route("/api/withdraw", methods=["POST"])
def withdraw():
    amount = request.json["amount"]
    do_withdraw(amount)
'''
        assert matches_any(get_patterns(self.RULE), code)


# ── V14 / V15 rules ────────────────────────────────────────────────────────────

class TestCachedSensitiveDataPatterns:
    RULE = "CACHED_SENSITIVE_DATA_SERVER_SIDE"

    def test_redis_set_password_without_ttl_detected(self):
        code = 'redis_client.set(f"password:{user_id}", password)'
        assert matches_any(get_patterns(self.RULE), code)

    def test_redis_set_password_with_ttl_not_detected(self):
        code = 'redis_client.set(f"password:{user_id}", password, ex=60)'
        assert not matches_any(get_patterns(self.RULE), code)

    def test_memcache_set_card_without_ttl_detected(self):
        code = 'memcache_client.set("card_number:1", card)'
        assert matches_any(get_patterns(self.RULE), code)

    def test_memcache_set_card_with_ttl_not_detected(self):
        code = 'memcache_client.set("card_number:1", card, time=30)'
        assert not matches_any(get_patterns(self.RULE), code)

    def test_cache_cached_sensitive_route_without_timeout_detected(self):
        code = '''
@cache.cached()
def get_account_profile():
    return jsonify(profile)
'''
        assert matches_any(get_patterns(self.RULE), code)

    def test_cache_cached_sensitive_route_with_timeout_not_detected(self):
        code = '''
@cache.cached(timeout=30)
def get_account_profile():
    return jsonify(profile)
'''
        assert not matches_any(get_patterns(self.RULE), code)


class TestSensitiveDataToThirdPartyTrackerPatterns:
    RULE = "SENSITIVE_DATA_TO_THIRD_PARTY_TRACKER"

    def test_analytics_track_with_password_detected(self):
        code = 'analytics.track(user_id, "signup", { password: password })'
        assert matches_any(get_patterns(self.RULE), code)

    def test_analytics_track_without_sensitive_field_not_detected(self):
        code = 'analytics.track(user_id, "signup", { plan: "pro" })'
        assert not matches_any(get_patterns(self.RULE), code)

    def test_mixpanel_track_with_ssn_detected(self):
        assert matches_any(get_patterns(self.RULE), 'mixpanel.track("login", {"ssn": ssn})')

    def test_sentry_setuser_with_password_detected(self):
        code = "Sentry.setUser({ email: user.email, password: user.password })"
        assert matches_any(get_patterns(self.RULE), code)

    def test_sentry_setuser_without_sensitive_field_not_detected(self):
        code = "Sentry.setUser({ email: user.email })"
        assert not matches_any(get_patterns(self.RULE), code)


class TestSBOMMaintainedMarkerPatterns:
    RULE = "SBOM_MAINTAINED_MARKER"

    def test_cyclonedx_ci_step_detected(self):
        assert matches_any(get_patterns(self.RULE), "- run: cyclonedx-py -o sbom.xml")

    def test_sbom_action_detected(self):
        assert matches_any(get_patterns(self.RULE), "- uses: anchore/sbom-action@v0")

    def test_unrelated_ci_step_not_detected(self):
        assert not matches_any(get_patterns(self.RULE), "- run: pytest")


class TestDebugCodeInProductionPatterns:
    RULE = "TEST_DEBUG_CODE_IN_PRODUCTION"

    def test_hardcoded_test_user_detected(self):
        code = 'if username == "testuser":\n    grant_admin()'
        assert matches_any(get_patterns(self.RULE), code)

    def test_debug_route_without_env_gate_detected(self):
        code = '''
@app.route("/debug-only/reset")
def debug_reset():
    reset_db()
'''
        assert matches_any(get_patterns(self.RULE), code)

    def test_debug_route_with_env_gate_not_detected(self):
        code = '''
@app.route("/debug-only/reset")
def debug_reset():
    if not os.environ.get("DEBUG"):
        abort(404)
    reset_db()
'''
        assert not matches_any(get_patterns(self.RULE), code)

    def test_remove_before_prod_marker_detected(self):
        assert matches_any(get_patterns(self.RULE), "# TODO remove before production")


class TestHTTPParameterPollutionPatterns:
    RULE = "HTTP_PARAMETER_POLLUTION_MISSING_DEFENSE"

    def test_flask_args_get_into_sql_detected(self):
        code = '''
id = request.args.get("id")
cursor.execute("SELECT * FROM t WHERE id=" + id)
'''
        assert matches_any(get_patterns(self.RULE), code)

    def test_flask_getlist_not_detected(self):
        code = '''
ids = request.args.getlist("id")
cursor.execute("SELECT * FROM t WHERE id=" + ids[0])
'''
        assert not matches_any(get_patterns(self.RULE), code)

    def test_express_req_query_into_db_call_detected(self):
        code = '''
const role = req.query.role;
db.query("SELECT * FROM users WHERE role = ?", [role]);
'''
        assert matches_any(get_patterns(self.RULE), code)

    def test_express_array_isarray_guard_not_detected(self):
        code = '''
const role = req.query.role;
if (Array.isArray(role)) { return res.status(400).end(); }
db.query("SELECT * FROM users WHERE role = ?", [role]);
'''
        assert not matches_any(get_patterns(self.RULE), code)


class TestSpoofableProxyHeaderTrustedProxyPatterns:
    """V15.3.4 extends SPOOFABLE_PROXY_HEADER (V4.1.3) to cover raw req.ip trust."""
    RULE = "SPOOFABLE_PROXY_HEADER"

    def test_rule_tagged_with_both_controls(self):
        assert set(RULES[self.RULE]["asvs_controls"]) >= {"V4.1.3", "V15.3.4"}

    def test_req_ip_used_for_security_decision_detected(self):
        code = "if (req.ip == bannedIp) { block(); }"
        assert matches_any(get_patterns(self.RULE), code)

    def test_req_ip_with_trusted_proxy_marker_nearby_not_detected(self):
        code = "if (req.ip == bannedIp /* trusted_proxies configured via app.set('trust proxy', 1) */) { block(); }"
        assert not matches_any(get_patterns(self.RULE), code)


# ── V16 / V17 rules ────────────────────────────────────────────────────────────

class TestUTCTimestampLoggingMarkerPatterns:
    RULE = "UTC_TIMESTAMP_LOGGING_MARKER"

    def test_datetime_utcnow_detected(self):
        assert matches_any(get_patterns(self.RULE), "timestamp = datetime.utcnow()")

    def test_datetime_now_timezone_utc_detected(self):
        assert matches_any(get_patterns(self.RULE), "timestamp = datetime.now(timezone.utc)")

    def test_toisostring_detected(self):
        assert matches_any(get_patterns(self.RULE), "const ts = new Date().toISOString();")

    def test_naive_local_time_not_detected(self):
        assert not matches_any(get_patterns(self.RULE), "timestamp = datetime.now()")


class TestSensitiveDataInLogStatementPatterns:
    RULE = "SENSITIVE_DATA_IN_LOG_STATEMENT"

    def test_fstring_log_with_raw_ssn_detected(self):
        code = 'logger.info(f"processing user {user.ssn}")'
        assert matches_any(get_patterns(self.RULE), code)

    def test_fstring_log_with_masked_ssn_not_detected(self):
        code = 'logger.info(f"processing user {mask(user.ssn)}")'
        assert not matches_any(get_patterns(self.RULE), code)

    def test_template_literal_console_log_with_raw_password_detected(self):
        code = "console.log(`login attempt for ${user.password}`)"
        assert matches_any(get_patterns(self.RULE), code)

    def test_template_literal_console_log_with_redacted_password_not_detected(self):
        code = "console.log(`login attempt for ${redact(user.password)}`)"
        assert not matches_any(get_patterns(self.RULE), code)

    def test_concatenated_token_in_log_detected(self):
        code = 'logger.error("failed for token " + token)'
        assert matches_any(get_patterns(self.RULE), code)

    def test_non_sensitive_field_not_detected(self):
        code = 'logger.info(f"processing user {user.id}")'
        assert not matches_any(get_patterns(self.RULE), code)


class TestAuthOperationLoggedMarkerPatterns:
    RULE = "AUTH_OPERATION_LOGGED_MARKER"

    def test_login_route_with_log_call_detected(self):
        code = '''
@app.route("/login", methods=["POST"])
def login():
    logger.info("login attempt for %s", username)
    return do_login()
'''
        assert matches_any(get_patterns(self.RULE), code)

    def test_login_route_without_log_call_not_detected(self):
        code = '''
@app.route("/login", methods=["POST"])
def login():
    return do_login()
'''
        assert not matches_any(get_patterns(self.RULE), code)

    def test_express_logout_route_with_log_call_detected(self):
        code = '''
router.post("/logout", (req, res) => {
  logger.info("logout", req.user.id);
  res.end();
});
'''
        assert matches_any(get_patterns(self.RULE), code)


class TestAuthzDenialLoggedMarkerPatterns:
    RULE = "AUTHZ_DENIAL_LOGGED_MARKER"

    def test_abort_403_with_log_call_detected(self):
        code = '''
if not has_permission(user, resource):
    logger.warning("permission denied for %s", user.id)
    abort(403)
'''
        assert matches_any(get_patterns(self.RULE), code)

    def test_abort_403_without_log_call_not_detected(self):
        code = '''
if not has_permission(user, resource):
    abort(403)
'''
        assert not matches_any(get_patterns(self.RULE), code)

    def test_express_403_with_log_call_detected(self):
        code = '''
if (!isAllowed) {
  res.status(403).send("forbidden");
  logger.warn("access denied");
}
'''
        assert matches_any(get_patterns(self.RULE), code)


class TestExceptPassNoLogJSExtensionPatterns:
    """V16.3.4 broadened EXCEPT_PASS_NO_LOG to also cover JS/TS empty catch blocks."""
    RULE = "EXCEPT_PASS_NO_LOG"

    def test_rule_tagged_with_v16_3_4(self):
        assert "V16.3.4" in RULES[self.RULE]["asvs_controls"]

    def test_python_except_pass_still_detected(self):
        code = "try:\n    risky()\nexcept Exception:\n    pass"
        assert matches_any(get_patterns(self.RULE), code)

    def test_js_empty_catch_detected(self):
        assert matches_any(get_patterns(self.RULE), "try { risky(); } catch (e) {}")

    def test_js_comment_only_catch_detected(self):
        code = "try {\n  risky();\n} catch (e) {\n  // ignore\n}"
        assert matches_any(get_patterns(self.RULE), code)

    def test_js_catch_with_logging_not_detected(self):
        code = "try { risky(); } catch (e) { logger.error(e); }"
        assert not matches_any(get_patterns(self.RULE), code)


class TestSignalingFloodRateLimitingPatterns:
    RULE = "SIGNALING_FLOOD_RATE_LIMITING"

    def test_socket_on_offer_wrapped_in_ratelimit_detected(self):
        code = "socket.on('offer', rateLimit(handleOffer));"
        assert matches_any(get_patterns(self.RULE), code)

    def test_socket_on_offer_with_limiter_in_handler_detected(self):
        code = '''
socket.on('offer', (data) => {
  limiter.consume(socket.id);
  handleOffer(data);
});
'''
        assert matches_any(get_patterns(self.RULE), code)

    def test_socket_on_offer_without_rate_limit_not_detected(self):
        code = '''
socket.on('offer', (data) => {
  handleOffer(data);
});
'''
        assert not matches_any(get_patterns(self.RULE), code)

    def test_flask_signal_route_with_limiter_decorator_detected(self):
        code = '''
@limiter.limit("10/minute")
@app.route("/signal/offer", methods=["POST"])
def offer():
    return handle_offer()
'''
        assert matches_any(get_patterns(self.RULE), code)


class TestAuthCheckFailsOpenPatterns:
    RULE = "AUTH_CHECK_FAILS_OPEN"

    def test_python_except_exception_returns_true_detected(self):
        code = '''
def has_permission(user, resource):
    try:
        return check_acl(user, resource)
    except Exception:
        return True
'''
        assert matches_any(get_patterns(self.RULE), code)

    def test_python_bare_except_returns_true_detected(self):
        code = '''
def has_permission(user, resource):
    try:
        return check_acl(user, resource)
    except:
        return True
'''
        assert matches_any(get_patterns(self.RULE), code)

    def test_python_except_returns_false_not_detected(self):
        code = '''
def has_permission(user, resource):
    try:
        return check_acl(user, resource)
    except Exception:
        return False
'''
        assert not matches_any(get_patterns(self.RULE), code)

    def test_python_except_reraises_not_detected(self):
        code = '''
def has_permission(user, resource):
    try:
        return check_acl(user, resource)
    except Exception:
        raise
'''
        assert not matches_any(get_patterns(self.RULE), code)

    def test_express_catch_calls_next_with_no_error_detected(self):
        code = '''
function checkAuth(req, res, next) {
  try {
    verifyToken(req);
    next();
  } catch (e) {
    next();
  }
}
'''
        assert matches_any(get_patterns(self.RULE), code)

    def test_express_catch_forwards_error_to_next_not_detected(self):
        code = '''
function checkAuth(req, res, next) {
  try {
    verifyToken(req);
    next();
  } catch (e) {
    next(e);
  }
}
'''
        assert not matches_any(get_patterns(self.RULE), code)

    def test_js_catch_returns_true_detected(self):
        code = '''
function isAuthorized(req) {
  try {
    return acl.check(req.user);
  } catch (e) {
    return true;
  }
}
'''
        assert matches_any(get_patterns(self.RULE), code)

    def test_js_catch_returns_false_not_detected(self):
        code = '''
function isAuthorized(req) {
  try {
    return acl.check(req.user);
  } catch (e) {
    return false;
  }
}
'''
        assert not matches_any(get_patterns(self.RULE), code)


# ── Automated Tier-1 upgrades from manual_attestation ───────────────────────────

class TestStructuredLoggingMarkerPatterns:
    RULE = "STRUCTURED_LOGGING_MARKER"

    def test_pythonjsonlogger_import_detected(self):
        assert matches_any(get_patterns(self.RULE), "from pythonjsonlogger import jsonlogger")

    def test_structlog_import_detected(self):
        code = "import structlog\nlogger = structlog.get_logger()"
        assert matches_any(get_patterns(self.RULE), code)

    def test_winston_json_format_detected(self):
        assert matches_any(get_patterns(self.RULE), "winston.format.json()")

    def test_pino_require_detected(self):
        assert matches_any(get_patterns(self.RULE), "const pino = require('pino')")

    def test_plain_logging_config_not_detected(self):
        code = "logging.basicConfig(level=logging.INFO)"
        assert not matches_any(get_patterns(self.RULE), code)


class TestAdminSessionTerminationMarkerPatterns:
    RULE = "ADMIN_SESSION_TERMINATION_MARKER"

    def test_flask_admin_terminate_route_detected(self):
        code = '''
@app.route("/admin/users/<id>/sessions/<sid>", methods=["DELETE"])
def admin_terminate_session(id, sid):
    return do_terminate(sid)
'''
        assert matches_any(get_patterns(self.RULE), code)

    def test_express_admin_terminate_route_detected(self):
        code = "router.delete('/admin/users/:id/sessions/:sid', adminTerminateSession);"
        assert matches_any(get_patterns(self.RULE), code)

    def test_unrelated_route_not_detected(self):
        code = '''
@app.route("/users/profile")
def profile():
    return render_profile()
'''
        assert not matches_any(get_patterns(self.RULE), code)


class TestSelfServiceSessionManagementMarkerPatterns:
    RULE = "SELF_SERVICE_SESSION_MANAGEMENT_MARKER"

    def test_flask_list_my_sessions_detected(self):
        code = '''
@app.route("/account/sessions")
def list_my_sessions():
    return get_sessions(current_user)
'''
        assert matches_any(get_patterns(self.RULE), code)

    def test_express_sessions_route_detected(self):
        assert matches_any(get_patterns(self.RULE), "router.get('/sessions', listSessions);")

    def test_unrelated_route_not_detected(self):
        code = '''
@app.route("/account/profile")
def profile():
    return render_profile()
'''
        assert not matches_any(get_patterns(self.RULE), code)


class TestTokenRevocationEndpointMarkerPatterns:
    RULE = "TOKEN_REVOCATION_ENDPOINT_MARKER"

    def test_flask_revoke_route_detected(self):
        code = '''
@app.route("/oauth/revoke", methods=["POST"])
def revoke_token():
    return do_revoke()
'''
        assert matches_any(get_patterns(self.RULE), code)

    def test_express_revoke_route_detected(self):
        assert matches_any(get_patterns(self.RULE), "router.post('/oauth/revoke', revokeToken);")

    def test_token_issuance_route_not_detected(self):
        code = '''
@app.route("/oauth/token", methods=["POST"])
def issue_token():
    return do_issue()
'''
        assert not matches_any(get_patterns(self.RULE), code)


class TestConsentManagementEndpointMarkerPatterns:
    RULE = "CONSENT_MANAGEMENT_ENDPOINT_MARKER"

    def test_flask_list_consents_route_detected(self):
        code = '''
@app.route("/account/consents", methods=["GET"])
def list_consents():
    return get_consents(current_user)
'''
        assert matches_any(get_patterns(self.RULE), code)

    def test_revoke_consent_function_detected(self):
        code = "def revoke_consent(user_id, client_id):\n    pass"
        assert matches_any(get_patterns(self.RULE), code)

    def test_unrelated_route_not_detected(self):
        code = '''
@app.route("/account/profile")
def profile():
    return render_profile()
'''
        assert not matches_any(get_patterns(self.RULE), code)


# ── Tier-2 upgrades from manual_attestation ─────────────────────────────────────

class TestLogTransportPlaintextPatterns:
    RULE = "LOG_TRANSPORT_PLAINTEXT"

    def test_http_log_endpoint_env_detected(self):
        code = 'LOG_ENDPOINT = "http://logs.internal.example.com/ingest"'
        assert matches_any(get_patterns(self.RULE), code)

    def test_https_log_endpoint_env_not_detected(self):
        code = 'LOG_ENDPOINT = "https://logs.internal.example.com/ingest"'
        assert not matches_any(get_patterns(self.RULE), code)

    def test_winston_http_transport_without_ssl_detected(self):
        code = "new winston.transports.Http({ host: 'logs.example.com', port: 80 })"
        assert matches_any(get_patterns(self.RULE), code)

    def test_winston_http_transport_with_ssl_not_detected(self):
        code = "new winston.transports.Http({ host: 'logs.example.com', ssl: true })"
        assert not matches_any(get_patterns(self.RULE), code)

    def test_python_httphandler_secure_false_detected(self):
        code = "handler = logging.handlers.HTTPHandler(host, url, secure=False)"
        assert matches_any(get_patterns(self.RULE), code)


class TestCentralizedLogShippingMarkerPatterns:
    RULE = "CENTRALIZED_LOG_SHIPPING_MARKER"

    def test_ddtrace_import_detected(self):
        assert matches_any(get_patterns(self.RULE), "import ddtrace")

    def test_cloudwatch_logs_client_detected(self):
        assert matches_any(get_patterns(self.RULE), "client = boto3.client('logs')")

    def test_winston_cloudwatch_require_detected(self):
        code = "const transport = require('winston-cloudwatch')"
        assert matches_any(get_patterns(self.RULE), code)

    def test_plain_logging_config_not_detected(self):
        assert not matches_any(get_patterns(self.RULE), "logging.basicConfig(level=logging.INFO)")


class TestTenantIsolationMissingPatterns:
    RULE = "TENANT_ISOLATION_MISSING"

    def test_flask_tenant_route_missing_filter_detected(self):
        code = '''
@app.route("/tenants/<tenant_id>/users")
def list_users(tenant_id):
    return User.query.filter_by(active=True).all()
'''
        assert matches_any(get_patterns(self.RULE), code)

    def test_flask_tenant_route_with_filter_not_detected(self):
        code = '''
@app.route("/tenants/<tenant_id>/users")
def list_users(tenant_id):
    return User.query.filter_by(tenant_id=tenant_id, active=True).all()
'''
        assert not matches_any(get_patterns(self.RULE), code)

    def test_express_tenant_route_missing_filter_detected(self):
        code = '''
router.get('/tenants/:tenantId/users', (req, res) => {
  User.findOne({ id: req.params.userId }).then(u => res.json(u));
});
'''
        assert matches_any(get_patterns(self.RULE), code)

    def test_express_tenant_route_with_filter_not_detected(self):
        code = '''
router.get('/tenants/:tenantId/users', (req, res) => {
  User.findOne({ id: req.params.userId, tenantId: req.params.tenantId }).then(u => res.json(u));
});
'''
        assert not matches_any(get_patterns(self.RULE), code)
