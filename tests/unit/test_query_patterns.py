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


def sanitizer_present(rule_id: str, code: str) -> bool:
    """
    Whole-file sanitizer-marker check, mirroring
    QueryExecutor._file_contains_sanitizer: does any of the rule's declared
    `sanitizers` terms appear anywhere in the code (case-insensitive
    substring)? Some rules rely on this cheap, unbounded-position-safe check
    to *downgrade* confidence/severity for a guarded call instead of using an
    inline regex lookahead to fully suppress it (see test_redos_regex_patterns.py
    for why a wide, unanchored inline lookahead is a ReDoS risk).
    """
    sanitizers = RULES.get(rule_id, {}).get("sanitizers") or []
    code_lower = code.lower()
    return any(s.lower() in code_lower for s in sanitizers if s)


# ── Regression: duplicate rule_id catalog cleanup ───────────────────────────────

class TestDuplicateRuleCatalogCleanup:
    """
    Eight regex patterns used to be owned by two rule_ids each, so a single line
    of vulnerable code produced two separate "vulnerabilities" in a report (the
    pipeline dedups on rule_name, which differs between the duplicate rules).
    True duplicates were merged into one surviving rule_id; deleted ids must no
    longer appear in the catalog.
    """

    def test_eval_code_injection_merged_into_code_injection(self):
        assert "EVAL_CODE_INJECTION" not in RULES
        assert matches_any(get_patterns("CODE_INJECTION"), "result = eval(user_input)")
        assert matches_any(get_patterns("CODE_INJECTION"), "const fn = new Function(userInput);")

    def test_xml_injection_merged_into_xxe_unsafe_xml_parser(self):
        assert "XML_INJECTION" not in RULES
        merged = get_patterns("XXE_UNSAFE_XML_PARSER")
        assert matches_any(merged, "etree.fromstring(data)")
        assert matches_any(merged, "resolve_entities = True")

    def test_toctou_check_then_use_merged_into_race_condition_file(self):
        assert "TOCTOU_CHECK_THEN_USE" not in RULES

    def test_render_template_string_removed_from_xss_still_owned_by_template_injection(self):
        # render_template_string is a template-injection sink, not genuinely XSS —
        # it's mis-scoped under XSS and belongs solely to TEMPLATE_INJECTION.
        code = 'return render_template_string(user_input)'
        assert not matches_any(get_patterns("XSS"), code)
        assert matches_any(get_patterns("TEMPLATE_INJECTION"), code)
        assert "render_template_string" not in RULES["XSS"]["sinks"]

    def test_xss_still_detects_genuine_dom_xss_after_cleanup(self):
        assert matches_any(get_patterns("XSS"), "el.innerHTML = userInput;")

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

    def test_set_cookie_with_secure_only_not_detected_by_secure_rule(self):
        code = "set_cookie('session', token, secure=True)"
        assert not matches_any(get_patterns(self.RULE), code)

    def test_missing_httponly_detected_by_dedicated_rule(self):
        code = "set_cookie('session', token, secure=True)"
        assert matches_any(get_patterns("COOKIE_MISSING_HTTPONLY"), code)

    def test_res_cookie_without_secure_detected(self):
        code = "res.cookie('auth', value)"
        assert matches_any(get_patterns(self.RULE), code)

    def test_res_cookie_with_secure_true_not_detected(self):
        code = "res.cookie('auth', value, { secure: true, httpOnly: true })"
        assert not matches_any(get_patterns(self.RULE), code)

    def test_res_cookie_secure_true_missing_httponly_not_flagged_by_secure_rule(self):
        # INSECURE_COOKIE is V3.3.1 (Secure flag) only — HttpOnly is COOKIE_MISSING_HTTPONLY's
        # job (V3.3.4). A cookie with secure:true but no httpOnly must NOT trip this rule.
        code = "res.cookie('auth', value, { secure: true })"
        assert not matches_any(get_patterns(self.RULE), code)
        assert matches_any(get_patterns("COOKIE_MISSING_HTTPONLY"), code)


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

    def test_id_token_decode_with_issuer_check_detected_but_downgradeable(self):
        # jwt.decode(...) with an id_token argument still fires -- the regex
        # no longer inline-suppresses on a nearby issuer check (see
        # test_redos_regex_patterns.py); the whole-file sanitizer check is
        # what downgrades it instead.
        code = '''
claims = jwt.decode(id_token, key, algorithms=["RS256"])
if claims["iss"] == EXPECTED_ISSUER:
    pass
'''
        assert matches_any(get_patterns(self.RULE), code)
        assert sanitizer_present(self.RULE, code)


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

    def test_id_token_decode_with_audience_detected_but_downgradeable(self):
        # jwt.decode(...) with an id_token argument still fires -- the regex
        # no longer inline-suppresses on a nearby audience check (see
        # test_redos_regex_patterns.py); the whole-file sanitizer check is
        # what downgrades it instead.
        code = 'claims = jwt.decode(id_token, key, algorithms=["RS256"], audience=CLIENT_ID)'
        assert matches_any(get_patterns(self.RULE), code)
        assert sanitizer_present(self.RULE, code)


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

    def test_req_ip_with_trusted_proxy_marker_nearby_detected_but_downgradeable(self):
        # req.ip used in a security decision still fires -- the regex no
        # longer inline-suppresses on a nearby trust-proxy marker (see
        # test_redos_regex_patterns.py: the old inline lookahead was placed
        # *before* the req.ip anchor, meaning re.search tried it at every
        # position in the file regardless of any real match -- a ReDoS risk).
        # The whole-file sanitizer check is what downgrades it instead, and
        # unlike the old lookahead it also catches a marker declared earlier
        # in the file rather than only text that happens to follow req.ip.
        code = "if (req.ip == bannedIp /* trusted_proxies configured via app.set('trust proxy', 1) */) { block(); }"
        assert matches_any(get_patterns(self.RULE), code)
        assert sanitizer_present(self.RULE, code)


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


# ── ASVS 5.0.0 Level 3 — V1 Encoding and Sanitization ───────────────────────────

class TestCSVFormulaInjectionPatterns:
    RULE = "CSV_FORMULA_INJECTION"

    def test_writerow_with_raw_request_data_detected(self):
        code = "writer.writerow([request.form['name'], request.form['amount']])"
        assert matches_any(get_patterns(self.RULE), code)

    def test_writerow_with_escaped_request_data_not_detected(self):
        code = "writer.writerow([escape_csv(request.form['name']), amount])"
        assert not matches_any(get_patterns(self.RULE), code)

    def test_worksheet_write_with_raw_request_data_detected(self):
        code = "worksheet.write(row, col, request.json['comment'])"
        assert matches_any(get_patterns(self.RULE), code)

    def test_ws_cell_with_raw_request_data_detected(self):
        code = "ws.cell(row=1, column=1, value=req.body.notes)"
        assert matches_any(get_patterns(self.RULE), code)

    def test_writerow_with_non_request_data_not_detected(self):
        code = "writer.writerow([user.id, user.created_at])"
        assert not matches_any(get_patterns(self.RULE), code)


class TestReDoSVulnerableRegexPatterns:
    RULE = "REDOS_VULNERABLE_REGEX"

    def test_python_nested_plus_quantifier_detected(self):
        assert matches_any(get_patterns(self.RULE), 're.compile(r"(a+)+")')

    def test_python_nested_star_quantifier_detected(self):
        code = 're.match(r"^(\\w+)*$", value)'
        assert matches_any(get_patterns(self.RULE), code)

    def test_python_simple_char_class_not_detected(self):
        assert not matches_any(get_patterns(self.RULE), 're.compile(r"^[a-z]+$")')

    def test_python_bounded_quantifier_not_detected(self):
        assert not matches_any(get_patterns(self.RULE), 're.compile(r"^\\d{3}-\\d{4}$")')

    def test_js_regex_literal_nested_quantifier_detected(self):
        assert matches_any(get_patterns(self.RULE), "const re = /(a+)+/;")

    def test_js_regex_literal_simple_not_detected(self):
        assert not matches_any(get_patterns(self.RULE), "const re = /^[a-z]+$/;")

    def test_new_regexp_nested_quantifier_detected(self):
        code = 'new RegExp("(\\\\w+)*")'
        assert matches_any(get_patterns(self.RULE), code)


# ── ASVS 5.0.0 Level 3 — V2 Validation and Business Logic ───────────────────────

class TestHumanTimingEnforcementMarkerPatterns:
    RULE = "HUMAN_TIMING_ENFORCEMENT_MARKER"

    def test_python_elapsed_time_check_detected(self):
        code = '''
if time.time() - session['form_loaded_at'] < MIN_SUBMIT_TIME:
    abort(400)
'''
        assert matches_any(get_patterns(self.RULE), code)

    def test_recaptcha_verify_detected(self):
        code = '''
if not recaptcha.verify(token):
    abort(403)
'''
        assert matches_any(get_patterns(self.RULE), code)

    def test_js_elapsed_time_check_detected(self):
        code = (
            "const elapsed = Date.now() - session.formStartTime;\n"
            "if (elapsed < MIN_SUBMIT_TIME) return res.status(400).end();"
        )
        assert matches_any(get_patterns(self.RULE), code)

    def test_route_without_timing_check_not_detected(self):
        code = '''
@app.route("/transfer", methods=["POST"])
def transfer():
    amount = request.form["amount"]
    do_transfer(amount)
'''
        assert not matches_any(get_patterns(self.RULE), code)


# ── ASVS 5.0.0 Level 3 — V4 API and Web Service ─────────────────────────────────

class TestManualTransferEncodingHeaderPatterns:
    RULE = "MANUAL_TRANSFER_ENCODING_HEADER"

    def test_express_set_header_detected(self):
        code = "res.setHeader('Transfer-Encoding', 'chunked')"
        assert matches_any(get_patterns(self.RULE), code)

    def test_headers_dict_assignment_detected(self):
        code = "headers['Transfer-Encoding'] = 'chunked'"
        assert matches_any(get_patterns(self.RULE), code)

    def test_unrelated_header_not_detected(self):
        code = "res.setHeader('Content-Type', 'application/json')"
        assert not matches_any(get_patterns(self.RULE), code)


class TestRequestLengthValidationMarkerPatterns:
    RULE = "REQUEST_LENGTH_VALIDATION_MARKER"

    def test_python_url_length_check_detected(self):
        code = "if len(url) > MAX_URL_LENGTH: raise ValueError('too long')"
        assert matches_any(get_patterns(self.RULE), code)

    def test_js_cookie_header_length_check_detected(self):
        code = "if (cookieHeader.length > MAX_COOKIE_LENGTH) return res.status(400).end();"
        assert matches_any(get_patterns(self.RULE), code)

    def test_max_length_constant_detected(self):
        assert matches_any(get_patterns(self.RULE), "MAX_URI_LENGTH = 2048")

    def test_max_cookie_length_constant_detected(self):
        assert matches_any(get_patterns(self.RULE), "MAX_COOKIE_LENGTH = 4096")

    def test_unrelated_url_build_not_detected(self):
        assert not matches_any(get_patterns(self.RULE), "url = build_url(base, params)")


# ── V6 Authentication (L3) ────────────────────────────────────────────────────

class TestSuspiciousAuthNotificationMarkerPatterns:
    RULE = "SUSPICIOUS_AUTH_NOTIFICATION_MARKER"

    def test_security_alert_near_failed_login_detected(self):
        code = 'if failed_login_attempt(user):\n    send_security_alert(user, "unusual location")'
        assert matches_any(get_patterns(self.RULE), code)

    def test_plain_login_check_not_detected(self):
        code = 'if not check_password(user, pw):\n    return "invalid"'
        assert not matches_any(get_patterns(self.RULE), code)


class TestEmailUsedAsAuthFactorPatterns:
    RULE = "EMAIL_USED_AS_AUTH_FACTOR"

    def test_password_compared_to_email_detected(self):
        assert matches_any(get_patterns(self.RULE), "if password == user.email:\n    return True")

    def test_password_compared_to_hash_not_detected(self):
        assert not matches_any(get_patterns(self.RULE), "if password == user.password_hash:\n    return True")


class TestAuthDetailChangeNotificationMarkerPatterns:
    RULE = "AUTH_DETAIL_CHANGE_NOTIFICATION_MARKER"

    def test_notification_inside_change_password_detected(self):
        code = 'def change_password(user, new_pw):\n    user.password = hash(new_pw)\n    send_email(user, "password changed")'
        assert matches_any(get_patterns(self.RULE), code)

    def test_change_password_without_notification_not_detected(self):
        code = "def change_password(user, new_pw):\n    user.password = hash(new_pw)"
        assert not matches_any(get_patterns(self.RULE), code)


class TestUserEnumerationViaAuthErrorsPatterns:
    RULE = "USER_ENUMERATION_VIA_AUTH_ERRORS"

    def test_distinct_user_not_found_vs_wrong_password_detected(self):
        code = 'if not user:\n    return "User not found"\nif not check(pw):\n    return "Wrong password"'
        assert matches_any(get_patterns(self.RULE), code)

    def test_generic_invalid_credentials_message_not_detected(self):
        code = 'if not user or not check(pw):\n    return "Invalid username or password"'
        assert not matches_any(get_patterns(self.RULE), code)


class TestAdminResetSetsPasswordDirectlyPatterns:
    RULE = "ADMIN_RESET_SETS_PASSWORD_DIRECTLY"

    def test_admin_endpoint_accepting_new_password_detected(self):
        code = ('@app.post("/admin/users/reset-password")\n'
                'def admin_reset(user_id):\n'
                '    new_password = request.json.get("new_password")\n'
                '    user.password = hash(new_password)')
        assert matches_any(get_patterns(self.RULE), code)

    def test_admin_endpoint_triggering_reset_email_not_detected(self):
        code = '@app.post("/admin/users/reset-password")\ndef admin_reset(user_id):\n    send_password_reset_email(user)'
        assert not matches_any(get_patterns(self.RULE), code)


class TestAuthFactorRevocationEndpointMarkerPatterns:
    RULE = "AUTH_FACTOR_REVOCATION_ENDPOINT_MARKER"

    def test_device_revocation_route_detected(self):
        assert matches_any(get_patterns(self.RULE), '@app.delete("/account/devices/revoke")\ndef revoke_device():\n    pass')

    def test_device_listing_route_not_detected(self):
        assert not matches_any(get_patterns(self.RULE), '@app.get("/account/devices")\ndef list_devices():\n    pass')


class TestBiometricAsSoleFactorPatterns:
    RULE = "BIOMETRIC_AS_SOLE_FACTOR"

    def test_biometric_only_grants_session_detected(self):
        assert matches_any(get_patterns(self.RULE), "if verify_biometric(scan):\n    create_session(user)")

    def test_biometric_with_password_check_not_detected(self):
        code = "if verify_biometric(scan) and verify_password(pw):\n    create_session(user)"
        assert not matches_any(get_patterns(self.RULE), code)

    def test_unrelated_biometric_check_followed_by_unrelated_session_not_detected(self):
        # A biometric check used for a non-auth purpose (unlocking an album),
        # with an unrelated create_session() call for a different flow landing
        # nearby in the file, must not false-positive.
        code = ('def unlock_photo_album(user):\n'
                '    if verify_biometric(user.face_scan):\n'
                '        show_album(user)\n'
                '    audit_log("album_unlock_attempt")\n'
                '    refresh_ui_state()\n'
                '    x = compute_something(user)\n'
                '    create_session(guest_user)')
        assert not matches_any(get_patterns(self.RULE), code)


class TestTotpClientTimeTrustedPatterns:
    RULE = "TOTP_CLIENT_TIME_TRUSTED"

    def test_totp_verified_against_client_timestamp_detected(self):
        code = 'totp.verify(code, for_time=request.json.get("client_time"))'
        assert matches_any(get_patterns(self.RULE), code)

    def test_totp_verified_against_server_clock_not_detected(self):
        assert not matches_any(get_patterns(self.RULE), "totp.verify(code, for_time=int(time.time()))")


class TestPushMfaRateLimitingMarkerPatterns:
    RULE = "PUSH_MFA_RATE_LIMITING_MARKER"

    def test_rate_limit_decorator_near_push_approve_detected(self):
        code = '@app.post("/mfa/push-approve")\n@limiter.limit("5/minute")\ndef push_approve():\n    pass'
        assert matches_any(get_patterns(self.RULE), code)

    def test_push_approve_route_without_rate_limit_not_detected(self):
        code = '@app.post("/mfa/push-approve")\ndef push_approve():\n    pass'
        assert not matches_any(get_patterns(self.RULE), code)


class TestWeakChallengeNoncePatterns:
    RULE = "WEAK_CHALLENGE_NONCE"

    def test_undersized_token_bytes_detected(self):
        assert matches_any(get_patterns(self.RULE), "challenge = secrets.token_bytes(4)")

    def test_time_based_uuid1_detected(self):
        assert matches_any(get_patterns(self.RULE), "nonce = uuid.uuid1()")

    def test_full_entropy_token_bytes_not_detected(self):
        assert not matches_any(get_patterns(self.RULE), "challenge = secrets.token_bytes(32)")

    def test_csprng_uuid4_not_detected(self):
        assert not matches_any(get_patterns(self.RULE), "nonce = uuid.uuid4()")


# ── V7 Session Management / V8 Authorization (L3) ─────────────────────────────

class TestStepUpClaimsSessionMgmtTagging:
    """V7.5.3 reuses STEPUP_CLAIMS_NOT_VALIDATED's existing detection surface."""
    RULE = "STEPUP_CLAIMS_NOT_VALIDATED"

    def test_rule_tagged_with_v7_5_3(self):
        assert "V7.5.3" in RULES[self.RULE]["asvs_controls"]

    def test_transfer_route_without_acr_check_still_detected(self):
        code = '''
@app.route("/api/transfer", methods=["POST"])
def transfer():
    amount = request.json["amount"]
    do_transfer(amount)
'''
        assert matches_any(get_patterns(self.RULE), code)


class TestAdaptiveAuthMarkerPatterns:
    RULE = "ADAPTIVE_AUTH_MARKER"

    def test_risk_score_near_login_detected(self):
        code = ('def login(user, pw):\n'
                '    if check_password(user, pw):\n'
                '        score = calculate_risk(user, request)\n'
                '        if score > 80:\n'
                '            require_mfa()')
        assert matches_any(get_patterns(self.RULE), code)

    def test_geoip_lookup_near_authenticate_detected(self):
        code = 'def authenticate(user, pw):\n    check_password(user, pw)\n    geoip2.database.Reader("GeoLite2-City.mmdb")'
        assert matches_any(get_patterns(self.RULE), code)

    def test_plain_login_without_risk_signal_not_detected(self):
        code = "def login(user, pw):\n    if check_password(user, pw):\n        create_session(user)"
        assert not matches_any(get_patterns(self.RULE), code)


# ── V10 OAuth/OIDC / V11 Cryptography (L3) ────────────────────────────────────

class TestTimingAttackSecretComparisonMapping:
    """V11.2.4 reuses TIMING_ATTACK's existing non-constant-time comparison detection."""
    RULE = "TIMING_ATTACK"

    def test_rule_tagged_with_v11_2_4(self):
        assert "V11.2.4" in RULES[self.RULE]["asvs_controls"]

    def test_password_compared_with_loose_equality_still_detected(self):
        assert matches_any(get_patterns(self.RULE), "if password == user.password_hash:\n    return True")

    def test_compare_digest_not_detected(self):
        code = "if hmac.compare_digest(password, user.password_hash):\n    return True"
        assert not matches_any(get_patterns(self.RULE), code)


class TestHardCodedIvNonceReuseTagging:
    """V11.3.4 reuses USE_OF_HARD_CODED_IV, broadened to also catch hardcoded nonce literals."""
    RULE = "USE_OF_HARD_CODED_IV"

    def test_rule_tagged_with_v11_3_4(self):
        assert "V11.3.4" in RULES[self.RULE]["asvs_controls"]

    def test_hardcoded_iv_still_detected(self):
        assert matches_any(get_patterns(self.RULE), 'iv = b"0123456789012345"')

    def test_hardcoded_nonce_detected(self):
        assert matches_any(get_patterns(self.RULE), 'nonce = b"fixednonce12"')

    def test_random_iv_not_detected(self):
        assert not matches_any(get_patterns(self.RULE), "iv = os.urandom(16)")


class TestInsufficientCryptoKeySizeKeyExchangeTagging:
    """V11.6.2 reuses INSUFFICIENT_CRYPTO_KEY_SIZE's existing DH parameter-size check."""
    RULE = "INSUFFICIENT_CRYPTO_KEY_SIZE"

    def test_rule_tagged_with_v11_6_2(self):
        assert "V11.6.2" in RULES[self.RULE]["asvs_controls"]

    def test_weak_dh_params_still_detected(self):
        assert matches_any(get_patterns(self.RULE), "dh.generate_parameters(generator=2, key_size=1024)")


class TestOAuthWildcardScopeRequestPatterns:
    RULE = "OAUTH_WILDCARD_SCOPE_REQUEST"

    def test_wildcard_scope_dict_detected(self):
        assert matches_any(get_patterns(self.RULE), 'params = {"scope": "*"}')

    def test_all_scope_in_authorize_url_detected(self):
        code = 'authorize_url = f"https://idp.example.com/authorize?client_id=x&scope=all"'
        assert matches_any(get_patterns(self.RULE), code)

    def test_scoped_permission_request_not_detected(self):
        assert not matches_any(get_patterns(self.RULE), 'params = {"scope": "read:profile"}')


class TestBearerTokenNotSenderConstrainedPatterns:
    RULE = "BEARER_TOKEN_NOT_SENDER_CONSTRAINED"

    def test_bearer_token_verified_without_dpop_check_detected(self):
        code = 'token = request.headers.get("Authorization").split("Bearer ")[1]\nclaims = jwt.decode(token, key)'
        assert matches_any(get_patterns(self.RULE), code)

    def test_bearer_token_with_dpop_check_not_detected(self):
        code = ('token = request.headers.get("Authorization").split("Bearer ")[1]\n'
                'if not verify_dpop_proof(request):\n    abort(401)\n'
                'claims = jwt.decode(token, key)')
        assert not matches_any(get_patterns(self.RULE), code)


class TestMacThenEncryptPatternPatterns:
    RULE = "MAC_THEN_ENCRYPT_PATTERN"

    def test_python_mac_computed_before_cbc_encrypt_detected(self):
        code = ('mac = hmac.new(key, plaintext, hashlib.sha256).digest()\n'
                'cipher = AES.new(key, AES.MODE_CBC, iv)\n'
                'ciphertext = cipher.encrypt(plaintext)\n'
                'result = ciphertext + mac')
        assert matches_any(get_patterns(self.RULE), code)

    def test_js_mac_computed_before_cbc_cipher_created_detected(self):
        code = ('const mac = crypto.createHmac("sha256", key).update(plaintext).digest();\n'
                'const cipher = crypto.createCipheriv("aes-256-cbc", key, iv);')
        assert matches_any(get_patterns(self.RULE), code)

    def test_encrypt_then_mac_order_not_detected(self):
        code = ('cipher = AES.new(key, AES.MODE_CBC, iv)\n'
                'ciphertext = cipher.encrypt(plaintext)\n'
                'mac = hmac.new(key, ciphertext, hashlib.sha256).digest()')
        assert not matches_any(get_patterns(self.RULE), code)

    def test_unrelated_hmac_before_unrelated_gcm_encrypt_not_detected(self):
        # AEAD (GCM) needs no separate MAC at all, and this hmac isn't even
        # related to the encryption call — must not false-positive.
        code = ('audit_mac = hmac.new(audit_key, data, hashlib.sha256).digest()\n'
                'log_audit(audit_mac)\n'
                'aesgcm = AESGCM(session_key)\n'
                'ciphertext = aesgcm.encrypt(nonce, data, None)')
        assert not matches_any(get_patterns(self.RULE), code)


# ── V12 Secure Communication / V13 Configuration (L3) ─────────────────────────

class TestCryptoViaIsolatedSecurityModuleMarkerPatterns:
    RULE = "CRYPTO_VIA_ISOLATED_SECURITY_MODULE_MARKER"

    def test_kms_encrypt_call_detected(self):
        code = 'ciphertext = kms.encrypt(KeyId=key_id, Plaintext=data)["CiphertextBlob"]'
        assert matches_any(get_patterns(self.RULE), code)

    def test_vault_transit_encrypt_detected(self):
        code = 'client = vault.write("transit/encrypt/my-key", plaintext=b64_data)'
        assert matches_any(get_patterns(self.RULE), code)

    def test_pkcs11_hsm_session_detected(self):
        code = 'session = pkcs11.lib("/usr/lib/softhsm/libsofthsm2.so").get_token()'
        assert matches_any(get_patterns(self.RULE), code)

    def test_boto3_kms_client_detected(self):
        code = 'kms_client = boto3.client("kms")\nresult = kms_client.encrypt(KeyId=key_id, Plaintext=data)'
        assert matches_any(get_patterns(self.RULE), code)

    def test_local_cipher_encrypt_not_detected(self):
        assert not matches_any(get_patterns(self.RULE), "data_encrypted = cipher.encrypt(plaintext)")


# ── V14 Data Protection / V15 Secure Coding and Architecture (L3) ────────────

class TestUnmaskedSensitiveFieldInResponsePatterns:
    RULE = "UNMASKED_SENSITIVE_FIELD_IN_RESPONSE"

    def test_jsonify_full_card_number_detected(self):
        code = 'return jsonify({"card_number": card.number, "expiry": card.expiry})'
        assert matches_any(get_patterns(self.RULE), code)

    def test_res_json_ssn_attribute_detected(self):
        code = "res.json(user.ssn)"
        assert matches_any(get_patterns(self.RULE), code)

    def test_masked_card_number_not_detected(self):
        code = 'return jsonify({"card_number": "**** **** **** 1234", "expiry": card.expiry})'
        assert not matches_any(get_patterns(self.RULE), code)

    def test_unrelated_field_not_detected(self):
        code = 'return jsonify({"username": user.username})'
        assert not matches_any(get_patterns(self.RULE), code)


class TestDataRetentionDeletionJobMarkerPatterns:
    RULE = "DATA_RETENTION_DELETION_JOB_MARKER"

    def test_mongo_ttl_index_detected(self):
        assert matches_any(get_patterns(self.RULE), "expireAfterSeconds: 2592000")

    def test_cron_decorator_delete_detected(self):
        code = '@cron("0 3 * * *")\ndef purge_stale_records():\n    Record.objects.filter(...).delete()'
        assert matches_any(get_patterns(self.RULE), code)

    def test_sql_delete_by_created_at_detected(self):
        code = "DELETE FROM audit_logs WHERE created_at < :cutoff"
        assert matches_any(get_patterns(self.RULE), code)

    def test_unrelated_delete_call_not_detected(self):
        assert not matches_any(get_patterns(self.RULE), "user.delete()")


class TestUploadMetadataNotStrippedPatterns:
    RULE = "UPLOAD_METADATA_NOT_STRIPPED"

    def test_flask_request_files_save_detected(self):
        code = 'request.files["avatar"].save(upload_path)'
        assert matches_any(get_patterns(self.RULE), code)

    def test_multer_setup_detected(self):
        code = "const upload = multer({ dest: 'uploads/' });"
        assert matches_any(get_patterns(self.RULE), code)

    def test_express_fileupload_mv_detected(self):
        code = "req.files.avatar.mv(uploadPath);"
        assert matches_any(get_patterns(self.RULE), code)

    def test_metadata_stripping_softens_via_sanitizer_list(self):
        # The rule intentionally still matches the save call — stripping calls are
        # a whole-file sanitizer softening confidence, not a suppression — but the
        # sanitizer token itself must be present in the rule's sanitizer list.
        assert "piexif.remove" in RULES[self.RULE]["sanitizers"]


class TestRaceConditionFilePatterns:
    """
    TOCTOU_CHECK_THEN_USE was a duplicate of RACE_CONDITION_FILE (same CWE-367)
    accidentally added later; its JS/TS coverage and V15.4.2 tagging were merged
    into RACE_CONDITION_FILE and the duplicate rule was deleted.
    """
    RULE = "RACE_CONDITION_FILE"

    def test_rule_tagged_with_v15_4_2(self):
        assert "V15.4.2" in RULES[self.RULE]["asvs_controls"]

    def test_python_exists_then_open_detected(self):
        code = "if os.path.exists(path):\n    with open(path) as f:\n        data = f.read()"
        assert matches_any(get_patterns(self.RULE), code)

    def test_python_access_then_open_detected(self):
        code = "if os.access(path, os.R_OK):\n    f = open(path)"
        assert matches_any(get_patterns(self.RULE), code)

    def test_python_exists_then_remove_detected(self):
        code = "if os.path.exists(lockfile):\n    os.remove(lockfile)"
        assert matches_any(get_patterns(self.RULE), code)

    def test_node_exists_sync_then_read_detected(self):
        code = "if (fs.existsSync(path)) {\n  const data = fs.readFileSync(path);\n}"
        assert matches_any(get_patterns(self.RULE), code)

    def test_atomic_open_with_exist_flag_not_detected(self):
        code = "fd = os.open(path, os.O_CREAT | os.O_EXCL)"
        assert not matches_any(get_patterns(self.RULE), code)


# ── V16 Logging and Error Handling / V17 WebRTC (L3) ──────────────────────────

class TestLastResortErrorHandlerMarkerPatterns:
    RULE = "LAST_RESORT_ERROR_HANDLER_MARKER"

    def test_python_sys_excepthook_detected(self):
        assert matches_any(get_patterns(self.RULE), "sys.excepthook = handle_uncaught_exception")

    def test_fastapi_exception_handler_detected(self):
        code = "@app.exception_handler(Exception)\nasync def handle_all(request, exc):\n    ..."
        assert matches_any(get_patterns(self.RULE), code)

    def test_node_uncaught_exception_detected(self):
        code = "process.on('uncaughtException', (err) => { logger.fatal(err); process.exit(1); });"
        assert matches_any(get_patterns(self.RULE), code)

    def test_node_unhandled_rejection_detected(self):
        code = 'process.on("unhandledRejection", (reason) => { logger.fatal(reason); });'
        assert matches_any(get_patterns(self.RULE), code)

    def test_express_final_error_middleware_detected(self):
        code = "app.use((err, req, res, next) => {\n  res.status(500).json({ error: 'internal' });\n});"
        assert matches_any(get_patterns(self.RULE), code)

    def test_ordinary_route_specific_try_except_not_detected(self):
        code = "try:\n    do_thing()\nexcept ValueError:\n    return {\"error\": \"bad input\"}"
        assert not matches_any(get_patterns(self.RULE), code)


class TestSdpFingerprintVerificationMarkerPatterns:
    RULE = "SDP_FINGERPRINT_VERIFICATION_MARKER"

    def test_sdp_fingerprint_line_compared_to_cert_detected(self):
        code = (
            'const sdpFingerprint = sdp.match(/a=fingerprint:(\\S+)/)[1];\n'
            'if (sdpFingerprint === peerCert.fingerprint) { acceptStream(); } else { rejectStream(); }'
        )
        assert matches_any(get_patterns(self.RULE), code)

    def test_get_fingerprint_comparison_detected(self):
        code = "if (transport.getFingerprint() === expectedFingerprint) { acceptStream(); }"
        assert matches_any(get_patterns(self.RULE), code)

    def test_remote_fingerprint_variable_comparison_detected(self):
        code = "if remoteFingerprint == dtls_cert_hash:\n    accept_stream()"
        assert matches_any(get_patterns(self.RULE), code)

    def test_unrelated_string_comparison_not_detected(self):
        code = "if (username === expectedUsername) { login(); }"
        assert not matches_any(get_patterns(self.RULE), code)


# ── Regression: COMMAND_INJECTION pattern ReDoS ────────────────────────────────

class TestCommandInjectionRegexNoBacktrackBlowup:
    """
    queries.json COMMAND_INJECTION pattern for spawn/execFile array args used to be:
      (?:cp\\.)?(?:spawn|execFile)\\s*\\([^\\n]*\\[(?:[^\\]]*,)*\\s*(?:cmd|command|path)\\s*(?:,|\\])
    The inner class [^\\]]* didn't exclude ',' so a run of commas inside the
    brackets could split ambiguously in exponentially many ways, causing
    catastrophic backtracking on a non-matching adversarial payload.
    Fixed by excluding ',' from the inner class: [^\\],]*
    """
    RULE = "COMMAND_INJECTION"

    def _pattern(self) -> str:
        for pat in get_patterns(self.RULE):
            if "spawn|execFile" in pat and r"\[" in pat:
                return pat
        raise AssertionError("spawn/execFile array-arg pattern not found in COMMAND_INJECTION rules")

    def test_still_detects_cmd_in_array(self):
        code = "spawn('sh', ['-c', cmd])"
        assert matches_any(get_patterns(self.RULE), code)

    def test_still_ignores_safe_array_without_cmd(self):
        code = "spawn('ls', ['-la', '-h'])"
        assert not matches_any(get_patterns(self.RULE), code)

    def test_adversarial_comma_payload_completes_fast(self):
        import time

        pattern = self._pattern()
        payload = "spawn('sh', [" + ("," * 40) + "x)"  # never closes with ']' — forces full backtrack search on failure
        start = time.monotonic()
        re.search(pattern, payload)
        elapsed = time.monotonic() - start
        assert elapsed < 0.5, f"regex took {elapsed:.2f}s on adversarial payload — ReDoS regression"


# ── Track D3 — V8.2.1: destructive route without ownership guard ──────────────

class TestUnprotectedDestructiveRoutePatterns:
    """A DELETE/PUT sibling of BROKEN_ACCESS_CONTROL/ADMIN_ROUTE_UNPROTECTED —
    catches a resource-id-in-the-URL-path route (Flask <id>/FastAPI {id}/
    Express :id) with no ownership/permission guard, a shape neither existing
    rule catches: BROKEN_ACCESS_CONTROL only looks for request.args/req.query
    reads, and ADMIN_ROUTE_UNPROTECTED only looks for '/admin' in the path."""

    RULE = "UNPROTECTED_DESTRUCTIVE_ROUTE"

    def test_flask_delete_route_without_guard_detected(self):
        code = (
            "@app.route('/orders/<int:order_id>', methods=['DELETE'])\n"
            "def delete_order(order_id):\n"
            "    db.orders.delete(order_id)\n"
            "    return '', 204\n"
        )
        assert matches_any(get_patterns(self.RULE), code)

    def test_flask_delete_route_with_ownership_guard_not_detected(self):
        code = (
            "@app.route('/orders/<int:order_id>', methods=['DELETE'])\n"
            "@login_required\n"
            "def delete_order(order_id):\n"
            "    if not check_ownership(current_user, order_id):\n"
            "        abort(403)\n"
            "    db.orders.delete(order_id)\n"
            "    return '', 204\n"
        )
        assert not matches_any(get_patterns(self.RULE), code)

    def test_fastapi_delete_route_without_guard_detected(self):
        code = (
            "@app.delete(\"/items/{item_id}\")\n"
            "def delete_item(item_id: int):\n"
            "    db.remove(item_id)\n"
        )
        assert matches_any(get_patterns(self.RULE), code)

    def test_fastapi_delete_route_with_depends_guard_not_detected(self):
        code = (
            "@app.delete(\"/items/{item_id}\")\n"
            "def delete_item(item_id: int, user=Depends(get_current_user)):\n"
            "    authorize(user, item_id)\n"
            "    db.remove(item_id)\n"
        )
        assert not matches_any(get_patterns(self.RULE), code)

    def test_express_delete_route_without_guard_detected(self):
        code = (
            "router.delete('/api/orders/:id', (req, res) => {\n"
            "    db.orders.remove(req.params.id);\n"
            "    res.sendStatus(204);\n"
            "});\n"
        )
        assert matches_any(get_patterns(self.RULE), code)

    def test_express_delete_route_with_ownership_guard_not_detected(self):
        code = (
            "router.delete('/api/orders/:id', requireAuth, (req, res) => {\n"
            "    if (!checkOwnership(req.user, req.params.id)) return res.sendStatus(403);\n"
            "    db.orders.remove(req.params.id);\n"
            "    res.sendStatus(204);\n"
            "});\n"
        )
        assert not matches_any(get_patterns(self.RULE), code)

    def test_get_route_on_the_same_path_is_not_flagged(self):
        # Only DELETE/PUT are destructive here — a plain read endpoint on the
        # same resource shape is out of scope for this rule (BROKEN_ACCESS_CONTROL
        # already covers unguarded reads via the request.args/id shape).
        code = "@app.route('/orders/<int:order_id>', methods=['GET'])\ndef get_order(order_id):\n    return db.orders.get(order_id)\n"
        assert not matches_any(get_patterns(self.RULE), code)

    def test_adversarial_input_completes_fast(self):
        import time

        code = "no_match_line_of_code_here_at_all(a, b, c);\n" * 5000
        for pattern in get_patterns(self.RULE):
            start = time.perf_counter()
            re.search(pattern, code)
            elapsed = time.perf_counter() - start
            assert elapsed < 1.0, f"{self.RULE} pattern took {elapsed:.2f}s — ReDoS regression: {pattern!r}"


# ── Track D3 — V2.3.2: business-logic value used without a bounds check ───────

class TestUnvalidatedBusinessLogicValuePatterns:
    """Low-confidence by design (see queries.json description): variable
    naming is the only signal a value feeds a calculation, and 'no validation
    keyword nearby' is not proof none exists elsewhere in the function."""

    RULE = "UNVALIDATED_BUSINESS_LOGIC_VALUE"

    def test_python_price_and_quantity_used_unchecked_detected(self):
        code = (
            "quantity = request.json.get('quantity')\n"
            "price = request.json.get('price')\n"
            "total = price * quantity\n"
        )
        assert matches_any(get_patterns(self.RULE), code)

    def test_python_price_and_quantity_bounds_checked_not_detected(self):
        code = (
            "quantity = request.json.get('quantity')\n"
            "if quantity <= 0 or quantity > MAX_QUANTITY:\n"
            "    raise ValueError('invalid quantity')\n"
            "price = request.json.get('price')\n"
            "if price <= 0:\n"
            "    raise ValueError('invalid price')\n"
            "total = price * quantity\n"
        )
        assert not matches_any(get_patterns(self.RULE), code)

    def test_js_price_and_quantity_used_unchecked_detected(self):
        code = (
            "const quantity = req.body.quantity;\n"
            "const price = req.body.price;\n"
            "const total = price * quantity;\n"
        )
        assert matches_any(get_patterns(self.RULE), code)

    def test_js_price_and_quantity_bounds_checked_not_detected(self):
        code = (
            "const quantity = req.body.quantity;\n"
            "if (quantity <= 0 || quantity > MAX_QUANTITY) { throw new Error('invalid quantity'); }\n"
            "const price = req.body.price;\n"
            "if (price <= 0) { throw new Error('invalid price'); }\n"
            "const total = price * quantity;\n"
        )
        assert not matches_any(get_patterns(self.RULE), code)

    def test_unrelated_variable_name_not_detected(self):
        code = "username = request.json.get('username')\ngreeting = 'hi ' + username\n"
        assert not matches_any(get_patterns(self.RULE), code)

    def test_adversarial_input_completes_fast(self):
        import time

        code = "no_match_line_of_code_here_at_all(a, b, c);\n" * 5000
        for pattern in get_patterns(self.RULE):
            start = time.perf_counter()
            re.search(pattern, code)
            elapsed = time.perf_counter() - start
            assert elapsed < 1.0, f"{self.RULE} pattern took {elapsed:.2f}s — ReDoS regression: {pattern!r}"
