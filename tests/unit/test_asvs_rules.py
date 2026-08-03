"""
ASVS 5.0.0 rule catalog tests.

Validates the 29 new ASVS-specific detection rules (added on top of the
original CWE rule catalog) against known-vulnerable and known-safe code
snippets, and confirms the whole-catalog coverage invariants hold across all
three ASVS levels (L1/L2/L3), in both directions:
  - every static_code control has a rule that maps to it
  - every rule's mapping points at a control_id that actually exists
  - every rule's mapping points at a control whose detection_strategy is
    static_code (anything else is silently inert in asvs_service.py)
  - every rule with no mapping documents why via a "note" field

Same `fires()` helper/pattern as test_vulnerability_detection.py — these are
pure regex-catalog tests, no pipeline/HTTP/database involved.
"""
import json
import re
from pathlib import Path

import pytest

QUERIES_PATH = Path(__file__).resolve().parents[2] / "queries" / "queries.json"
QUERIES = json.loads(QUERIES_PATH.read_text(encoding="utf-8"))

DATA_DIR = Path(__file__).resolve().parents[2] / "app" / "data"

CATALOG_PATH = DATA_DIR / "asvs_l1_controls.json"
CATALOG = json.loads(CATALOG_PATH.read_text(encoding="utf-8"))

# All three ASVS levels — used for the catalog-wide (not just L1) coverage checks.
# Loaded once at import time so every test in this module shares the same view.
ALL_LEVEL_CONTROLS = {
    lvl: json.loads((DATA_DIR / f"asvs_{lvl}_controls.json").read_text(encoding="utf-8"))
    for lvl in ("l1", "l2", "l3")
}
ALL_CONTROLS_BY_ID = {
    c["control_id"]: c for controls in ALL_LEVEL_CONTROLS.values() for c in controls
}

from app.domain.analysis.capability_checker import _CAPABILITY_CHECKS
CAPABILITY_CHECKED_CONTROLS = set(_CAPABILITY_CHECKS.keys())


def fires(rule_id: str, code: str) -> bool:
    patterns = QUERIES.get(rule_id, {}).get("regex_patterns", [])
    for pat in patterns:
        try:
            if re.search(pat, code):
                return True
        except re.error:
            pass
    return False


class TestUnsafeUrlProtocol:
    RULE = "UNSAFE_URL_PROTOCOL"
    VULNERABLE = [
        ("window.location = base + userInput", "concatenated location assignment"),
        ('el.href = "javascript:" + payload;', "javascript: scheme concatenation"),
    ]
    SAFE = [("window.location = '/dashboard'", "static redirect target")]

    @pytest.mark.parametrize("code,desc", VULNERABLE)
    def test_vulnerable(self, code, desc): assert fires(self.RULE, code), desc

    @pytest.mark.parametrize("code,desc", SAFE)
    def test_safe(self, code, desc): assert not fires(self.RULE, code), desc


class TestMissingHtmlSanitizer:
    RULE = "MISSING_HTML_SANITIZER"
    VULNERABLE = [("el.innerHTML = comment.body", "raw innerHTML assignment")]
    SAFE = [("el.textContent = comment.body", "textContent assignment")]

    @pytest.mark.parametrize("code,desc", VULNERABLE)
    def test_vulnerable(self, code, desc): assert fires(self.RULE, code), desc

    @pytest.mark.parametrize("code,desc", SAFE)
    def test_safe(self, code, desc): assert not fires(self.RULE, code), desc


class TestXxeUnsafeXmlParser:
    RULE = "XXE_UNSAFE_XML_PARSER"
    VULNERABLE = [("import xml.etree.ElementTree as ET", "stdlib ElementTree import")]
    SAFE = [("import defusedxml.ElementTree as ET", "defusedxml import")]

    @pytest.mark.parametrize("code,desc", VULNERABLE)
    def test_vulnerable(self, code, desc): assert fires(self.RULE, code), desc

    @pytest.mark.parametrize("code,desc", SAFE)
    def test_safe(self, code, desc): assert not fires(self.RULE, code), desc


class TestUnsafeDomRendering:
    RULE = "UNSAFE_DOM_RENDERING"
    VULNERABLE = [
        ("el.innerHTML = userComment;", "innerHTML assignment"),
        ("document.write(userInput);", "document.write"),
    ]
    SAFE = [("el.textContent = userComment;", "textContent assignment")]

    @pytest.mark.parametrize("code,desc", VULNERABLE)
    def test_vulnerable(self, code, desc): assert fires(self.RULE, code), desc

    @pytest.mark.parametrize("code,desc", SAFE)
    def test_safe(self, code, desc): assert not fires(self.RULE, code), desc


class TestMissingCsrfProtection:
    RULE = "MISSING_CSRF_PROTECTION"
    VULNERABLE = [("@csrf_exempt\ndef transfer(request): ...", "csrf_exempt decorator")]
    SAFE = [("@csrf_protect\ndef transfer(request): ...", "csrf_protect decorator")]

    @pytest.mark.parametrize("code,desc", VULNERABLE)
    def test_vulnerable(self, code, desc): assert fires(self.RULE, code), desc

    @pytest.mark.parametrize("code,desc", SAFE)
    def test_safe(self, code, desc): assert not fires(self.RULE, code), desc


class TestInsecureWebsocket:
    RULE = "INSECURE_WEBSOCKET"
    VULNERABLE = [("const ws = new WebSocket('ws://example.com/socket');", "ws:// scheme")]
    SAFE = [("const ws = new WebSocket('wss://example.com/socket');", "wss:// scheme")]

    @pytest.mark.parametrize("code,desc", VULNERABLE)
    def test_vulnerable(self, code, desc): assert fires(self.RULE, code), desc

    @pytest.mark.parametrize("code,desc", SAFE)
    def test_safe(self, code, desc): assert not fires(self.RULE, code), desc


class TestWeakPasswordMinLength:
    RULE = "WEAK_PASSWORD_MIN_LENGTH"
    VULNERABLE = [
        ("min_length = 4", "min_length below 8"),
        ('password: {\n  type: "password",\n  minLength: 6,\n},', "JS password schema, minLength 6"),
    ]
    SAFE = [
        ("min_length = 12", "min_length at recommended 12"),
        # Regression: this used to fire on ANY field's minLength, not just password's —
        # a product-name schema with minLength:3 was flagged as a weak password policy.
        ('name: {\n  type: "string",\n  minLength: 3,\n},', "unrelated field (product name), not password"),
        ('password: {\n  type: "password",\n  minLength: 8,\n},', "password minLength at the 8-char floor"),
    ]

    @pytest.mark.parametrize("code,desc", VULNERABLE)
    def test_vulnerable(self, code, desc): assert fires(self.RULE, code), desc

    @pytest.mark.parametrize("code,desc", SAFE)
    def test_safe(self, code, desc): assert not fires(self.RULE, code), desc


class TestOverlyRestrictivePasswordComposition:
    RULE = "OVERLY_RESTRICTIVE_PASSWORD_COMPOSITION"
    VULNERABLE = [
        (r"PASSWORD_REGEX = re.compile(r'(?=.*[a-z])(?=.*[A-Z])(?=.*\d)')", "composition regex"),
    ]
    SAFE = [("if len(password) < 8: raise ValueError('too short')", "length-only check")]

    @pytest.mark.parametrize("code,desc", VULNERABLE)
    def test_vulnerable(self, code, desc): assert fires(self.RULE, code), desc

    @pytest.mark.parametrize("code,desc", SAFE)
    def test_safe(self, code, desc): assert not fires(self.RULE, code), desc


class TestPasswordFieldNotMasked:
    RULE = "PASSWORD_FIELD_NOT_MASKED"
    VULNERABLE = [('<input type="text" id="password" name="password" />', "plaintext password field")]
    SAFE = [
        ('<input type="password" id="password" name="password" />', "masked password field"),
        # Regression: a compliant show/hide toggle uses a dynamic JSX type expression,
        # which the old regex (literal type="password" only) couldn't recognize.
        (
            "<input id=\"password\" type={showPassword ? 'text' : 'password'} autoComplete=\"current-password\" />",
            "JSX show/hide toggle, masked by default",
        ),
    ]

    @pytest.mark.parametrize("code,desc", VULNERABLE)
    def test_vulnerable(self, code, desc): assert fires(self.RULE, code), desc

    @pytest.mark.parametrize("code,desc", SAFE)
    def test_safe(self, code, desc): assert not fires(self.RULE, code), desc


class TestPasswordManagerBlocked:
    RULE = "PASSWORD_MANAGER_BLOCKED"
    VULNERABLE = [('<input type="password" autocomplete="off" />', "autocomplete disabled")]
    SAFE = [('<input type="password" autocomplete="current-password" />', "autocomplete allowed")]

    @pytest.mark.parametrize("code,desc", VULNERABLE)
    def test_vulnerable(self, code, desc): assert fires(self.RULE, code), desc

    @pytest.mark.parametrize("code,desc", SAFE)
    def test_safe(self, code, desc): assert not fires(self.RULE, code), desc


class TestPasswordModifiedBeforeVerify:
    RULE = "PASSWORD_MODIFIED_BEFORE_VERIFY"
    VULNERABLE = [("if password.lower() == stored: ...", "case-folded comparison")]
    SAFE = [("if password == stored: ...", "exact comparison")]

    @pytest.mark.parametrize("code,desc", VULNERABLE)
    def test_vulnerable(self, code, desc): assert fires(self.RULE, code), desc

    @pytest.mark.parametrize("code,desc", SAFE)
    def test_safe(self, code, desc): assert not fires(self.RULE, code), desc


class TestSecretQuestionsPresent:
    RULE = "SECRET_QUESTIONS_PRESENT"
    VULNERABLE = [("def get_secret_question(user): return user.security_question", "secret question field")]
    SAFE = [("def get_profile(user): return user.email", "unrelated profile field")]

    @pytest.mark.parametrize("code,desc", VULNERABLE)
    def test_vulnerable(self, code, desc): assert fires(self.RULE, code), desc

    @pytest.mark.parametrize("code,desc", SAFE)
    def test_safe(self, code, desc): assert not fires(self.RULE, code), desc


class TestSessionVerificationBypassed:
    RULE = "SESSION_VERIFICATION_BYPASSED"
    VULNERABLE = [("jwt.decode(token, verify=False)", "signature verification disabled")]
    SAFE = [('jwt.decode(token, key, algorithms=["HS256"])', "normal verified decode")]

    @pytest.mark.parametrize("code,desc", VULNERABLE)
    def test_vulnerable(self, code, desc): assert fires(self.RULE, code), desc

    @pytest.mark.parametrize("code,desc", SAFE)
    def test_safe(self, code, desc): assert not fires(self.RULE, code), desc


class TestStaticSessionSecret:
    RULE = "STATIC_SESSION_SECRET"
    VULNERABLE = [('SECRET_KEY = "dev-secret-please-change"', "hardcoded literal secret")]
    SAFE = [("SECRET_KEY = os.environ['SECRET_KEY']", "loaded from environment")]

    @pytest.mark.parametrize("code,desc", VULNERABLE)
    def test_vulnerable(self, code, desc): assert fires(self.RULE, code), desc

    @pytest.mark.parametrize("code,desc", SAFE)
    def test_safe(self, code, desc): assert not fires(self.RULE, code), desc


class TestJwtHeaderSourceNotValidated:
    RULE = "JWT_HEADER_SOURCE_NOT_VALIDATED"
    VULNERABLE = [("key = header.get('jku')", "jku header trusted directly")]
    SAFE = [("key = get_key_from_allowlisted_issuer(iss)", "key resolved via allowlist")]

    @pytest.mark.parametrize("code,desc", VULNERABLE)
    def test_vulnerable(self, code, desc): assert fires(self.RULE, code), desc

    @pytest.mark.parametrize("code,desc", SAFE)
    def test_safe(self, code, desc): assert not fires(self.RULE, code), desc


class TestJwtExpNbfNotVerified:
    RULE = "JWT_EXP_NBF_NOT_VERIFIED"
    VULNERABLE = [('jwt.decode(token, options={"verify_exp": False})', "verify_exp disabled")]
    SAFE = [('jwt.decode(token, key, algorithms=["HS256"])', "default verification")]

    @pytest.mark.parametrize("code,desc", VULNERABLE)
    def test_vulnerable(self, code, desc): assert fires(self.RULE, code), desc

    @pytest.mark.parametrize("code,desc", SAFE)
    def test_safe(self, code, desc): assert not fires(self.RULE, code), desc


class TestClientStorageNotClearedOnLogout:
    RULE = "CLIENT_STORAGE_NOT_CLEARED_ON_LOGOUT"
    VULNERABLE = [("function logout() { localStorage.removeItem('token'); }", "token cleared on logout")]

    @pytest.mark.parametrize("code,desc", VULNERABLE)
    def test_vulnerable(self, code, desc): assert fires(self.RULE, code), desc


# ── Catalog-level coverage checks ────────────────────────────────────────────

class TestAsvsCatalogCoverage:
    def test_all_70_controls_present(self):
        assert len(CATALOG) == 70

    def test_all_three_levels_load(self):
        # L1/L3 are both 70 controls (L3 restates every L1+L2 control at L3
        # scope); L2 is the larger superset (205). A count drifting to 0 here
        # means a level's JSON file went missing or empty, not that ASVS shrank.
        assert len(ALL_LEVEL_CONTROLS["l1"]) == 70
        assert len(ALL_LEVEL_CONTROLS["l2"]) == 205
        assert len(ALL_LEVEL_CONTROLS["l3"]) == 70

    def test_every_static_code_control_at_every_level_has_a_rule(self):
        # The old version of this test only checked L1 (70 controls) and only
        # in this direction. It would have missed a static_code control that's
        # L2/L3-only, and it says nothing about a rule claiming a control that
        # doesn't actually exist (a typo'd control_id) — see the reverse check
        # below and test_no_orphan_rules_without_a_documented_reason.
        #
        # Controls answered by CapabilityChecker (app/domain/analysis/capability_checker.py)
        # are a separate side-channel by design — they never go through the taint-engine
        # rule catalog, so they're legitimately absent from queries.json.
        all_static = {
            c["control_id"] for c in ALL_CONTROLS_BY_ID.values()
            if c["detection_strategy"] == "static_code"
        }
        covered = {cid for r in QUERIES.values() for cid in r.get("asvs_controls", [])}
        missing = all_static - covered - CAPABILITY_CHECKED_CONTROLS
        assert not missing, f"static_code controls with no rule coverage: {sorted(missing)}"

    def test_every_mapped_control_id_actually_exists(self):
        # The reverse of the missing-coverage check: a rule's asvs_controls
        # entry pointing at a control_id that's absent from all three catalogs
        # (typo, renamed control, wrong ASVS version) is exactly as inert as
        # having no mapping at all, but silently — nothing flags it without
        # this check.
        bogus = {
            (rule_id, cid)
            for rule_id, r in QUERIES.items()
            for cid in r.get("asvs_controls", [])
            if cid not in ALL_CONTROLS_BY_ID
        }
        assert not bogus, f"rules mapped to nonexistent control_ids: {sorted(bogus)}"

    def test_every_mapped_control_is_static_code_strategy(self):
        # A rule's asvs_controls entry is silently inert in asvs_service.py's
        # verdict policy unless that control's detection_strategy is also
        # "static_code" (see the module docstring there) — with one documented
        # exception: HYBRID_STATIC_ELIGIBLE_CONTROLS lists the handful of
        # config_inspection/dynamic_probe controls that asvs_service.py's
        # _compute_result *also* special-cases to accept a static rule match
        # for. Importing that constant (rather than hardcoding the exception
        # list here) keeps this test honest if that special-casing ever
        # changes. This is the general form of the check problem #3 added for
        # its 10 specific new mappings — it now guards the entire catalog,
        # including every rule that already had a mapping before this fix.
        from app.services.asvs_service import HYBRID_STATIC_ELIGIBLE_CONTROLS

        wrong_strategy = {
            (rule_id, cid, ALL_CONTROLS_BY_ID[cid]["detection_strategy"])
            for rule_id, r in QUERIES.items()
            for cid in r.get("asvs_controls", [])
            if cid in ALL_CONTROLS_BY_ID
            and ALL_CONTROLS_BY_ID[cid]["detection_strategy"] != "static_code"
            and cid not in HYBRID_STATIC_ELIGIBLE_CONTROLS
        }
        assert not wrong_strategy, f"rules mapped to a non-static_code control: {sorted(wrong_strategy)}"

    def test_no_orphan_rules_without_a_documented_reason(self):
        # Every rule must either move an ASVS verdict (asvs_controls) or
        # explain in a "note" why it can't (see problem #3's 9 documented
        # rules). A rule with neither is a silent gap nobody will notice —
        # exactly how 21 rules went unmapped in the first place.
        unexplained = {
            rid for rid, r in QUERIES.items()
            if not r.get("asvs_controls") and "note" not in r
        }
        assert not unexplained, f"rules with no ASVS mapping and no explanatory note: {sorted(unexplained)}"

    def test_relabeled_rules_still_have_original_cwe_metadata(self):
        # Relabeling must be additive — the original CWE catalog fields stay intact.
        sql_rule = QUERIES["SQL_INJECTION"]
        assert sql_rule["cwe"] == "CWE-89"
        assert sql_rule["asvs_controls"] == ["V1.2.4"]


# ── Regression: 21 rules with no ASVS mapping ────────────────────────────────
# A rule's asvs_controls entry is silently inert in asvs_service.py's verdict
# policy unless that control's detection_strategy is also "static_code" — that
# general invariant is now covered catalog-wide by
# TestAsvsCatalogCoverage.test_every_mapped_control_is_static_code_strategy
# above. This class just pins the specific mapping values problem #3 added.

class TestNewlyMappedRulesTargetStaticCodeControls:
    NEW_MAPPINGS = {
        "NOSQL_INJECTION": ["V1.2.4"],
        "GRAPHQL_INJECTION": ["V1.2.4"],
        "INFORMATION_EXPOSURE_ERROR": ["V16.5.1"],
        "SENSITIVE_LOGGING": ["V16.2.5"],
        "HTTP_ERROR_HANDLER_SILENT": ["V16.3.4"],
        "REMOTE_SCRIPT_EXECUTION": ["V1.3.2"],
        "AWS_METADATA_ACCESS": ["V1.3.6"],
        "GCP_METADATA_ACCESS": ["V1.3.6"],
        "AZURE_METADATA_ACCESS": ["V1.3.6"],
        "IMDS_TOKENLESS": ["V1.3.6"],
    }

    @pytest.mark.parametrize("rule_id,expected_controls", list(NEW_MAPPINGS.items()))
    def test_rule_carries_expected_mapping(self, rule_id, expected_controls):
        assert QUERIES[rule_id]["asvs_controls"] == expected_controls


class TestGenuinelyUnmappableRulesAreDocumented:
    # These rules have no static_code-strategy ASVS control to attach to. They
    # must stay asvs_controls-free (an empty/absent mapping is correct here,
    # not a bug) and carry a "note" explaining why, so nobody "fixes" them
    # into a dead tag later.
    UNMAPPABLE_RULE_IDS = [
        "BUFFER_OVERFLOW",
        "CLICKJACKING_NO_HEADER",
        "LOGGING_DISABLED",
        "UNTRUSTED_BINARY_EXEC",
        "VULNERABLE_COMPONENTS",
        "A06_NPM_RESOLVED_HTTP",
        "A06_NPM_REGISTRY_HTTP",
        "A06_PYTHON_VCS_DEP",
        "A06_PIPFILE_VCS",
    ]

    @pytest.mark.parametrize("rule_id", UNMAPPABLE_RULE_IDS)
    def test_rule_has_explanatory_note_and_no_asvs_controls(self, rule_id):
        rule = QUERIES[rule_id]
        assert not rule.get("asvs_controls")
        assert rule.get("note"), f"{rule_id} must document why it's unmapped"


# ── Backfilled regression coverage: 10 highest severity/fundamentality rules ──
# 59 of 202 catalog rules had zero regression protection — a rule could regress
# to always-false (or the reverse, a runaway false-positive) and nothing would
# catch it. This is exactly the class of gap that let #2's RACE_CONDITION_FILE
# duplicate and #3's 21 unmapped rules go unnoticed for as long as they did.
# These 10 are hand-picked by severity/fundamentality; the remaining 44
# regex-backed rules follow below as a mechanical second pass, and the 4
# pure-taint rules (no regex_patterns at all — see the last section) get a
# config-integrity check instead of a fires() test, since fires() can never
# return True for them regardless of input.


class TestXss:
    def test_inner_html_assignment_detected(self):
        assert fires("XSS", "el.innerHTML = userInput;")

    def test_text_content_assignment_not_detected(self):
        assert not fires("XSS", "el.textContent = userInput;")


class TestCodeInjection:
    def test_eval_of_user_input_detected(self):
        assert fires("CODE_INJECTION", "result = eval(user_input)")

    def test_literal_eval_not_detected(self):
        assert not fires("CODE_INJECTION", "result = ast.literal_eval(user_input)")


class TestJwtNoneAlgorithm:
    def test_none_algorithm_accepted_detected(self):
        code = 'jwt.decode(token, options={"verify_signature": False}, algorithms=["none"])'
        assert fires("JWT_NONE_ALGORITHM", code)

    def test_signed_algorithm_not_detected(self):
        assert not fires("JWT_NONE_ALGORITHM", 'jwt.decode(token, key, algorithms=["HS256"])')


class TestJwtWeakSecret:
    def test_short_hardcoded_secret_detected(self):
        assert fires("JWT_WEAK_SECRET", 'token = jwt.encode(payload, "secret123")')

    def test_secret_loaded_from_env_not_detected(self):
        code = 'token = jwt.encode(payload, os.environ["JWT_SIGNING_KEY_32_BYTES_MIN"])'
        assert not fires("JWT_WEAK_SECRET", code)


class TestDefaultCredentials:
    def test_admin_admin_pair_detected(self):
        assert fires("DEFAULT_CREDENTIALS", 'admin_password = "admin"')

    def test_env_sourced_password_not_detected(self):
        assert not fires("DEFAULT_CREDENTIALS", 'admin_password = os.environ["ADMIN_PASSWORD"]')


class TestSensitiveDataExposure:
    def test_password_field_in_jsonify_detected(self):
        code = "return jsonify(user_id=uid, password=user.password)"
        assert fires("SENSITIVE_DATA_EXPOSURE", code)

    def test_non_sensitive_fields_not_detected(self):
        code = "return jsonify(user_id=uid, username=user.username)"
        assert not fires("SENSITIVE_DATA_EXPOSURE", code)


class TestVulnerableComponents:
    def test_wildcard_version_range_detected(self):
        assert fires("VULNERABLE_COMPONENTS", '"lodash": "*"')

    def test_pinned_version_not_detected(self):
        assert not fires("VULNERABLE_COMPONENTS", '"lodash": "^4.17.21"')


class TestNosqlInjection:
    def test_where_operator_with_raw_input_detected(self):
        assert fires("NOSQL_INJECTION", "db.users.find({$where: userInput})")

    def test_plain_field_match_not_detected(self):
        assert not fires("NOSQL_INJECTION", 'db.users.find({name: "bob"})')


class TestHttpRequestSmuggling:
    def test_chunked_transfer_encoding_header_detected(self):
        assert fires("HTTP_REQUEST_SMUGGLING", 'headers["Transfer-Encoding"] = "chunked"')

    def test_unrelated_header_not_detected(self):
        assert not fires("HTTP_REQUEST_SMUGGLING", 'headers["Content-Type"] = "application/json"')


class TestBrokenAccessControl:
    def test_user_id_taken_from_request_args_detected(self):
        assert fires("BROKEN_ACCESS_CONTROL", 'user_id = request.args.get("user_id")')

    def test_user_id_from_authenticated_session_not_detected(self):
        assert not fires("BROKEN_ACCESS_CONTROL", "user_id = current_user.id")


# ── Pure-taint rules: no regex_patterns, fires() can never test them ──────────
# BUFFER_OVERFLOW, GRAPHQL_INJECTION, PROTOTYPE_POLLUTION, and
# UNRESTRICTED_FILE_UPLOAD are DFG_FLOW-only (sources -> sinks, evaluated
# against a real code-property graph by QueryExecutor, not by regex_search on
# raw text). fires() reads only regex_patterns, so `assert not fires(...)`
# would pass trivially for these regardless of how vulnerable the input is —
# a fake-green test that asserts nothing. The honest regression check for a
# pure-taint rule is that its taint-flow configuration itself hasn't been
# silently emptied out (the actual way these rules go dark).
class TestPureTaintRulesRetainSourceSinkConfig:
    RULE_IDS = [
        "BUFFER_OVERFLOW",
        "GRAPHQL_INJECTION",
        "PROTOTYPE_POLLUTION",
        "UNRESTRICTED_FILE_UPLOAD",
    ]

    def test_no_regex_patterns_confirms_these_are_taint_only(self):
        # Documents *why* they're excluded from the fires()-based tests above —
        # if a future edit gives one of these rules regex_patterns, it should
        # graduate into the fires()-tested set, not stay here untested.
        for rule_id in self.RULE_IDS:
            assert not QUERIES[rule_id].get("regex_patterns"), (
                f"{rule_id} now has regex_patterns — give it a fires()-based "
                f"test like the other backfilled rules instead of leaving it here"
            )

    def test_dfg_flow_taint_config_present(self):
        for rule_id in self.RULE_IDS:
            rule = QUERIES[rule_id]
            assert rule.get("sources"), f"{rule_id} has no sources"
            assert rule.get("sinks"), f"{rule_id} has no sinks"
            assert "DFG_FLOW" in (rule.get("patterns") or []), f"{rule_id} is missing DFG_FLOW"


# ── Backfilled regression coverage: 44 previously-untested rules ─────────────
# Mechanical second pass (see problem #5's 10 hand-picked rules above for the
# fully-reasoned first pass). Every (vulnerable, safe) / (marker-present,
# marker-absent) pair below was verified against the real regex_patterns in
# queries.json before being committed here — several initial drafts didn't
# actually fire as expected (a python-esque `except ... : return str(e)`
# needing the literal `str(e)` shape, JS_JSON_INJECTION's pattern only matching
# an opening quote glued directly to `+`, etc.) and were corrected against the
# actual engine rather than assumed.

class TestA06NpmRegistryHttp:
    def test_vulnerable_detected(self):
        assert fires('A06_NPM_REGISTRY_HTTP', 'registry=http://registry.npmjs.org/')

    def test_safe_not_detected(self):
        assert not fires('A06_NPM_REGISTRY_HTTP', 'registry=https://registry.npmjs.org/')


class TestA06NpmResolvedHttp:
    def test_vulnerable_detected(self):
        assert fires('A06_NPM_RESOLVED_HTTP', '"resolved": "http://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz"')

    def test_safe_not_detected(self):
        assert not fires('A06_NPM_RESOLVED_HTTP', '"resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz"')


class TestA06PipfileVcs:
    def test_vulnerable_detected(self):
        assert fires('A06_PIPFILE_VCS', 'mypkg = {git = "https://github.com/example/mypkg.git"}')

    def test_safe_not_detected(self):
        assert not fires('A06_PIPFILE_VCS', 'mypkg = "==1.2.3"')


class TestA06PythonVcsDep:
    def test_vulnerable_detected(self):
        assert fires('A06_PYTHON_VCS_DEP', '-e git+https://github.com/example/mypkg.git#egg=mypkg')

    def test_safe_not_detected(self):
        assert not fires('A06_PYTHON_VCS_DEP', 'mypkg==1.2.3')


class TestAdminRouteUnprotected:
    def test_vulnerable_detected(self):
        assert fires('ADMIN_ROUTE_UNPROTECTED', '@app.route("/admin/users")\ndef list_users():\n    pass')

    def test_safe_not_detected(self):
        assert not fires('ADMIN_ROUTE_UNPROTECTED', '@app.route("/dashboard")\ndef dashboard():\n    pass')


class TestAwsMetadataAccess:
    def test_vulnerable_detected(self):
        assert fires('AWS_METADATA_ACCESS', 'requests.get("http://169.254.169.254/latest/meta-data/")')

    def test_safe_not_detected(self):
        assert not fires('AWS_METADATA_ACCESS', 'requests.get("https://api.example.com/data")')


class TestAzureMetadataAccess:
    def test_vulnerable_detected(self):
        assert fires('AZURE_METADATA_ACCESS', 'requests.get("http://169.254.169.254/metadata/instance?api-version=2021-02-01")')

    def test_safe_not_detected(self):
        assert not fires('AZURE_METADATA_ACCESS', 'requests.get("https://api.example.com/data")')


class TestCleartextTransmission:
    def test_vulnerable_detected(self):
        assert fires('CLEARTEXT_TRANSMISSION', 'requests.post("http://api.example.com/login", data=creds)')

    def test_safe_not_detected(self):
        assert not fires('CLEARTEXT_TRANSMISSION', 'requests.post("https://api.example.com/login", data=creds)')


class TestClickjackingNoHeader:
    def test_vulnerable_detected(self):
        assert fires('CLICKJACKING_NO_HEADER', 'headers = {"X-Frame-Options": "ALLOWALL"}')

    def test_safe_not_detected(self):
        assert not fires('CLICKJACKING_NO_HEADER', 'headers = {"X-Frame-Options": "DENY"}')


class TestClientSideAuthorizationOnly:
    def test_vulnerable_detected(self):
        assert fires('CLIENT_SIDE_AUTHORIZATION_ONLY', '<button v-if="isAdmin">Delete</button>')

    def test_safe_not_detected(self):
        assert not fires('CLIENT_SIDE_AUTHORIZATION_ONLY', '<button v-if="canDeletePost">Delete</button>')


class TestClientSideOnlyValidation:
    def test_vulnerable_detected(self):
        assert fires('CLIENT_SIDE_ONLY_VALIDATION', '<input type="text" pattern="[0-9]{3}-[0-9]{4}" />')

    def test_safe_not_detected(self):
        assert not fires('CLIENT_SIDE_ONLY_VALIDATION', '<input type="text" />')


class TestCookieHostPrefixMissing:
    def test_vulnerable_detected(self):
        assert fires('COOKIE_HOST_PREFIX_MISSING', "response.set_cookie('session_id', token)")

    def test_safe_not_detected(self):
        assert not fires('COOKIE_HOST_PREFIX_MISSING', "response.set_cookie('__Host-session_id', token)")


class TestCookieMissingSamesite:
    def test_vulnerable_detected(self):
        assert fires('COOKIE_MISSING_SAMESITE', "response.set_cookie('session', token)")

    def test_safe_not_detected(self):
        assert not fires('COOKIE_MISSING_SAMESITE', "response.set_cookie('session', token, samesite='Strict')")


class TestCorsMisconfiguration:
    def test_vulnerable_detected(self):
        assert fires('CORS_MISCONFIGURATION', "response.headers['Access-Control-Allow-Origin'] = '*'")

    def test_safe_not_detected(self):
        assert not fires('CORS_MISCONFIGURATION', "response.headers['Access-Control-Allow-Origin'] = 'https://trusted.example.com'")


class TestCorsPreflightBypass:
    def test_vulnerable_detected(self):
        assert fires('CORS_PREFLIGHT_BYPASS', 'CORSMiddleware(allow_headers=["*"])')

    def test_safe_not_detected(self):
        assert not fires('CORS_PREFLIGHT_BYPASS', 'CORSMiddleware(allow_headers=["Content-Type", "Authorization"])')


class TestDebugModeEnabled:
    def test_vulnerable_detected(self):
        assert fires('DEBUG_MODE_ENABLED', 'DEBUG = True')

    def test_safe_not_detected(self):
        assert not fires('DEBUG_MODE_ENABLED', 'DEBUG = False')


class TestDeprecatedClientTech:
    def test_vulnerable_detected(self):
        assert fires('DEPRECATED_CLIENT_TECH', 'var obj = new ActiveXObject("Msxml2.XMLHTTP");')

    def test_safe_not_detected(self):
        assert not fires('DEPRECATED_CLIENT_TECH', 'var obj = new XMLHttpRequest();')


class TestGcpMetadataAccess:
    def test_vulnerable_detected(self):
        assert fires('GCP_METADATA_ACCESS', 'requests.get("http://metadata.google.internal/computeMetadata/v1/")')

    def test_safe_not_detected(self):
        assert not fires('GCP_METADATA_ACCESS', 'requests.get("https://api.example.com/data")')


class TestGraphqlNoCostLimit:
    def test_vulnerable_detected(self):
        assert fires('GRAPHQL_NO_COST_LIMIT', 'new ApolloServer({ typeDefs, resolvers })')

    def test_safe_not_detected(self):
        assert not fires('GRAPHQL_NO_COST_LIMIT', 'new ApolloServer({ typeDefs, resolvers, validationRules: [depthLimit(5)] })')


class TestHttpErrorHandlerSilent:
    def test_vulnerable_detected(self):
        assert fires('HTTP_ERROR_HANDLER_SILENT', 'app.use((err, req, res, next) => { res.status(500).send(error); });')

    def test_safe_not_detected(self):
        assert not fires('HTTP_ERROR_HANDLER_SILENT', '@app.route("/health")\ndef health():\n    return "ok"')


class TestImdsTokenless:
    def test_vulnerable_detected(self):
        assert fires('IMDS_TOKENLESS', 'requests.get(url, headers={"X-aws-ec2-metadata-token": token})')

    def test_safe_not_detected(self):
        assert not fires('IMDS_TOKENLESS', 'requests.get("https://api.example.com/data")')


class TestInitialPasswordNotExpiring:
    # INITIAL_PASSWORD_NOT_EXPIRING is a compliant-polarity marker: a match is evidence the
    # control IS satisfied, not a vulnerability.
    def test_marker_present_detected(self):
        assert fires('INITIAL_PASSWORD_NOT_EXPIRING', 'user.must_change_password = True')

    def test_marker_absent_not_detected(self):
        assert not fires('INITIAL_PASSWORD_NOT_EXPIRING', 'user.last_login = timezone.now()')


class TestInputValidationMissing:
    def test_vulnerable_detected(self):
        assert fires('INPUT_VALIDATION_MISSING', 'user_id = request.args["user_id"]')

    def test_safe_not_detected(self):
        assert not fires('INPUT_VALIDATION_MISSING', "user_id = UserIdSchema().load(request.args)['user_id']")


class TestInsufficientEntropy:
    def test_vulnerable_detected(self):
        assert fires('INSUFFICIENT_ENTROPY', 'reset_code = str(random.randint(100000, 999999))')

    def test_safe_not_detected(self):
        assert not fires('INSUFFICIENT_ENTROPY', 'reset_code = secrets.token_urlsafe(32)')


class TestJsJsonInjection:
    def test_vulnerable_detected(self):
        assert fires('JS_JSON_INJECTION', "const data = JSON.parse('+ userInput);")

    def test_safe_not_detected(self):
        assert not fires('JS_JSON_INJECTION', 'const data = JSON.parse(rawInput);')


class TestJwtTokenTypeNotValidated:
    def test_vulnerable_detected(self):
        assert fires('JWT_TOKEN_TYPE_NOT_VALIDATED', 'claims = jwt.decode(token, key)\nif claims.get("scope"):\n    allow()')

    def test_safe_not_detected(self):
        assert not fires('JWT_TOKEN_TYPE_NOT_VALIDATED', 'claims = jwt.decode(token, key)\nif claims.get("token_type") == "access":\n    if claims.get("scope"):\n        allow()')


class TestLoggingDisabled:
    def test_vulnerable_detected(self):
        assert fires('LOGGING_DISABLED', 'logging.disable(logging.CRITICAL)')

    def test_safe_not_detected(self):
        assert not fires('LOGGING_DISABLED', 'logging.basicConfig(level=logging.INFO)')


class TestMissingRateLimiting:
    # MISSING_RATE_LIMITING is a compliant-polarity marker: a match is evidence the
    # control IS satisfied, not a vulnerability.
    def test_marker_present_detected(self):
        assert fires('MISSING_RATE_LIMITING', "@limiter.limit('5/minute')\n@app.route('/login', methods=['POST'])\ndef login():\n    pass")

    def test_marker_absent_not_detected(self):
        assert not fires('MISSING_RATE_LIMITING', "@app.route('/login', methods=['POST'])\ndef login():\n    pass")


class TestPasswordChangeCurrentCheck:
    # PASSWORD_CHANGE_CURRENT_CHECK is a compliant-polarity marker: a match is evidence the
    # control IS satisfied, not a vulnerability.
    def test_marker_present_detected(self):
        assert fires('PASSWORD_CHANGE_CURRENT_CHECK', 'if not check_password(user, old_password): abort(403)')

    def test_marker_absent_not_detected(self):
        assert not fires('PASSWORD_CHANGE_CURRENT_CHECK', 'def change_password(user, new_pw): user.password = hash(new_pw)')


class TestPasswordChangeEndpoint:
    # PASSWORD_CHANGE_ENDPOINT is a compliant-polarity marker: a match is evidence the
    # control IS satisfied, not a vulnerability.
    def test_marker_present_detected(self):
        assert fires('PASSWORD_CHANGE_ENDPOINT', '@app.route("/account/change-password", methods=["POST"])')

    def test_marker_absent_not_detected(self):
        assert not fires('PASSWORD_CHANGE_ENDPOINT', '@app.route("/account/profile", methods=["GET"])')


class TestPasswordInUrl:
    def test_vulnerable_detected(self):
        assert fires('PASSWORD_IN_URL', "password = request.args.get('password')")

    def test_safe_not_detected(self):
        assert not fires('PASSWORD_IN_URL', "password = request.form.get('password')")


class TestPostmessageOriginNotChecked:
    def test_vulnerable_detected(self):
        assert fires('POSTMESSAGE_ORIGIN_NOT_CHECKED', "window.addEventListener('message', function(e) { handle(e.data); })")

    def test_safe_not_detected(self):
        assert not fires('POSTMESSAGE_ORIGIN_NOT_CHECKED', "window.addEventListener('message', function(e) { if (e.origin !== TRUSTED) return; handle(e.data); })")


class TestRegexDos:
    def test_vulnerable_detected(self):
        assert fires('REGEX_DOS', "const re = new RegExp('(' + req.query.pattern + ')+');")

    def test_safe_not_detected(self):
        assert not fires('REGEX_DOS', 'const re = /^[a-z]+$/;')


class TestRemoteScriptExecution:
    def test_vulnerable_detected(self):
        assert fires('REMOTE_SCRIPT_EXECUTION', 'curl https://example.com/install.sh | bash')

    def test_safe_not_detected(self):
        assert not fires('REMOTE_SCRIPT_EXECUTION', 'curl -o install.sh https://example.com/install.sh')


class TestSensitiveDataInBrowserStorage:
    def test_vulnerable_detected(self):
        assert fires('SENSITIVE_DATA_IN_BROWSER_STORAGE', "localStorage.setItem('api_key', key)")

    def test_safe_not_detected(self):
        assert not fires('SENSITIVE_DATA_IN_BROWSER_STORAGE', "sessionStorage.setItem('session_token', token)")


class TestSensitiveLogging:
    def test_vulnerable_detected(self):
        assert fires('SENSITIVE_LOGGING', 'logger.info("login attempt" + " password=" + password)')

    def test_safe_not_detected(self):
        assert not fires('SENSITIVE_LOGGING', 'logger.info("login attempt for user %s", username)')


class TestSessionsNotTerminatedOnAccountDisable:
    # SESSIONS_NOT_TERMINATED_ON_ACCOUNT_DISABLE is a compliant-polarity marker: a match is evidence the
    # control IS satisfied, not a vulnerability.
    def test_marker_present_detected(self):
        assert fires('SESSIONS_NOT_TERMINATED_ON_ACCOUNT_DISABLE', 'def disable_account(user):\n    user.is_active = False')

    def test_marker_absent_not_detected(self):
        assert not fires('SESSIONS_NOT_TERMINATED_ON_ACCOUNT_DISABLE', "def disable_account(user):\n    user.status = 'disabled'")


class TestSessionNotInvalidatedOnLogout:
    # SESSION_NOT_INVALIDATED_ON_LOGOUT is a compliant-polarity marker: a match is evidence the
    # control IS satisfied, not a vulnerability.
    def test_marker_present_detected(self):
        assert fires('SESSION_NOT_INVALIDATED_ON_LOGOUT', 'def logout(request):\n    request.session.clear()')

    def test_marker_absent_not_detected(self):
        assert not fires('SESSION_NOT_INVALIDATED_ON_LOGOUT', "def logout(request):\n    return redirect('/login')")


class TestStackTraceExposedToClient:
    def test_vulnerable_detected(self):
        assert fires('STACK_TRACE_EXPOSED_TO_CLIENT', 'except Exception as e:\n    return str(e)')

    def test_safe_not_detected(self):
        assert not fires('STACK_TRACE_EXPOSED_TO_CLIENT', 'except Exception as e:\n    logger.exception(e)\n    return "internal error"')


class TestUnauthenticatedEncryptionMode:
    def test_vulnerable_detected(self):
        assert fires('UNAUTHENTICATED_ENCRYPTION_MODE', 'cipher = AES.new(key, AES.MODE_CBC, iv)')

    def test_safe_not_detected(self):
        assert not fires('UNAUTHENTICATED_ENCRYPTION_MODE', 'cipher = AES.new(key, AES.MODE_GCM, nonce)')


class TestUnsafeDownloadFilenameEncoding:
    def test_vulnerable_detected(self):
        assert fires('UNSAFE_DOWNLOAD_FILENAME_ENCODING', 'headers["Content-Disposition"] = f"attachment; filename={user_filename}"')

    def test_safe_not_detected(self):
        assert not fires('UNSAFE_DOWNLOAD_FILENAME_ENCODING', 'headers["Content-Disposition"] = build_content_disposition(user_filename)')


class TestUnsafeHttpMethodForSensitiveAction:
    def test_vulnerable_detected(self):
        assert fires('UNSAFE_HTTP_METHOD_FOR_SENSITIVE_ACTION', "router.get('/users/:id/delete', deleteUser);")

    def test_safe_not_detected(self):
        assert not fires('UNSAFE_HTTP_METHOD_FOR_SENSITIVE_ACTION', "router.delete('/users/:id', deleteUser);")


class TestUntrustedBinaryExec:
    def test_vulnerable_detected(self):
        assert fires('UNTRUSTED_BINARY_EXEC', "download(url, 'install.bin'); exec('./install.bin');")

    def test_safe_not_detected(self):
        assert not fires('UNTRUSTED_BINARY_EXEC', "download(url, 'install.bin'); verify_signature('install.bin');")


class TestWebsocketOriginNotChecked:
    def test_vulnerable_detected(self):
        assert fires('WEBSOCKET_ORIGIN_NOT_CHECKED', 'def check_origin(self, origin):\n    return True')

    def test_safe_not_detected(self):
        assert not fires('WEBSOCKET_ORIGIN_NOT_CHECKED', 'def check_origin(self, origin):\n    return origin in ALLOWED_ORIGINS')
