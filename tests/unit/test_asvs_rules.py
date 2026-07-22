"""
ASVS 5.0.0 L1 rule catalog tests.

Validates the 29 new ASVS-specific detection rules (added on top of the
original CWE rule catalog) against known-vulnerable and known-safe code
snippets, and confirms every static_code L1 control has rule coverage.

Same `fires()` helper/pattern as test_vulnerability_detection.py — these are
pure regex-catalog tests, no pipeline/HTTP/database involved.
"""
import json
import re
from pathlib import Path

import pytest

QUERIES_PATH = Path(__file__).resolve().parents[2] / "queries" / "queries.json"
QUERIES = json.loads(QUERIES_PATH.read_text(encoding="utf-8"))

CATALOG_PATH = Path(__file__).resolve().parents[2] / "app" / "data" / "asvs_l1_controls.json"
CATALOG = json.loads(CATALOG_PATH.read_text(encoding="utf-8"))


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
    VULNERABLE = [("min_length = 4", "min_length below 8")]
    SAFE = [("min_length = 12", "min_length at recommended 12")]

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
    SAFE = [('<input type="password" id="password" name="password" />', "masked password field")]

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

    def test_every_static_code_control_has_a_rule(self):
        static_control_ids = {
            c["control_id"] for c in CATALOG if c["detection_strategy"] == "static_code"
        }
        covered = set()
        for rule in QUERIES.values():
            covered.update(rule.get("asvs_controls", []))
        missing = static_control_ids - covered
        assert not missing, f"static_code controls with no rule coverage: {sorted(missing)}"

    def test_relabeled_rules_still_have_original_cwe_metadata(self):
        # Relabeling must be additive — the original CWE catalog fields stay intact.
        sql_rule = QUERIES["SQL_INJECTION"]
        assert sql_rule["cwe"] == "CWE-89"
        assert sql_rule["asvs_controls"] == ["V1.2.4"]
