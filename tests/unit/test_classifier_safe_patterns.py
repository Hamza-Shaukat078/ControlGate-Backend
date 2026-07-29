"""
SliceClassifier._code_is_safe() regression tests — the safe-pattern overrides
that stop a static/LLM-fallback match from being reported as a confirmed
finding when the code actually shows a guard/validation already in place.
"""
from semantic_engine.classifier.classifier import SliceClassifier


def _classifier():
    return SliceClassifier(enable_llm=False)


class TestOwnershipGuardRecognizedAcrossRules:
    """
    Regression: this ownership/role-guard check only applied to the
    "PATH_DISCOVERY" rule_id. A real Express/Node ownership check —
    `order.user_id !== req.user.userId` / `req.user.userId !== resourceUserId` —
    was invisible to BROKEN_ACCESS_CONTROL (IDOR) and INPUT_VALIDATION_MISSING,
    so a correctly-guarded endpoint was still reported as a vulnerability.
    """

    ORDER_CONTROLLER_SNIPPET = (
        "const order = await orderModel.findById(req.params.id);\n"
        "if (req.user.role !== ROLES.ADMIN && order.user_id !== req.user.userId) {\n"
        "  throw new ValidationError('Access denied');\n"
        "}"
    )
    RBAC_SNIPPET = (
        "const resourceUserId = req.params[userIdParam] || req.query[userIdParam];\n"
        "if (req.user.userId !== resourceUserId) {\n"
        "  logAuthzFailure(req.user.userId, req.originalUrl, req.method, {});\n"
        "}"
    )
    NO_GUARD_SNIPPET = "const order = await orderModel.findById(req.params.id);"

    def test_broken_access_control_recognizes_ownership_guard(self):
        assert _classifier()._code_is_safe("BROKEN_ACCESS_CONTROL", self.ORDER_CONTROLLER_SNIPPET)

    def test_input_validation_missing_recognizes_ownership_guard(self):
        assert _classifier()._code_is_safe("INPUT_VALIDATION_MISSING", self.RBAC_SNIPPET)

    def test_path_discovery_still_recognizes_snake_case_guard(self):
        # Non-regression: the original Flask/Django-style pattern this was built for.
        assert _classifier()._code_is_safe("PATH_DISCOVERY", "if user_id != current_user.id: abort(403)")

    def test_no_guard_present_is_not_marked_safe(self):
        assert not _classifier()._code_is_safe("BROKEN_ACCESS_CONTROL", self.NO_GUARD_SNIPPET)
        assert not _classifier()._code_is_safe("INPUT_VALIDATION_MISSING", self.NO_GUARD_SNIPPET)


class TestReDoSSafePatternExtractsActualRegex:
    """
    Regression: the ReDoS/REGEX_DOS safe-pattern check used to test the first
    quoted string found anywhere in the snippet for nested quantifiers. An
    unrelated route path like '/validate' sitting near a genuinely catastrophic
    regex would be graded instead of the regex itself, falsely marking a
    vulnerable snippet as safe. The fix anchors extraction to the actual regex
    API call (re.compile/match/search/fullmatch, new RegExp, or /pattern/.test).
    """

    CATASTROPHIC_PY = (
        '@app.route("/validate")\n'
        'def validate():\n'
        '    pattern = re.compile(r"(a+)+$")\n'
        '    if pattern.match(user_input):\n'
        '        return "ok"\n'
    )
    SAFE_PY = (
        '@app.route("/validate")\n'
        'def validate():\n'
        '    pattern = re.compile(r"^[a-z0-9]+$")\n'
        '    if pattern.match(user_input):\n'
        '        return "ok"\n'
    )
    CATASTROPHIC_JS_NEW_REGEXP = (
        'app.post("/validate", (req,res) => { '
        'const re = new RegExp("(a+)+$"); re.test(req.body.x); })'
    )
    CATASTROPHIC_JS_LITERAL_TEST = (
        'app.post("/validate", (req,res) => { /(a+)+$/.test(req.body.x); })'
    )
    SAFE_JS_LITERAL_TEST = (
        'app.post("/validate", (req,res) => { /^[a-z0-9]+$/.test(req.body.x); })'
    )
    NO_REGEX_CALL_AT_ALL = '@app.route("/validate")\ndef validate():\n    return "ok"'

    def test_catastrophic_regex_near_route_string_not_marked_safe(self):
        assert not _classifier()._code_is_safe("REGEX_DOS", self.CATASTROPHIC_PY)
        assert not _classifier()._code_is_safe("PATH_DISCOVERY", self.CATASTROPHIC_PY)

    def test_safe_regex_near_same_route_string_is_marked_safe(self):
        assert _classifier()._code_is_safe("REGEX_DOS", self.SAFE_PY)

    def test_js_new_regexp_catastrophic_not_marked_safe(self):
        assert not _classifier()._code_is_safe("REGEX_DOS", self.CATASTROPHIC_JS_NEW_REGEXP)

    def test_js_literal_test_catastrophic_not_marked_safe(self):
        assert not _classifier()._code_is_safe("REGEX_DOS", self.CATASTROPHIC_JS_LITERAL_TEST)

    def test_js_literal_test_safe_is_marked_safe(self):
        assert _classifier()._code_is_safe("REGEX_DOS", self.SAFE_JS_LITERAL_TEST)

    def test_no_regex_construction_present_not_marked_safe(self):
        assert not _classifier()._code_is_safe("REGEX_DOS", self.NO_REGEX_CALL_AT_ALL)


class TestSSRFRelativeBrowserFetchIsSafe:
    PRODUCTS_SNIPPET = (
        'const url = category ? `/api/products?category=${category}` : "/api/products";\n'
        "fetch(url)\n"
        "  .then((r) => r.json())"
    )
    ADMIN_SNIPPET = (
        'const url = isEdit ? `/api/admin/products/${form.id}` : "/api/admin/products";\n'
        'const res = await fetch(url, { method, headers: { "Content-Type": "application/json" } });'
    )
    ABSOLUTE_URL_SNIPPET = (
        "const url = req.query.url;\n"
        "await fetch(url);"
    )

    def test_relative_product_api_fetch_is_not_ssrf(self):
        assert _classifier()._code_is_safe("SSRF", self.PRODUCTS_SNIPPET)

    def test_relative_admin_api_fetch_is_not_ssrf(self):
        assert _classifier()._code_is_safe("SSRF", self.ADMIN_SNIPPET)

    def test_request_controlled_absolute_fetch_is_not_marked_safe(self):
        assert not _classifier()._code_is_safe("SSRF", self.ABSOLUTE_URL_SNIPPET)


class TestVisualRandomnessIsSafe:
    VISUAL_SNIPPET = (
        "alphaSpeed: (Math.random() * 0.6 + 0.2) * (Math.random() > 0.5 ? 1 : -1),\n"
        "vx: (Math.random() - 0.5) * speed,\n"
        "vy: (Math.random() - 0.5) * speed"
    )
    UPLOAD_FILENAME_SNIPPET = (
        "const filename = `${Date.now()}-${Math.random().toString(36).slice(2)}${ext}`;"
    )

    def test_particle_animation_randomness_is_not_security_randomness(self):
        assert _classifier()._code_is_safe("INSECURE_RANDOM", self.VISUAL_SNIPPET)

    def test_upload_filename_randomness_still_requires_review(self):
        assert not _classifier()._code_is_safe("INSECURE_RANDOM", self.UPLOAD_FILENAME_SNIPPET)
