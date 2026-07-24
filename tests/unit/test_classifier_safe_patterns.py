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
