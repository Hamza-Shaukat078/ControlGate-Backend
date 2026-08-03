"""
Regression tests for the ReDoS-class regex bug found via a real scan timeout:

    Query ZIPSLIP_VULNERABILITY timed out — skipped
    [scan:...] analyze_repository timed out after 300s — completing with partial results

Root cause: several rules used a negative lookahead of the shape
`(?![\\s\\S]{0,N}(?:sanitizer1|sanitizer2|...))ANCHOR` with the lookahead placed
*before* any anchor text. Python's `re.search` tries the pattern at every
character position in the file; with no anchor gating the lookahead, it's
evaluated at literally every position regardless of whether anything could
ever match there — confirmed empirically to take 6.6s on just 40K characters
of never-matching text for ZIPSLIP_VULNERABILITY, and >3s (timeout) for
ARCHIVE_SYMLINK_EXTRACTION on a realistic 74K-character corpus.

An initial fix attempt just moved the lookahead to *after* the anchor
(bounding invocation count to how often the anchor matches, which is what
already made the other ~59 similarly-shaped patterns in this catalog safe in
practice). That broke two real cases: a symlink check appearing *before* the
extract() call in a for-loop, and `trust proxy` configured once near the top
of a file, ahead of every route that reads req.ip — both legitimate,
common code shapes that a "check only what comes after" window can't see.

Final fix: drop the inline lookahead entirely and rely on
query_executor.py's existing whole-file `sanitizers`-list downgrade
mechanism (already used by other rules in this catalog) — a plain
substring check with no backtracking risk, and one that doesn't care
whether the guard appears before or after the flagged call.
"""
import re
import time

import pytest

from tests.unit.test_query_patterns import RULES, get_patterns, matches_any
from tests.unit.test_query_patterns import sanitizer_present as _sanitizer_present


def _fires(rule_id: str, code: str) -> bool:
    return matches_any(get_patterns(rule_id), code)


def _assert_fast_on_adversarial_input(rule_id: str, cap_seconds: float = 1.0):
    # Large, never-matching text -- the worst case for a lookahead invoked at
    # every position with nothing to anchor it.
    code = "no_match_line_of_code_here_at_all(a, b, c);\n" * 5000
    for pattern in get_patterns(rule_id):
        start = time.perf_counter()
        re.search(pattern, code)
        elapsed = time.perf_counter() - start
        assert elapsed < cap_seconds, (
            f"{rule_id} pattern took {elapsed:.2f}s on {len(code)} chars of "
            f"non-matching text — ReDoS regression: {pattern!r}"
        )


class TestZipslipVulnerabilityPerf:
    RULE = "ZIPSLIP_VULNERABILITY"

    def test_fast_on_adversarial_input(self):
        _assert_fast_on_adversarial_input(self.RULE)

    def test_still_detects_unsafe_extractall(self):
        assert _fires(self.RULE, "zipfile.ZipFile(p).extractall(dest)")

    def test_safe_call_with_validation_not_suppressed_but_downgradeable(self):
        # The old inline lookahead fully suppressed this; now the regex still
        # fires and the whole-file sanitizer check is what softens it.
        code = "zipfile.ZipFile(p).extractall(dest)\nassert validate_path(dest)"
        assert _fires(self.RULE, code)
        assert _sanitizer_present(self.RULE, code)


class TestArchiveSymlinkExtractionPerf:
    RULE = "ARCHIVE_SYMLINK_EXTRACTION"

    def test_fast_on_adversarial_input(self):
        _assert_fast_on_adversarial_input(self.RULE)

    def test_still_detects_unchecked_extractall(self):
        assert _fires(self.RULE, "zipfile.ZipFile(p).extractall(dest)")

    def test_guard_before_extract_in_loop_no_longer_missed(self):
        # This is the case that broke the "just move the lookahead after the
        # anchor" attempt: the symlink check happens *before* extract() in a
        # for-loop, which a forward-only window can't see.
        code = "for m in tf.getmembers():\n    if m.issym(): continue\n    tf.extract(m, dest)"
        assert _fires(self.RULE, code)
        assert _sanitizer_present(self.RULE, code)


class TestOidcIssuerNotValidatedPerf:
    RULE = "OIDC_ISSUER_NOT_VALIDATED"

    def test_fast_on_adversarial_input(self):
        _assert_fast_on_adversarial_input(self.RULE)

    def test_still_detects_missing_issuer_check(self):
        code = 'claims = jwt.decode(id_token, key, algorithms=["RS256"])'
        assert _fires(self.RULE, code)

    def test_issuer_check_present_downgradeable(self):
        code = (
            'claims = jwt.decode(id_token, key, algorithms=["RS256"])\n'
            'if claims["iss"] == EXPECTED_ISSUER:\n    pass'
        )
        assert _fires(self.RULE, code)
        assert _sanitizer_present(self.RULE, code)


class TestIdTokenNonceNotCheckedPerf:
    RULE = "ID_TOKEN_NONCE_NOT_CHECKED"

    def test_fast_on_adversarial_input(self):
        _assert_fast_on_adversarial_input(self.RULE)

    def test_still_detects_missing_nonce_check(self):
        code = 'claims = jwt.decode(id_token, key, algorithms=["RS256"])'
        assert _fires(self.RULE, code)

    def test_nonce_check_present_downgradeable(self):
        code = (
            'claims = jwt.decode(id_token, key, algorithms=["RS256"])\n'
            'if claims["nonce"] == session["nonce"]:\n    pass'
        )
        assert _fires(self.RULE, code)
        assert _sanitizer_present(self.RULE, code)


class TestIdTokenAudienceNotCheckedPerf:
    RULE = "ID_TOKEN_AUDIENCE_NOT_CHECKED"

    def test_fast_on_adversarial_input(self):
        _assert_fast_on_adversarial_input(self.RULE)

    def test_still_detects_missing_audience_check(self):
        code = 'claims = jwt.decode(id_token, key, algorithms=["RS256"])'
        assert _fires(self.RULE, code)

    def test_audience_check_present_downgradeable(self):
        code = 'claims = jwt.decode(id_token, key, algorithms=["RS256"], audience=CLIENT_ID)'
        assert _fires(self.RULE, code)
        assert _sanitizer_present(self.RULE, code)


class TestUnvalidatedRedirectPerf:
    RULE = "UNVALIDATED_REDIRECT"

    def test_fast_on_adversarial_input(self):
        _assert_fast_on_adversarial_input(self.RULE)

    def test_still_detects_unvalidated_next_param_redirect(self):
        code = 'dest = request.args.get("next")\nreturn redirect(dest)'
        assert _fires(self.RULE, code)

    def test_is_safe_url_guard_downgradeable(self):
        code = (
            'dest = request.args.get("next")\n'
            'if not is_safe_url(dest): abort(400)\n'
            'return redirect(dest)'
        )
        assert _fires(self.RULE, code)
        assert _sanitizer_present(self.RULE, code)


class TestSpoofableProxyHeaderPerf:
    RULE = "SPOOFABLE_PROXY_HEADER"

    def test_fast_on_adversarial_input(self):
        _assert_fast_on_adversarial_input(self.RULE)

    def test_still_detects_req_ip_used_for_security_decision(self):
        assert _fires(self.RULE, "if (req.ip == bannedIp) { block(); }")

    def test_trust_proxy_configured_earlier_in_file_downgradeable(self):
        # trust-proxy config declared once near the top of the file, well
        # before the req.ip usage -- the other case a forward-only window
        # can't see.
        code = "app.set('trust proxy', 1);\nif (req.ip == bannedIp) { block(); }"
        assert _fires(self.RULE, code)
        assert _sanitizer_present(self.RULE, code)


class TestSsrfPerf:
    RULE = "SSRF"

    def test_fast_on_adversarial_input(self):
        _assert_fast_on_adversarial_input(self.RULE)

    def test_still_detects_unvalidated_url_flow_to_axios(self):
        code = "const target = req.query.url;\naxios.get(target);"
        assert _fires(self.RULE, code)

    def test_allowlist_check_downgradeable(self):
        code = (
            "const target = req.query.url;\n"
            "if (!ALLOWED_HOSTS.has(target)) return;\n"
            "axios.get(target);"
        )
        assert _fires(self.RULE, code)
        assert _sanitizer_present(self.RULE, code)


class TestNoRemainingUnanchoredLookaheads:
    """
    Catalog-wide guard: a negative lookahead with a large bounded [\\s\\S]{0,N}
    window sitting at the very start of a pattern (before any anchor text) is
    exactly the shape that caused this whole class of bug — re.search tries it
    at every position in the file. Fails the build if this shape reappears
    anywhere in the catalog, rather than relying on someone noticing the next
    scan timeout.
    """

    _LOOKAHEAD_RE = re.compile(r"\(\?![\[(].{0,40}?\{0,(\d+)\}")

    def test_no_pattern_starts_with_a_wide_negative_lookahead(self):
        offenders = []
        for rule_id, rule in RULES.items():
            for idx, pattern in enumerate(rule.get("regex_patterns", [])):
                m = self._LOOKAHEAD_RE.search(pattern)
                if not m:
                    continue
                window = int(m.group(1))
                at_start = m.start() <= 6  # allows a leading (?i) flag
                if window >= 150 and at_start:
                    offenders.append((rule_id, idx, pattern))
        assert not offenders, (
            "Pattern(s) with an unanchored wide negative lookahead (evaluated "
            "at every position in the file, regardless of any real anchor) "
            f"found: {offenders}"
        )
