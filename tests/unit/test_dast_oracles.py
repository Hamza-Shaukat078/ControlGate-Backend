"""Phase 1 confirmation spine (app/domain/analysis/dast/oracles.py) — the
shared toolkit every check uses to move a heuristic FAIL to a reproduced-
impact CONFIRMED. Was the one brand-new dast/ module with zero unit
coverage; only exercised indirectly via tests/integration/test_dast_regression_corpus.py.
"""
from dataclasses import dataclass
from unittest.mock import AsyncMock, patch

import pytest

from app.domain.analysis.dast.oracles import (
    canary,
    canary_reflected_unescaped,
    comparative_timing_oracle,
    error_signature_oracle,
    oob_oracle,
    response_diff_oracle,
    timing_oracle,
)


class TestCanary:
    def test_canary_has_recognizable_prefix(self):
        assert canary().startswith("dastcanary")

    def test_two_canaries_are_unique(self):
        assert canary() != canary()


class TestCanaryReflectedUnescaped:
    def test_not_reflected_at_all_is_false(self):
        assert canary_reflected_unescaped("MARKER123", "<p>hello world</p>") is False

    def test_reflected_inside_script_block_is_dangerous(self):
        body = "<script>var x = 'MARKER123';</script>"
        assert canary_reflected_unescaped("MARKER123", body) is True

    def test_reflected_inside_event_handler_is_dangerous(self):
        body = '<img src=x onerror="alert(\'MARKER123\')">'
        assert canary_reflected_unescaped("MARKER123", body) is True

    def test_reflected_in_unquoted_attribute_is_dangerous(self):
        body = "<input value=MARKER123 type=text>"
        assert canary_reflected_unescaped("MARKER123", body) is True

    def test_reflected_in_quoted_attribute_is_true_via_broad_tag_fallback(self):
        # The properly-quoted-attribute check itself (_ATTR_VALUE_RE) does
        # correctly treat this as quoted/safe, BUT the final catch-all regex
        # (`<tag...marker`, meant for the "marker's own '<' opened a new
        # tag" break-out case) matches any tag whose content contains the
        # marker anywhere before its closing '>', quoted or not — so the
        # overall function still returns True here. Documented as current
        # behavior (a false positive skewed toward the module's stated
        # "assume dangerous unless clearly safe" bias), not a spec.
        body = '<input value="MARKER123" type="text">'
        assert canary_reflected_unescaped("MARKER123", body) is True

    def test_reflected_in_html_entity_quoted_attribute_is_true_via_broad_tag_fallback(self):
        body = "<input value=&quot;MARKER123&quot; type=text>"
        assert canary_reflected_unescaped("MARKER123", body) is True

    def test_reflected_as_plain_text_node_is_safe(self):
        body = "<p>Hello MARKER123, welcome back</p>"
        assert canary_reflected_unescaped("MARKER123", body) is False

    def test_marker_as_sole_new_tag_name_is_dangerous(self):
        # Docstring case 4: a marker whose own '<' opened a real tag, e.g. a
        # `"><MARKER123 onclick=x>` break-out payload, where the marker IS
        # the tag name (nothing else in the tag repeats it). Covered by its
        # own anchored `<{marker}` check, independent of the broader
        # catch-all below (which needs a second occurrence).
        body = '<p>hello</p><MARKER123 onclick="x">'
        assert canary_reflected_unescaped("MARKER123", body) is True

    def test_marker_as_tag_name_followed_by_slash_or_close_is_dangerous(self):
        assert canary_reflected_unescaped("MARKER123", "<MARKER123/>") is True
        assert canary_reflected_unescaped("MARKER123", "<MARKER123>") is True

    def test_marker_as_prefix_of_a_longer_tag_name_is_not_flagged_by_this_branch(self):
        # Word-boundary-ish guard `(?=[\\s/>]|$)` — "MARKER123EXTRA" is a
        # different tag name than the marker, this specific check shouldn't
        # treat it as "the marker opened a tag".
        assert canary_reflected_unescaped("MARKER123", "<MARKER123EXTRA>") is False

    def test_marker_repeated_after_a_real_tag_name_is_dangerous(self):
        # The catch-all regex DOES fire when the marker shows up a second
        # time, after a real (non-marker) tag name — e.g. an attribute
        # value the earlier quoted/unquoted attribute checks didn't already
        # catch for some other reason.
        body = '<div data-x=MARKER123 class=MARKER123>'
        assert canary_reflected_unescaped("MARKER123", body) is True

    def test_non_renderable_content_type_is_never_dangerous(self):
        body = '<script>MARKER123</script>'
        assert canary_reflected_unescaped("MARKER123", body, content_type="application/json") is False

    def test_missing_content_type_defaults_to_dangerous(self):
        body = "<script>MARKER123</script>"
        assert canary_reflected_unescaped("MARKER123", body, content_type="") is True

    def test_empty_body_is_false(self):
        assert canary_reflected_unescaped("MARKER123", "") is False


class TestErrorSignatureOracle:
    @pytest.mark.parametrize("text", [
        "You have an error in your SQL syntax near 'foo'",
        "Warning: mysqli_query() expects parameter",
        "unrecognized token: \"'\"",
        "PostgreSQL ERROR: syntax error at or near \"SELECT\"",
        "Microsoft SQL Server: Incorrect syntax near '1'",
        "ORA-00933: SQL command not properly ended",
    ])
    def test_known_db_error_signatures_detected(self, text):
        assert error_signature_oracle(text) is True

    def test_case_insensitive(self):
        assert error_signature_oracle("SQL SYNTAX error near token") is True

    def test_benign_response_not_flagged(self):
        assert error_signature_oracle("<html><body>Welcome back, alice!</body></html>") is False


class TestResponseDiffOracle:
    def test_identical_bodies_not_different(self):
        assert response_diff_oracle("same body text", "same body text") is False

    def test_small_length_delta_below_threshold_not_different(self):
        assert response_diff_oracle("x" * 100, "x" * 105) is False

    def test_large_length_delta_is_different(self):
        assert response_diff_oracle("short", "x" * 500) is True

    def test_short_bodies_use_absolute_20_char_floor(self):
        # 15 vs 40 chars: diff=25 > max(20, 0.15*40=6) -> True
        assert response_diff_oracle("a" * 15, "b" * 40) is True
        # diff=10 <= 20 floor -> False even though it's a large relative change
        assert response_diff_oracle("a" * 5, "b" * 15) is False


class TestOobOracle:
    @dataclass
    class _FakeHit:
        method: str
        remote_addr: str
        path: str

    class _FakeCollaborator:
        def __init__(self, hits):
            self._hits = hits

        def hits_for(self, token):
            return self._hits

    def test_no_hits_is_not_confirmed(self):
        collaborator = self._FakeCollaborator([])
        confirmed, proof = oob_oracle(collaborator, "tok-abc")
        assert confirmed is False
        assert proof == {"token": "tok-abc", "hits": 0}

    def test_hit_recorded_is_confirmed_with_proof_fields(self):
        hit = self._FakeHit(method="GET", remote_addr="10.0.0.5", path="/tok-abc/x")
        collaborator = self._FakeCollaborator([hit])
        confirmed, proof = oob_oracle(collaborator, "tok-abc")
        assert confirmed is True
        assert proof["hits"] == 1
        assert proof["first_hit_method"] == "GET"
        assert proof["first_hit_remote_addr"] == "10.0.0.5"
        assert proof["first_hit_path"] == "/tok-abc/x"


class TestTimingOracle:
    """Drives time.monotonic() with a scripted sequence of (start, end) pairs
    per sample instead of real sleeps — deterministic and fast, and lets
    each test target one exact branch of the confirm/reject logic instead of
    hoping real wall-clock jitter lands the right side of the threshold."""

    @staticmethod
    def _clock(*elapsed_seconds_per_sample: float):
        """One (start=0, end=elapsed) pair per call to timing_oracle's
        `time.monotonic()` — two calls per sample (start, then elapsed-calc)."""
        values = []
        for elapsed in elapsed_seconds_per_sample:
            values.extend([0.0, elapsed])
        return values

    @pytest.mark.asyncio
    async def test_stable_baseline_with_sufficient_delay_confirms(self):
        send_fn = AsyncMock(return_value=None)
        # baseline: 1ms every sample (stable); injected: 8000ms every sample.
        # required_delta = 5000ms * 1.5 = 7500ms; delta ~= 7999ms >= that.
        clock_values = self._clock(0.001, 0.001, 0.001, 8.0, 8.0, 8.0)
        with patch("app.domain.analysis.dast.oracles.time.monotonic", side_effect=clock_values):
            confirmed, proof = await timing_oracle(
                send_fn, baseline_delay=0, injected_delay=5, samples=3, margin=1.5,
            )
        assert confirmed is True
        assert proof["baseline_stable"] is True

    @pytest.mark.asyncio
    async def test_delay_present_but_below_required_margin_not_confirmed(self):
        send_fn = AsyncMock(return_value=None)
        # injected only ~2000ms slower than baseline; required is 7500ms.
        clock_values = self._clock(0.001, 0.001, 0.001, 2.0, 2.0, 2.0)
        with patch("app.domain.analysis.dast.oracles.time.monotonic", side_effect=clock_values):
            confirmed, proof = await timing_oracle(
                send_fn, baseline_delay=0, injected_delay=5, samples=3, margin=1.5,
            )
        assert confirmed is False
        assert proof["baseline_stable"] is True

    @pytest.mark.asyncio
    async def test_jittery_baseline_prevents_confirmation_even_with_huge_delta(self):
        send_fn = AsyncMock(return_value=None)
        # Baseline alternates ~1ms/~3000ms (stdev way above the 1250ms
        # threshold for injected_delay=5), even though the injected side is
        # a clean, huge, consistent delay — instability alone must block it.
        clock_values = self._clock(0.001, 3.0, 0.001, 8.0, 8.0, 8.0)
        with patch("app.domain.analysis.dast.oracles.time.monotonic", side_effect=clock_values):
            confirmed, proof = await timing_oracle(
                send_fn, baseline_delay=0, injected_delay=5, samples=3, margin=1.5,
            )
        assert confirmed is False
        assert proof["baseline_stable"] is False

    @pytest.mark.asyncio
    async def test_zero_injected_delay_never_confirms(self):
        send_fn = AsyncMock(return_value=None)
        confirmed, _ = await timing_oracle(send_fn, injected_delay=0, samples=2)
        assert confirmed is False

    @pytest.mark.asyncio
    async def test_proof_contains_expected_keys(self):
        send_fn = AsyncMock(return_value=None)
        _, proof = await timing_oracle(send_fn, samples=2)
        assert set(proof) == {
            "baseline_ms", "injected_ms", "baseline_median_ms", "injected_median_ms",
            "baseline_stdev_ms", "delta_ms", "required_delta_ms", "baseline_stable",
        }


class TestComparativeTimingOracle:
    """V11.2.5 — unlike TimingOracle above (a KNOWN expected delay), this
    has no expected magnitude: the question is only whether two fixed
    payload variants are timing-distinguishable at all, beyond jitter.
    Interleaved a/b/a/b/... sampling means 4 time.monotonic() calls per
    sample (start_a, end_a, start_b, end_b)."""

    @staticmethod
    def _clock(*ab_elapsed_pairs: tuple):
        """One (elapsed_a, elapsed_b) pair per sample; expands to the 4
        monotonic() return values comparative_timing_oracle consumes for
        that sample (start=0 each call, then elapsed)."""
        values = []
        for elapsed_a, elapsed_b in ab_elapsed_pairs:
            values.extend([0.0, elapsed_a, 0.0, elapsed_b])
        return values

    @pytest.mark.asyncio
    async def test_large_consistent_delta_confirms(self):
        send_a, send_b = AsyncMock(return_value=None), AsyncMock(return_value=None)
        # a: ~50ms every sample (tight); b: ~90ms every sample (tight) —
        # 40ms delta, far above both the 5ms floor and the noise floor
        # (stdev ~0 * 4 multiplier).
        clock_values = self._clock((0.050, 0.090), (0.050, 0.090), (0.050, 0.090))
        with patch("app.domain.analysis.dast.oracles.time.monotonic", side_effect=clock_values):
            confirmed, proof = await comparative_timing_oracle(send_a, send_b, samples=3)
        assert confirmed is True
        assert proof["delta_ms"] == pytest.approx(40.0, abs=0.5)

    @pytest.mark.asyncio
    async def test_microsecond_delta_below_floor_not_confirmed(self):
        send_a, send_b = AsyncMock(return_value=None), AsyncMock(return_value=None)
        # 2ms delta — below the 5ms min_delta_ms floor even though it's
        # perfectly consistent (zero jitter).
        clock_values = self._clock((0.050, 0.052), (0.050, 0.052), (0.050, 0.052))
        with patch("app.domain.analysis.dast.oracles.time.monotonic", side_effect=clock_values):
            confirmed, proof = await comparative_timing_oracle(send_a, send_b, samples=3)
        assert confirmed is False
        assert proof["delta_ms"] == pytest.approx(2.0, abs=0.5)

    @pytest.mark.asyncio
    async def test_jittery_samples_prevent_confirmation_despite_large_median_delta(self):
        send_a, send_b = AsyncMock(return_value=None), AsyncMock(return_value=None)
        # b swings wildly (20ms..500ms) — its own noise dwarfs the median
        # delta, so the difference can't be trusted as signal.
        clock_values = self._clock((0.050, 0.020), (0.050, 0.500), (0.050, 0.060))
        with patch("app.domain.analysis.dast.oracles.time.monotonic", side_effect=clock_values):
            confirmed, _ = await comparative_timing_oracle(send_a, send_b, samples=3)
        assert confirmed is False

    @pytest.mark.asyncio
    async def test_identical_timing_not_confirmed(self):
        send_a, send_b = AsyncMock(return_value=None), AsyncMock(return_value=None)
        clock_values = self._clock((0.050, 0.050), (0.050, 0.050), (0.050, 0.050))
        with patch("app.domain.analysis.dast.oracles.time.monotonic", side_effect=clock_values):
            confirmed, proof = await comparative_timing_oracle(send_a, send_b, samples=3)
        assert confirmed is False
        assert proof["delta_ms"] == pytest.approx(0.0, abs=0.1)

    @pytest.mark.asyncio
    async def test_sends_are_interleaved_not_batched(self):
        # Both send_fns get called once per sample, in a/b/a/b order — not
        # all of a followed by all of b (see comparative_timing_oracle's
        # own docstring for why: a slow-drift bias otherwise favors
        # whichever variant runs second).
        call_order = []

        async def send_a():
            call_order.append("a")

        async def send_b():
            call_order.append("b")

        clock_values = self._clock((0.01, 0.01), (0.01, 0.01))
        with patch("app.domain.analysis.dast.oracles.time.monotonic", side_effect=clock_values):
            await comparative_timing_oracle(send_a, send_b, samples=2)
        assert call_order == ["a", "b", "a", "b"]

    @pytest.mark.asyncio
    async def test_proof_contains_expected_keys(self):
        send_a, send_b = AsyncMock(return_value=None), AsyncMock(return_value=None)
        clock_values = self._clock((0.01, 0.01), (0.01, 0.01))
        with patch("app.domain.analysis.dast.oracles.time.monotonic", side_effect=clock_values):
            _, proof = await comparative_timing_oracle(send_a, send_b, samples=2)
        assert set(proof) == {
            "variant_a_ms", "variant_b_ms", "variant_a_median_ms", "variant_b_median_ms",
            "delta_ms", "noise_floor_ms",
        }
