from enum import Enum


class Verdict(str, Enum):
    """Shared result vocabulary for every DAST check (payload and scenario alike).

    Values "pass"/"fail"/"not_tested" are kept identical to the strings
    dynamic_probe.py's ProbeFinding already uses, so the two are
    interchangeable when Phase 4 merges static-probe and DAST-engine findings
    into one report. The extra states exist so a check can say precisely why
    it didn't produce pass/fail, instead of the report ever implying "no
    finding" means "verified secure":
      - CONFIRMED: strictly stronger than FAIL — the engine didn't just see a
        strong heuristic signal (a response diff, an error string), it
        reproduced real impact (a measured time delay, an out-of-band
        callback received, data exfiltrated, JS actually executed). Every
        CONFIRMED finding is also a FAIL for filtering/counting purposes
        (see FAILING_VERDICTS below) — it's a stronger form of the same
        "this check failed" fact, not a separate category.
      - FAIL: strong heuristic signal (a response diff, an error string) —
        the check didn't reproduce impact, but the evidence is not inert.
      - INCONCLUSIVE: the check ran but the response didn't clearly satisfy
        either the pass or fail condition (e.g. ambiguous/ratelimited response).
      - NOT_CONFIGURED: the check requires scan config the user didn't supply
        (e.g. a second actor, a login flow) — it never ran at all.
      - SKIPPED_REQUIRES_ACTIVE_AUTHORIZATION: the check has side effects
        (race/business-logic probes, request smuggling) and active_mode
        was not enabled for this scan.
    """

    PASS = "pass"
    FAIL = "fail"
    CONFIRMED = "confirmed"
    NOT_TESTED = "not_tested"
    INCONCLUSIVE = "inconclusive"
    NOT_CONFIGURED = "not_configured"
    SKIPPED_REQUIRES_ACTIVE_AUTHORIZATION = "skipped_requires_active_authorization"


# Rank a verdict's strength as evidence, strongest first — the ordering any
# severity sort/dedup should use when two findings for the same
# check/control disagree. CONFIRMED (reproduced impact) outranks FAIL
# (heuristic signal only); everything else never represents a positive
# finding at all, so they're tied at the bottom.
VERDICT_RANK: dict[str, int] = {
    Verdict.CONFIRMED.value: 3,
    Verdict.FAIL.value: 2,
    Verdict.INCONCLUSIVE.value: 1,
    Verdict.PASS.value: 0,
    Verdict.NOT_TESTED.value: 0,
    Verdict.NOT_CONFIGURED.value: 0,
    Verdict.SKIPPED_REQUIRES_ACTIVE_AUTHORIZATION.value: 0,
}

# Verdicts that represent a positive (failing) finding. CONFIRMED is
# strictly stronger evidence of the same underlying fact FAIL represents, so
# anywhere existing code filters/counts on `verdict == "fail"` (severity
# totals, static-finding confirmation propagation) must treat CONFIRMED as
# qualifying too — otherwise the strongest findings the engine can produce
# would silently drop out of those counts.
FAILING_VERDICTS = frozenset({Verdict.FAIL.value, Verdict.CONFIRMED.value})
