from enum import Enum


class Verdict(str, Enum):
    """Shared result vocabulary for every DAST check (payload and scenario alike).

    Values "pass"/"fail"/"not_tested" are kept identical to the strings
    dynamic_probe.py's ProbeFinding already uses, so the two are
    interchangeable when Phase 4 merges static-probe and DAST-engine findings
    into one report. The extra states exist so a check can say precisely why
    it didn't produce pass/fail, instead of the report ever implying "no
    finding" means "verified secure":
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
    NOT_TESTED = "not_tested"
    INCONCLUSIVE = "inconclusive"
    NOT_CONFIGURED = "not_configured"
    SKIPPED_REQUIRES_ACTIVE_AUTHORIZATION = "skipped_requires_active_authorization"
