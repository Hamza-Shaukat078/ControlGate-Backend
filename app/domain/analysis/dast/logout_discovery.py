"""Discovers a logout endpoint well enough to build a LOGOUT_INVALIDATES_SESSION
scenario without a full crawler (Phase 3 territory). Deliberately narrow:
this is the one scenario in Phase 2B that doesn't need scan-config-supplied
steps, because "find the logout link/path" is genuinely generic across apps
in a way "find the business-logic steps" (V2.3.1) is not — that one still
requires the caller to supply the Scenario's steps explicitly.

Also home to check_logout_visible_on_every_page (V7.4.4) — same "find the
logout control" theme, reusing _LOGOUT_HREF_PATTERN, but sweeping every
crawled authenticated page instead of just base_url to build one logout URL.
"""
import re
from typing import List, Optional
from urllib.parse import urlsplit

from app.domain.analysis.dast.checks import _PUBLIC_BY_DEFINITION_PATH_RE
from app.domain.analysis.dast.findings import DynamicFinding
from app.domain.analysis.dast.scenario import Assertion, Scenario, Step
from app.domain.analysis.dast.session import DastSession
from app.domain.analysis.dast.verdict import Verdict

_LOGOUT_HREF_PATTERN = re.compile(r'href=["\']([^"\']*(?:logout|sign-?out)[^"\']*)["\']', re.IGNORECASE)
_CANDIDATE_LOGOUT_PATHS = (
    "/logout", "/signout", "/sign-out", "/auth/logout", "/api/logout",
    "/api/auth/logout", "/user/logout", "/session/logout",
)
# Catches a logout CONTROL that isn't a plain <a href> — a <button> or a
# JS-driven <a> whose visible text says "Log out"/"Sign out" rather than
# carrying it in the href. Bounded (`{0,300}` on the attribute gap, a fixed
# word alternation, no nested variable-width quantifiers) so it can't
# backtrack catastrophically the way an unanchored `.*` scan of a whole page
# could — same ReDoS-safety posture test_redos_regex_patterns.py enforces
# for the static rule catalog.
_LOGOUT_TEXT_PATTERN = re.compile(
    r'<(?:a|button)\b[^>]{0,300}>\s*(?:log\s?out|sign\s?out)\b', re.IGNORECASE,
)


async def discover_logout_url(session: DastSession, base_url: str) -> Optional[str]:
    """Best-effort logout-endpoint discovery: look for a logout link on the
    base page first, then fall back to common paths. Returns None if
    nothing plausible was found — the caller treats that as NOT_CONFIGURED,
    never as a false PASS. Note: hitting a real candidate path *is* the
    logout action, not a separate probe — there's no side-effect-free way to
    "check" a logout endpoint without invoking it.
    """
    base = base_url.rstrip("/")

    try:
        resp = await session.request("GET", base_url)
        m = _LOGOUT_HREF_PATTERN.search(resp.text)
        if m:
            href = m.group(1)
            if href.startswith("http://") or href.startswith("https://"):
                return href
            return base + "/" + href.lstrip("/")
    except Exception:
        pass

    for path in _CANDIDATE_LOGOUT_PATHS:
        try:
            resp = await session.request("GET", base + path, follow_redirects=False)
        except Exception:
            continue
        if resp.status_code != 404:
            return base + path

    return None


def build_logout_invalidates_session_scenario(logout_url: str, protected_url: str) -> Scenario:
    return Scenario(
        scenario_id="LOGOUT_INVALIDATES_SESSION",
        asvs_controls=["V7.4.1"],
        requires_active_mode=False,
        severity="high",
        description="Logs out, then re-requests a protected URL with the same (now-stale) session — "
                    "the app must disallow further use of a terminated session.",
        steps=[
            Step(method="GET", url=logout_url),
            Step(
                method="GET", url=protected_url, follow_redirects=False,
                assertions=[
                    Assertion(type="any_of", of=[
                        Assertion(type="status_in", expected=[401, 403]),
                        Assertion(type="redirect_location_contains", expected="login"),
                    ]),
                ],
            ),
        ],
    )


async def check_logout_visible_on_every_page(session: DastSession, urls: List[str]) -> DynamicFinding:
    """V7.4.4 — best-effort DAST assist, not a replacement for the real
    (perceptual: not hidden behind a broken menu, reachable without
    scrolling/hunting) check this control asks for. Requests every
    candidate URL through the scan's authenticated session and looks for a
    logout-shaped link/button — href (_LOGOUT_HREF_PATTERN) or visible text
    (_LOGOUT_TEXT_PATTERN) — anywhere in the response body.

    Fail-only signal, same asymmetric-confidence posture as
    REDIRECT_WARNING_LIVE/CSRF_TOKEN_NOT_VALIDATED: a page with no
    logout-shaped markup at all is real evidence (a control that's
    genuinely absent from the DOM can't be visible to a user either, no
    matter how it's styled) — but the reverse doesn't hold. "Logout"
    appearing SOMEWHERE in the markup doesn't prove it's actually reachable
    without scrolling, isn't buried in a collapsed mobile menu, or survives
    an error state — see asvs_service.py's HYBRID_ATTESTATION_DYNAMIC_
    ELIGIBLE_CONTROLS, which never lets this PASS decide the control on its
    own either way.
    """
    if not session.is_authenticated:
        return DynamicFinding(
            control_id="V7.4.4", verdict=Verdict.NOT_CONFIGURED, rule_id="LOGOUT_VISIBLE_ON_EVERY_PAGE",
            url="", method="GET", severity="medium",
            note="This scan has no authenticated session configured — there's no set of authenticated "
                 "pages to check for a logout control.",
            confidence=1.0,
        )

    # Same reasoning checks.py's _check_unauthenticated_access documents for
    # _PUBLIC_BY_DEFINITION_PATH_RE — a login/register/password-recovery page
    # is reachable (and shown) specifically to a visitor who ISN'T logged in
    # yet, so it never needs a logout control to begin with; testing it the
    # same way as a genuinely authenticated page would produce a false FAIL.
    candidate_urls = [
        u for u in urls
        if not _PUBLIC_BY_DEFINITION_PATH_RE.search(urlsplit(u).path.rstrip("/"))
    ]
    if not candidate_urls:
        return DynamicFinding(
            control_id="V7.4.4", verdict=Verdict.NOT_TESTED, rule_id="LOGOUT_VISIBLE_ON_EVERY_PAGE",
            url="", method="GET", severity="medium",
            note="No authenticated (non-login/register/reset) pages were discovered to check.",
            confidence=0.2,
        )

    checked = 0
    missing: List[str] = []
    for url in candidate_urls:
        try:
            resp = await session.request("GET", url)
        except Exception:
            continue
        if resp.status_code >= 400 or "html" not in resp.headers.get("content-type", "html"):
            continue
        checked += 1
        if not (_LOGOUT_HREF_PATTERN.search(resp.text) or _LOGOUT_TEXT_PATTERN.search(resp.text)):
            missing.append(url)

    if checked == 0:
        return DynamicFinding(
            control_id="V7.4.4", verdict=Verdict.NOT_TESTED, rule_id="LOGOUT_VISIBLE_ON_EVERY_PAGE",
            url="", method="GET", severity="medium",
            note="Could not fetch any candidate page as HTML through the authenticated session.",
            confidence=0.2,
        )

    if missing:
        return DynamicFinding(
            control_id="V7.4.4", verdict=Verdict.FAIL, rule_id="LOGOUT_VISIBLE_ON_EVERY_PAGE",
            url=missing[0], method="GET", severity="medium",
            note=f"No logout-shaped link or button (href or visible text) found anywhere in the markup "
                 f"of {len(missing)} of {checked} checked authenticated page(s) — e.g. "
                 f"{session.redact(missing[0])}. Markup-presence check only: doesn't confirm the control "
                 f"is actually reachable without scrolling/hunting on the pages where it WAS found.",
            confidence=0.55, evidence_type="response_diff",
            proof={
                "checked": checked, "missing_count": len(missing),
                "missing_urls": [session.redact(u) for u in missing[:10]],
            },
        )

    return DynamicFinding(
        control_id="V7.4.4", verdict=Verdict.PASS, rule_id="LOGOUT_VISIBLE_ON_EVERY_PAGE",
        url=candidate_urls[0], method="GET", severity="medium",
        note=f"A logout-shaped link or button was found somewhere in the markup of all {checked} "
             f"checked authenticated page(s) — markup presence only, not a check of real "
             f"visibility/reachability (scrolling, collapsed mobile menus, error states).",
        confidence=0.35,
    )
