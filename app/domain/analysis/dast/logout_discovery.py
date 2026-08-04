"""Discovers a logout endpoint well enough to build a LOGOUT_INVALIDATES_SESSION
scenario without a full crawler (Phase 3 territory). Deliberately narrow:
this is the one scenario in Phase 2B that doesn't need scan-config-supplied
steps, because "find the logout link/path" is genuinely generic across apps
in a way "find the business-logic steps" (V2.3.1) is not — that one still
requires the caller to supply the Scenario's steps explicitly.
"""
import re
from typing import Optional

from app.domain.analysis.dast.scenario import Assertion, Scenario, Step
from app.domain.analysis.dast.session import DastSession

_LOGOUT_HREF_PATTERN = re.compile(r'href=["\']([^"\']*(?:logout|sign-?out)[^"\']*)["\']', re.IGNORECASE)
_CANDIDATE_LOGOUT_PATHS = (
    "/logout", "/signout", "/sign-out", "/auth/logout", "/api/logout",
    "/api/auth/logout", "/user/logout", "/session/logout",
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
