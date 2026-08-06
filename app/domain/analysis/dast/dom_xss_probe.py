"""Track C2 — DOM-based XSS probe (V1.2.1).

Every other XSS-shaped check in this engine (REFLECTED_XSS_LIVE,
STORED_XSS_PROBE) infers "did the payload execute?" from response *text*:
does an unescaped tag appear in the HTML the server sent back. Neither can
see a payload that never touches the server at all — DOM-based XSS, where
client-side JS reads something like location.hash and writes it into the
page unescaped (e.g. el.innerHTML = location.hash), with no request the
server ever sees. This is structurally invisible to every check built so
far, since none of them execute JavaScript — this one does, via a real
headless browser context (browser_crawler.py's shared Chromium instance).

The marker payload goes into the URL *fragment* specifically because the
fragment is never sent to the server at all (RFC 3986 §3.5 — everything
after '#' is resolved client-side only). Any effect it has can only come
from client-side JS reading location.hash, making a positive result here a
true DOM-XSS-only signal, structurally incapable of overlapping with
REFLECTED_XSS_LIVE's server-side check (that one only ever looks at query
parameters, which do reach the server).

Not in dynamic_queries.json / checks.py's _CHECK_FUNCTIONS, same as
SSRF_LIVE and STORED_XSS_PROBE: this needs a live browser context, not just
a DastSession, so it's invoked directly by scan_service._run_dynamic_checks
rather than through run_payload_checks' generic per-rule dispatch.
"""
import logging
import secrets

from app.domain.analysis.dast.findings import DynamicFinding
from app.domain.analysis.dast.verdict import Verdict

logger = logging.getLogger(__name__)

RULE_ID = "DOM_XSS_LIVE"
PAGE_LOAD_TIMEOUT_MS = 15_000


async def run_dom_xss_probe(
    browser_context,
    url: str,
    *,
    control_id: str = "V1.2.1",
    severity: str = "high",
    active_mode: bool = False,
) -> DynamicFinding:
    """browser_context: a live playwright.async_api.BrowserContext (the same
    shared context browser_crawler.py's crawl_with_browser used, reused here
    rather than launching a second browser).

    requires_active_mode, same reasoning as every other check in this engine
    with a real side effect (race/business-logic probes, request smuggling):
    navigating with this payload executes real, attacker-shaped JS against
    the live target if the app is vulnerable — that's a genuine action
    against the target, not a passive read, and needs the same explicit
    opt-in.
    """
    if not active_mode:
        return DynamicFinding(
            control_id=control_id, verdict=Verdict.SKIPPED_REQUIRES_ACTIVE_AUTHORIZATION,
            rule_id=RULE_ID, url=url, method="GET", severity=severity,
            note="Navigating with a live DOM-XSS probe payload executes real JS against the target "
                 "and active_mode was not enabled for this scan",
            confidence=1.0,
        )

    marker = f"dast_dom_{secrets.token_hex(4)}"
    # If the target's own client-side JS reads location.hash and writes it
    # into the page unescaped, the <img>'s onerror handler fires and sets
    # window.__dast_marker — a value only real JS execution could produce,
    # not something inferable from response text the way every other check
    # in this engine works.
    payload = f"<img src=x onerror=\"window.__dast_marker='{marker}'\">"
    target = f"{url.split('#', 1)[0]}#{payload}"

    page = await browser_context.new_page()
    try:
        try:
            await page.goto(target, wait_until="networkidle", timeout=PAGE_LOAD_TIMEOUT_MS)
        except Exception as exc:
            return DynamicFinding(
                control_id=control_id, verdict=Verdict.NOT_TESTED, rule_id=RULE_ID,
                url=url, method="GET", severity=severity,
                note=f"Could not load the page with the DOM-XSS probe payload: {exc}", confidence=0.2,
            )

        try:
            observed = await page.evaluate("window.__dast_marker")
        except Exception as exc:
            return DynamicFinding(
                control_id=control_id, verdict=Verdict.NOT_TESTED, rule_id=RULE_ID,
                url=url, method="GET", severity=severity,
                note=f"Could not read back the probe marker after page load: {exc}", confidence=0.2,
            )
    finally:
        await page.close()

    if observed == marker:
        return DynamicFinding(
            control_id=control_id, verdict=Verdict.FAIL, rule_id=RULE_ID,
            url=url, method="GET", severity=severity,
            note="A marker placed in the URL fragment executed as live JS after the page loaded — "
                 "client-side code reads location.hash and writes it into the DOM unescaped "
                 f"(marker: {marker}, never sent to the server)",
            confidence=0.8,
        )
    return DynamicFinding(
        control_id=control_id, verdict=Verdict.PASS, rule_id=RULE_ID,
        url=url, method="GET", severity=severity,
        note="The URL-fragment marker did not execute as JS after the page loaded",
        confidence=0.55,
    )
