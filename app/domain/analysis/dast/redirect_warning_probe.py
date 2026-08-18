"""V3.7.3 — outbound-redirect warning probe.

"Verify that the application shows a notification when the user is being
redirected to a URL outside of the application's control, with an option to
cancel the navigation." Every other check in this engine infers a verdict
from HTTP request/response text; this one is about a *rendered page's
interactive behavior* (does clicking an outbound link show an interstitial
before the browser actually leaves, or does it navigate immediately) — that
can only be observed by driving a real browser, not read from a response
body. Same reasoning as dom_xss_probe.py.

Deliberately asymmetric, same epistemic stance as every other manual-vs-
automated split in this engine (see HYBRID_ATTESTATION_ELIGIBLE_CONTROLS in
asvs_service.py): an immediate same-tab cross-origin navigation with zero
intervening user-facing state is confident, direct evidence of the
violation (FAIL). The absence of that — the page's own URL never changed —
is NOT confident evidence of a *working* interstitial with a real cancel
option; it's equally consistent with the link opening in a new tab, the
click silently failing, or the app genuinely doing the right thing. That
weaker case gets a PASS, but at meaningfully lower confidence than the FAIL
case, same asymmetry dom_xss_probe.py already uses (0.8 vs 0.55) — a human
still needs to look at what's actually on the page before trusting it.

Not in dynamic_queries.json / checks.py's _CHECK_FUNCTIONS, same as
DOM_XSS_LIVE: this needs a live browser context, not just a DastSession, so
it's invoked directly by scan_service._run_dynamic_checks rather than
through run_payload_checks' generic per-rule dispatch.
"""
import logging
from urllib.parse import urlparse

from app.domain.analysis.dast.findings import DynamicFinding
from app.domain.analysis.dast.verdict import Verdict

logger = logging.getLogger(__name__)

RULE_ID = "REDIRECT_WARNING_LIVE"
PAGE_LOAD_TIMEOUT_MS = 15_000
CLICK_TIMEOUT_MS = 5_000
# How long to give the page after a click to actually complete a same-tab
# navigation before we read page.url as the "did it move" signal.
POST_CLICK_SETTLE_MS = 1_500


def _host(url: str) -> str:
    try:
        return urlparse(url).netloc.lower()
    except Exception:
        return ""


async def _find_external_link(page, own_host: str):
    """Returns (href, target_attr) for the first same-tab-navigable outbound
    link on the page, or (None, None) if none is found. target="_blank"
    links are collected too (returned with their target attr) so the caller
    can tell the two cases apart rather than silently treating a new-tab
    link as either a pass or a fail."""
    try:
        links = await page.eval_on_selector_all(
            "a[href]",
            "els => els.map(el => ({href: el.href, target: el.getAttribute('target') || ''}))",
        )
    except Exception as exc:
        logger.debug(f"[{RULE_ID}] could not enumerate links: {exc}")
        return None, None

    for link in links or []:
        href = link.get("href") or ""
        if not href.startswith(("http://", "https://")):
            continue
        host = _host(href)
        if host and host != own_host:
            return href, link.get("target") or ""
    return None, None


async def run_redirect_warning_probe(
    browser_context,
    url: str,
    *,
    control_id: str = "V3.7.3",
    severity: str = "medium",
    active_mode: bool = False,
) -> DynamicFinding:
    """browser_context: a live playwright.async_api.BrowserContext — same
    shared-context convention as run_dom_xss_probe.

    active_mode-gated for the same reason as every other check with a real
    side effect against the live target: clicking an outbound link and
    following where it actually goes is a genuine navigation action, not a
    passive read.
    """
    if not active_mode:
        return DynamicFinding(
            control_id=control_id, verdict=Verdict.SKIPPED_REQUIRES_ACTIVE_AUTHORIZATION,
            rule_id=RULE_ID, url=url, method="GET", severity=severity,
            note="Clicking an outbound link and observing where the browser actually navigates is a "
                 "real action against the target and active_mode was not enabled for this scan",
            confidence=1.0,
        )

    page = await browser_context.new_page()
    try:
        try:
            await page.goto(url, wait_until="networkidle", timeout=PAGE_LOAD_TIMEOUT_MS)
        except Exception as exc:
            return DynamicFinding(
                control_id=control_id, verdict=Verdict.NOT_TESTED, rule_id=RULE_ID,
                url=url, method="GET", severity=severity,
                note=f"Could not load the page to probe for a redirect warning: {exc}", confidence=0.2,
            )

        own_host = _host(page.url)
        external_href, target_attr = await _find_external_link(page, own_host)
        if not external_href:
            return DynamicFinding(
                control_id=control_id, verdict=Verdict.NOT_TESTED, rule_id=RULE_ID,
                url=url, method="GET", severity=severity,
                note="No outbound link to a different host was found on this page — nothing to probe "
                     "a redirect warning against here",
                confidence=0.2,
            )

        if target_attr.lower() == "_blank":
            # Opens in a new tab — the original app page never navigates
            # away, which is a materially different (and generally lower-
            # risk) shape than the same-tab silent redirect this control is
            # really about. Not this probe's call to make either way — left
            # for the human attestor rather than guessed at.
            return DynamicFinding(
                control_id=control_id, verdict=Verdict.NOT_TESTED, rule_id=RULE_ID,
                url=url, method="GET", severity=severity,
                note=f"The outbound link found (target=_blank, {external_href}) opens in a new tab — "
                     "this probe only assesses same-tab navigation, where a silent redirect actually "
                     "takes the user away from the app",
                confidence=0.3,
            )

        before_url = page.url
        try:
            await page.click(f'a[href="{external_href}"]', timeout=CLICK_TIMEOUT_MS)
        except Exception as exc:
            return DynamicFinding(
                control_id=control_id, verdict=Verdict.NOT_TESTED, rule_id=RULE_ID,
                url=url, method="GET", severity=severity,
                note=f"Could not click the outbound link ({external_href}) to observe navigation behavior: {exc}",
                confidence=0.2,
            )

        try:
            await page.wait_for_timeout(POST_CLICK_SETTLE_MS)
        except Exception:
            pass

        after_url = page.url
        after_host = _host(after_url)
        external_host = _host(external_href)

        if after_url != before_url and after_host and after_host == external_host:
            return DynamicFinding(
                control_id=control_id, verdict=Verdict.FAIL, rule_id=RULE_ID,
                url=url, method="GET", severity=severity,
                note=f"Clicking an outbound link to {external_host} navigated the page there immediately, "
                     "with no interstitial or confirmation step observed in between — a silent redirect, "
                     "not a warning the user could cancel",
                confidence=0.75, payload=external_href, evidence_type="response_diff",
                proof={"before_url": before_url, "after_url": after_url, "external_host": external_host},
            )

        return DynamicFinding(
            control_id=control_id, verdict=Verdict.PASS, rule_id=RULE_ID,
            url=url, method="GET", severity=severity,
            note=f"Clicking an outbound link to {external_host} did not immediately navigate the page "
                 "there — consistent with an interstitial intercepting the click, but this probe can't "
                 "confirm the interstitial is real and its cancel option actually works; a human should "
                 "still look at what's on the page before trusting this",
            confidence=0.45, payload=external_href, evidence_type="response_diff",
            proof={"before_url": before_url, "after_url": after_url, "external_host": external_host},
        )
    finally:
        await page.close()
