"""Track C2 — headless-browser crawling for JS-rendered (SPA) targets.

crawler.py's regex crawler only ever sees the raw HTTP response body. A
React/Vue SPA that renders its content via client-side JavaScript after page
load has almost nothing in that raw body — the crawler sees an empty shell
(a <div id="root"></div> and a <script> tag). This module launches a real
headless Chromium, lets each page's own JS run to completion, and feeds the
*rendered* DOM (page.content(), after JS execution) into crawler.py's
existing _extract_links/_extract_forms regex functions — the only thing
that changes versus crawler.py's crawl() is where the HTML comes from.
Same CrawlResult/DiscoveredForm shape, same same-origin/GET-only/
forms-captured-never-submitted invariants crawler.py's own docstring
establishes.

One browser launched per scan, not per page: playwright.chromium.launch()
and browser.new_context() happen once, up front, and every page visited in
the crawl loop is a new tab (context.new_page()) inside that same shared
context — launching a fresh browser process per page would be prohibitively
slow (real OS process startup) for zero benefit, since a persistent context
is exactly what lets cookies/auth state carry across pages the way a normal
browser session would.

Auth reuse, not re-implementation: this never performs its own login flow.
Whatever DastSession already authenticated with gets exported once via
DastSession.browser_auth_state() (cookies for form_login,
Authorization header for bearer) and imported into the Playwright context
before the crawl starts — see that method's docstring. Keeps login logic in
exactly one place (DastSession._authenticate()).
"""
import logging
from typing import Dict, List, Optional, Set, Tuple

from app.domain.analysis.dast.crawler import (
    DEFAULT_MAX_DEPTH,
    DEFAULT_MAX_PAGES,
    CrawlResult,
    _extract_forms,
    _extract_links,
    _same_origin,
)

logger = logging.getLogger(__name__)

# Generous but bounded: an SPA's own XHR/fetch calls need time to settle
# after networkidle before the DOM is considered "rendered", but a page that
# never goes idle (long-poll/websocket-heavy apps) must not stall the whole
# crawl indefinitely.
PAGE_LOAD_TIMEOUT_MS = 15_000


async def crawl_with_browser(
    start_url: str,
    *,
    max_pages: int = DEFAULT_MAX_PAGES,
    max_depth: int = DEFAULT_MAX_DEPTH,
    cookies: Optional[List[dict]] = None,
    extra_headers: Optional[Dict[str, str]] = None,
) -> CrawlResult:
    """Same traversal shape as crawler.crawl() (BFS, max_pages/max_depth caps,
    same-origin only), driven by a headless Chromium instead of httpx.

    cookies/extra_headers: whatever DastSession.browser_auth_state()
    returned for the primary actor — None/empty means an unauthenticated
    crawl, same as an ActorConfig with auth_mode=NONE.
    """
    # Deferred import: playwright is an optional dependency (requirements.txt),
    # and callers must be able to construct/import this module without it
    # installed — the caller (scan_service._run_dynamic_checks) already
    # wraps this whole call in a try/except for exactly that reason.
    from playwright.async_api import async_playwright

    visited: Set[str] = set()
    queue: List[Tuple[str, int]] = [(start_url.split("#", 1)[0], 0)]
    result = CrawlResult()

    async with async_playwright() as pw:
        browser = await pw.chromium.launch(headless=True)
        try:
            context = await browser.new_context()
            if cookies:
                await context.add_cookies(cookies)
            if extra_headers:
                await context.set_extra_http_headers(extra_headers)

            while queue and len(visited) < max_pages:
                url, depth = queue.pop(0)
                if url in visited:
                    continue
                visited.add(url)

                html = await _render_page(context, url)
                if html is None:
                    continue

                result.urls.append(url)
                result.forms.extend(_extract_forms(html, url))

                if depth >= max_depth:
                    continue
                for link in _extract_links(html, url):
                    if not _same_origin(start_url, link):
                        continue
                    normalized = link.split("#", 1)[0]
                    if normalized not in visited:
                        queue.append((normalized, depth + 1))
        finally:
            await browser.close()

    return result


async def _render_page(context, url: str) -> Optional[str]:
    """One tab per page, closed immediately after — keeps memory bounded
    across a crawl of up to max_pages pages without needing a pool."""
    page = await context.new_page()
    try:
        try:
            await page.goto(url, wait_until="networkidle", timeout=PAGE_LOAD_TIMEOUT_MS)
        except Exception as exc:
            logger.debug(f"Browser crawler could not load {url}: {exc}")
            return None
        return await page.content()
    finally:
        await page.close()
