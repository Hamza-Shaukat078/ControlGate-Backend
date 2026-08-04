"""Phase 3 — conservative same-origin crawler.

Deliberately lightweight regex-based HTML link/form extraction, matching the
same-weight approach already used in logout_discovery.py and dynamic_probe.py,
rather than reusing app/domain/analysis/html_parser.py — that module is a
tree-sitter-backed static-analysis parser built around a file_path and a
SemanticGraph, the wrong shape entirely for a live HTTP response body.

Hard constraints (not suggestions): same-origin only, GET-only discovery,
forms are captured but never submitted here — Phase 2A/2B decide what (if
anything) to do with a discovered form, and only under active_mode.
"""
import asyncio
import logging
import re
from dataclasses import dataclass, field
from typing import List, Set, Tuple
from urllib.parse import urljoin, urlsplit

from app.domain.analysis.dast.session import DastSession

logger = logging.getLogger(__name__)

DEFAULT_MAX_PAGES = 10
DEFAULT_MAX_DEPTH = 2

_LINK_PATTERN = re.compile(r'<a\s+[^>]*href=["\']([^"\'#][^"\']*)["\']', re.IGNORECASE)
_FORM_PATTERN = re.compile(r'<form\b([^>]*)>(.*?)</form>', re.IGNORECASE | re.DOTALL)
_FORM_ACTION_PATTERN = re.compile(r'action=["\']([^"\']*)["\']', re.IGNORECASE)
_FORM_METHOD_PATTERN = re.compile(r'method=["\']([^"\']*)["\']', re.IGNORECASE)
_FIELD_NAME_PATTERN = re.compile(r'<(?:input|select|textarea)\b[^>]*\bname=["\']([^"\']+)["\']', re.IGNORECASE)
_IGNORED_SCHEMES = ("javascript:", "mailto:", "tel:")


@dataclass
class DiscoveredForm:
    action_url: str
    method: str
    fields: List[str]
    source_url: str


@dataclass
class CrawlResult:
    urls: List[str] = field(default_factory=list)
    forms: List[DiscoveredForm] = field(default_factory=list)


def _same_origin(a: str, b: str) -> bool:
    pa, pb = urlsplit(a), urlsplit(b)
    return (pa.scheme, pa.netloc) == (pb.scheme, pb.netloc)


def _extract_links(html: str, base_url: str) -> List[str]:
    links = []
    for match in _LINK_PATTERN.finditer(html):
        href = match.group(1).strip()
        if href.startswith(_IGNORED_SCHEMES):
            continue
        links.append(urljoin(base_url, href))
    return links


def _extract_forms(html: str, base_url: str) -> List[DiscoveredForm]:
    forms = []
    for match in _FORM_PATTERN.finditer(html):
        attrs, body = match.group(1), match.group(2)
        action_match = _FORM_ACTION_PATTERN.search(attrs)
        method_match = _FORM_METHOD_PATTERN.search(attrs)
        action = urljoin(base_url, action_match.group(1)) if action_match else base_url
        method = method_match.group(1).upper() if method_match else "GET"
        fields = _FIELD_NAME_PATTERN.findall(body)
        forms.append(DiscoveredForm(action_url=action, method=method, fields=fields, source_url=base_url))
    return forms


async def crawl(
    session: DastSession,
    start_url: str,
    *,
    max_pages: int = DEFAULT_MAX_PAGES,
    max_depth: int = DEFAULT_MAX_DEPTH,
    request_delay: float = 0.0,
) -> CrawlResult:
    """request_delay: seconds to sleep before each request after the first
    (default 0.0 — no behavior change for direct/test callers). Real scans
    go through scan_service.py, which passes a small nonzero pacing delay so
    a large crawl (dynamic_crawl_max_pages) doesn't fire a rapid-fire burst
    at the target; this loop is already strictly sequential (one request in
    flight at a time), so a plain sleep between iterations is enough — no
    semaphore needed since there's no concurrency here to bound."""
    visited: Set[str] = set()
    queue: List[Tuple[str, int]] = [(start_url.split("#", 1)[0], 0)]
    result = CrawlResult()

    while queue and len(visited) < max_pages:
        url, depth = queue.pop(0)
        if url in visited:
            continue
        if visited and request_delay:
            await asyncio.sleep(request_delay)
        visited.add(url)

        try:
            resp = await session.request("GET", url)
        except Exception as exc:
            logger.debug(f"Crawler could not fetch {url}: {exc}")
            continue

        result.urls.append(url)

        content_type = resp.headers.get("content-type", "")
        if content_type and "html" not in content_type:
            continue
        try:
            html = resp.text
        except Exception:
            continue

        result.forms.extend(_extract_forms(html, url))

        if depth >= max_depth:
            continue
        for link in _extract_links(html, url):
            if not _same_origin(start_url, link):
                continue
            normalized = link.split("#", 1)[0]
            if normalized not in visited:
                queue.append((normalized, depth + 1))

    return result
