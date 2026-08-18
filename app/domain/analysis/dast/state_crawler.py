"""Track C6 — state/form-transition crawl.

The regex crawler (crawler.py) and headless-browser crawler
(browser_crawler.py) only ever discover pages reachable by *following a GET
link* — a same-origin breadth-first walk over <a href>. Anything that only
becomes reachable after *submitting* a form is invisible to that walk: a
search-results page, step 2 of a checkout (cart -> address -> payment), a
password-reset confirmation page reached after the "request reset" form is
posted, or simply the authenticated dashboard a login form redirects to.
crawler.py's forms are captured but deliberately never submitted there (see
its docstring) — Phase 2A/2B decided what, if anything, to do with a
discovered form, and xss_probe.run_stored_xss_probe is the first thing that
ever submits one (an XSS marker, to test reflection).

This module is the second thing: it submits each already-discovered form
once with benign, non-adversarial placeholder values (this is not a
vulnerability probe — xss_probe.py already owns that; this only exists to
see what page comes *next*), follows the resulting response, and extracts
whatever new links/forms that page reveals. Each newly discovered form can
itself be chained one level further (bounded by max_depth), which is what
turns a single login/search/"add to cart" form into a multi-step
login -> dashboard -> "update profile" chain instead of stopping at the
first page past it.

Deliberately not a general state machine: no notion of form *sequencing*
beyond "submit, see what's next, submit that too" — no business-logic
modeling per target, just enough to reach flows like password-reset and
checkout that a pure link-following crawl can't.

Side-effecting by nature (it submits real forms against the live target),
so — same posture as xss_probe.py, race_probe.py, and every other
side-effect check in this engine — it's gated behind active_mode and a
caller that doesn't opt in gets an empty result, not a silent partial one.
"""
import asyncio
import logging
import re
from dataclasses import dataclass, field
from typing import Dict, List, Set, Tuple

from app.domain.analysis.dast.crawler import (
    DiscoveredForm,
    _extract_forms,
    _extract_links,
    _same_origin,
)
from app.domain.analysis.dast.session import DastSession

logger = logging.getLogger(__name__)

DEFAULT_MAX_FORMS = 5
DEFAULT_MAX_DEPTH = 2

_CSRF_NAME_HINTS = ("csrf", "xsrf", "authenticity_token", "requestverificationtoken", "_token")
# Benign, non-adversarial value dropped into every non-CSRF field before
# submitting — the goal is reaching the *next* page in a flow, not probing
# for a specific vulnerability class, so a plain value that satisfies most
# server-side "required"/basic-format checks is enough. Deliberately not
# XSS/SQLi-shaped: that's xss_probe.py's job, using its own session.
_PLACEHOLDER_VALUE = "dastprobe1"

_INPUT_TAG_RE = re.compile(r'<input\b[^>]*>', re.IGNORECASE)
_INPUT_ATTR_RE = re.compile(r'([\w-]+)\s*=\s*["\']([^"\']*)["\']')


def _extract_current_field_values(html: str) -> Dict[str, str]:
    """Same shape as xss_probe._extract_current_field_values — a fresh GET
    of the form's source page, right before submitting, so a rotated CSRF
    token (or any other server-set hidden value) gets picked up instead of
    the possibly-stale value the seed DiscoveredForm carries."""
    fields: Dict[str, str] = {}
    for tag_match in _INPUT_TAG_RE.finditer(html):
        attrs = dict(_INPUT_ATTR_RE.findall(tag_match.group(0)))
        name = attrs.get("name")
        if name:
            fields[name] = attrs.get("value", "")
    return fields


@dataclass
class FormTransitionResult:
    urls: List[str] = field(default_factory=list)
    forms: List[DiscoveredForm] = field(default_factory=list)


def _build_submission_data(form: DiscoveredForm, current_fields: Dict[str, str]) -> Dict[str, str]:
    field_names = current_fields.keys() if current_fields else form.fields
    return {
        name: (
            current_fields.get(name, "") if any(hint in name.lower() for hint in _CSRF_NAME_HINTS)
            else _PLACEHOLDER_VALUE
        )
        for name in field_names
    }


def _form_key(form: DiscoveredForm) -> Tuple[str, str]:
    return (form.method.upper(), form.action_url)


async def crawl_form_transitions(
    session: DastSession,
    seed_forms: List[DiscoveredForm],
    origin_url: str,
    *,
    active_mode: bool = False,
    max_forms: int = DEFAULT_MAX_FORMS,
    max_depth: int = DEFAULT_MAX_DEPTH,
    request_delay: float = 0.0,
) -> FormTransitionResult:
    """Submits up to max_forms distinct forms (BFS over form-submission ->
    next-page-forms, bounded to max_depth chained submissions), returning
    every new same-origin URL/form the resulting pages revealed.

    active_mode=False (the default, matching every other side-effecting
    check here) returns an empty result immediately — no request is ever
    sent — rather than raising, so a caller can unconditionally invoke this
    after a crawl and let active_mode decide whether it does anything, the
    same shape run_stored_xss_probe/run_race_probe already follow.
    """
    result = FormTransitionResult()
    if not active_mode or not seed_forms:
        return result

    submitted: Set[Tuple[str, str]] = set()
    seen_urls: Set[str] = {origin_url}
    queue: List[Tuple[DiscoveredForm, int]] = [(f, 0) for f in seed_forms]

    while queue and len(submitted) < max_forms:
        form, depth = queue.pop(0)
        key = _form_key(form)
        if key in submitted:
            continue
        if not _same_origin(origin_url, form.action_url):
            continue
        if submitted and request_delay:
            await asyncio.sleep(request_delay)
        submitted.add(key)

        try:
            source_resp = await session.request("GET", form.source_url)
            current_fields = _extract_current_field_values(source_resp.text)
        except Exception:
            current_fields = {}
        submit_data = _build_submission_data(form, current_fields)

        try:
            resp = await session.request(
                form.method, form.action_url, data=submit_data, follow_redirects=True,
            )
        except Exception as exc:
            logger.debug(f"State-crawl form submission failed for {form.action_url}: {session.redact(str(exc))}")
            continue

        content_type = resp.headers.get("content-type", "")
        if content_type and "html" not in content_type:
            continue
        try:
            html = resp.text
        except Exception:
            continue

        landed_url = str(resp.url)
        if landed_url not in seen_urls:
            seen_urls.add(landed_url)
            result.urls.append(landed_url)

        new_forms = [f for f in _extract_forms(html, landed_url) if _form_key(f) not in submitted]
        for new_form in new_forms:
            if _form_key(new_form) not in {_form_key(rf) for rf in result.forms}:
                result.forms.append(new_form)
            if depth < max_depth:
                queue.append((new_form, depth + 1))

        for link in _extract_links(html, landed_url):
            if not _same_origin(origin_url, link):
                continue
            normalized = link.split("#", 1)[0]
            if normalized not in seen_urls:
                seen_urls.add(normalized)
                result.urls.append(normalized)

    return result
