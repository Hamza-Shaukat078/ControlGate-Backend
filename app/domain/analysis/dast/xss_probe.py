"""Stored-XSS probe (Phase 4, V1.2.1) — the reason crawler.py's forms were
ever captured in the first place (see crawler.py's docstring: "forms are
captured but never submitted here — Phase 2A/2B decide what (if anything)
to do with a discovered form, and only under active_mode").

Submits a DiscoveredForm with a unique, inert, HTML-shaped marker in every
non-CSRF field, then checks whether that marker comes back *unescaped* —
either immediately in the submission response (reflected) or on any other
page the crawler already visited (stored). No real browser/JS engine is
involved: an unescaped `<dastxss id="...">` tag in a later response is
treated as proof the app renders this input into HTML without encoding it,
the same signal a real `<script>` payload would rely on, without actually
constructing one.

Requires active_mode: submitting a form is a real state change (a comment
posted, a profile field overwritten, ...), same risk class as the CSRF and
race-probe checks.
"""
import logging
import re
import secrets
from typing import Dict, List

from app.domain.analysis.dast.crawler import DiscoveredForm
from app.domain.analysis.dast.findings import DynamicFinding
from app.domain.analysis.dast.session import DastSession
from app.domain.analysis.dast.verdict import Verdict

logger = logging.getLogger(__name__)

_CSRF_NAME_HINTS = ("csrf", "xsrf", "authenticity_token", "requestverificationtoken")

_INPUT_TAG_RE = re.compile(r'<input\b[^>]*>', re.IGNORECASE)
_INPUT_ATTR_RE = re.compile(r'([\w-]+)\s*=\s*["\']([^"\']*)["\']')

_MAX_REFLECTION_CHECK_URLS = 10


def _extract_current_field_values(html: str) -> Dict[str, str]:
    fields: Dict[str, str] = {}
    for tag_match in _INPUT_TAG_RE.finditer(html):
        attrs = dict(_INPUT_ATTR_RE.findall(tag_match.group(0)))
        name = attrs.get("name")
        if name:
            fields[name] = attrs.get("value", "")
    return fields


def _build_marker_payload(marker: str) -> str:
    # An inert, non-executing tag: no real script runs, but if it survives
    # into a later response unescaped, real HTML/JS did too.
    return f'"><dastxss id="{marker}">probe</dastxss>'


async def run_stored_xss_probe(
    session: DastSession,
    form: DiscoveredForm,
    reflection_check_urls: List[str],
    *,
    control_id: str = "V1.2.1",
    severity: str = "high",
    active_mode: bool = False,
) -> DynamicFinding:
    if not active_mode:
        return DynamicFinding(
            control_id=control_id, verdict=Verdict.SKIPPED_REQUIRES_ACTIVE_AUTHORIZATION,
            rule_id="STORED_XSS_PROBE", url=form.action_url, method=form.method, severity=severity,
            note="Submitting a discovered form is a real state change and active_mode was not enabled "
                 "for this scan",
            confidence=1.0,
        )

    marker = f"dastxss{secrets.token_hex(4)}"
    payload = _build_marker_payload(marker)

    try:
        source_resp = await session.request("GET", form.source_url)
        current_fields = _extract_current_field_values(source_resp.text)
    except Exception:
        current_fields = {}

    # Prefer field names/values from a fresh GET of the source page (picks up
    # e.g. a rotated CSRF token); fall back to the crawler's captured names
    # with no values if that GET failed.
    field_names = current_fields.keys() if current_fields else form.fields
    submit_data = {
        name: (
            current_fields.get(name, "") if any(hint in name.lower() for hint in _CSRF_NAME_HINTS) else payload
        )
        for name in field_names
    }

    try:
        submit_resp = await session.request(form.method, form.action_url, data=submit_data, follow_redirects=True)
    except Exception as exc:
        return DynamicFinding(
            control_id=control_id, verdict=Verdict.NOT_TESTED, rule_id="STORED_XSS_PROBE",
            url=form.action_url, method=form.method, severity=severity,
            note=f"Form submission failed: {session.redact(str(exc))}", confidence=0.2,
        )

    if payload in submit_resp.text:
        return DynamicFinding(
            control_id=control_id, verdict=Verdict.FAIL, rule_id="STORED_XSS_PROBE",
            url=form.action_url, method=form.method, severity=severity,
            note=f"Submission marker came back unescaped in the submission response itself — "
                 f"reflected, unsanitized HTML output (marker: {marker})",
            confidence=0.7,
        )

    checked = 0
    for check_url in reflection_check_urls[:_MAX_REFLECTION_CHECK_URLS]:
        try:
            resp = await session.request("GET", check_url)
        except Exception:
            continue
        checked += 1
        if payload in resp.text:
            return DynamicFinding(
                control_id=control_id, verdict=Verdict.FAIL, rule_id="STORED_XSS_PROBE",
                url=check_url, method="GET", severity=severity,
                note=f"Submission marker came back unescaped on a different page ({check_url}) — "
                     f"stored, unsanitized HTML output (marker: {marker}, submitted via {form.action_url})",
                confidence=0.75,
            )

    if checked == 0:
        return DynamicFinding(
            control_id=control_id, verdict=Verdict.INCONCLUSIVE, rule_id="STORED_XSS_PROBE",
            url=form.action_url, method=form.method, severity=severity,
            note="Form was submitted but no other page could be re-fetched to check for stored "
                 "reflection of the marker",
            confidence=0.3,
        )

    return DynamicFinding(
        control_id=control_id, verdict=Verdict.PASS, rule_id="STORED_XSS_PROBE",
        url=form.action_url, method=form.method, severity=severity,
        note=f"Marker was not found unescaped in the submission response or any of {checked} "
             f"re-checked page(s)",
        confidence=0.5,
    )
