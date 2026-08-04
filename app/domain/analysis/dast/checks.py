"""Payload checks (Phase 2A) — single-request/response DAST checks, driven
by queries/dynamic_queries.json. Scenario checks (multi-step, stateful) land
in Phase 2B with their own runner; these are deliberately the simpler kind.
"""
import asyncio
import logging
import re
import secrets
import socket
import ssl
from typing import Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlsplit

from app.domain.analysis.dast.findings import DynamicFinding
from app.domain.analysis.dast.rule_loader import DynamicQueryRule, load_dynamic_queries
from app.domain.analysis.dast.session import DastSession
from app.domain.analysis.dast.verdict import Verdict

logger = logging.getLogger(__name__)

_BLOCKED_STATUS_CODES = {400, 403, 404}
_REDIRECT_STATUS_CODES = {301, 302, 303, 307, 308}

# Same regex weight class as crawler.py — good enough to find *a* state-changing
# form and its fields, not a full HTML parser.
_FORM_TAG_RE = re.compile(r'<form\b([^>]*)>(.*?)</form>', re.IGNORECASE | re.DOTALL)
_FORM_ACTION_ATTR_RE = re.compile(r'action=["\']([^"\']*)["\']', re.IGNORECASE)
_FORM_METHOD_ATTR_RE = re.compile(r'method=["\']([^"\']*)["\']', re.IGNORECASE)
_INPUT_TAG_RE = re.compile(r'<input\b[^>]*>', re.IGNORECASE)
_INPUT_ATTR_RE = re.compile(r'([\w-]+)\s*=\s*["\']([^"\']*)["\']')
_STATE_CHANGING_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
_CSRF_NAME_HINTS = ("csrf", "xsrf", "authenticity_token", "requestverificationtoken")


async def _check_double_decode_bypass(session: DastSession, target_url: str, rule: DynamicQueryRule) -> DynamicFinding:
    control_id = rule.asvs_controls[0]
    base = target_url.rstrip("/")
    single_url = base + rule.single_encoded_suffix
    double_url = base + rule.double_encoded_suffix

    try:
        single_resp = await session.request("GET", single_url, follow_redirects=False)
        double_resp = await session.request("GET", double_url, follow_redirects=False)
    except Exception as exc:
        return DynamicFinding(
            control_id=control_id, verdict=Verdict.NOT_TESTED, rule_id=rule.rule_id, severity=rule.severity,
            url=base, method="GET",
            note=f"Request failed: {session.redact(str(exc))}", confidence=0.3,
        )

    if single_resp.status_code in _BLOCKED_STATUS_CODES and double_resp.status_code not in _BLOCKED_STATUS_CODES:
        return DynamicFinding(
            control_id=control_id, verdict=Verdict.FAIL, rule_id=rule.rule_id, severity=rule.severity,
            url=double_url, method="GET",
            note=f"Single-encoded request was blocked ({single_resp.status_code}) but the double-encoded "
                 f"equivalent returned {double_resp.status_code} — input appears decoded more than once "
                 f"before validation",
            confidence=0.7,
        )
    if single_resp.status_code == double_resp.status_code == 404:
        return DynamicFinding(
            control_id=control_id, verdict=Verdict.NOT_TESTED, rule_id=rule.rule_id, severity=rule.severity,
            url=base, method="GET",
            note="Both encodings returned 404 — no responding endpoint here to compare decode behavior against",
            confidence=0.25,
        )
    if single_resp.status_code == double_resp.status_code:
        return DynamicFinding(
            control_id=control_id, verdict=Verdict.PASS, rule_id=rule.rule_id, severity=rule.severity,
            url=base, method="GET",
            note=f"Single- and double-encoded requests were handled identically (both {single_resp.status_code})",
            confidence=0.6,
        )
    return DynamicFinding(
        control_id=control_id, verdict=Verdict.INCONCLUSIVE, rule_id=rule.rule_id, severity=rule.severity,
        url=base, method="GET",
        note=f"Ambiguous result: single-encoded={single_resp.status_code}, double-encoded={double_resp.status_code}",
        confidence=0.3,
    )


async def _check_crlf_header_reflection(session: DastSession, target_url: str, rule: DynamicQueryRule) -> DynamicFinding:
    control_id = rule.asvs_controls[0]
    marker_value = f"dast-{secrets.token_hex(4)}"
    injected_header = "X-Dast-Probe"
    payload = f"https://example.org/\r\n{injected_header}: {marker_value}"

    observed_response = False
    attempted = False
    for param in rule.candidate_params:
        try:
            resp = await session.request("GET", target_url, params={param: payload}, follow_redirects=False)
        except Exception:
            continue
        attempted = True
        if resp.status_code == 404:
            continue
        observed_response = True
        reflected = resp.headers.get(injected_header.lower())
        if reflected and marker_value in reflected:
            return DynamicFinding(
                control_id=control_id, verdict=Verdict.FAIL, rule_id=rule.rule_id, severity=rule.severity,
                url=str(resp.request.url), method="GET",
                note=f"Marker header reflected literally via query param '{param}' — CRLF from user input "
                     f"reaches a response header unsanitized",
                confidence=0.75,
            )

    if observed_response:
        return DynamicFinding(
            control_id=control_id, verdict=Verdict.PASS, rule_id=rule.rule_id, severity=rule.severity,
            url=target_url, method="GET",
            note="No candidate redirect/reflection query parameter reflected the injected CRLF marker",
            confidence=0.55,
        )
    if attempted:
        return DynamicFinding(
            control_id=control_id, verdict=Verdict.NOT_TESTED, rule_id=rule.rule_id, severity=rule.severity,
            url=target_url, method="GET",
            note="No candidate query parameter was recognized by the target (all returned 404) — "
                 "crawler-discovered parameters (Phase 3) would widen this",
            confidence=0.2,
        )
    return DynamicFinding(
        control_id=control_id, verdict=Verdict.NOT_TESTED, rule_id=rule.rule_id, severity=rule.severity,
        url=target_url, method="GET",
        note="Could not reach the target with any candidate parameter",
        confidence=0.2,
    )


async def _check_open_redirect_live(session: DastSession, target_url: str, rule: DynamicQueryRule) -> DynamicFinding:
    control_id = rule.asvs_controls[0]
    canary = rule.canary_domain
    external_target = f"https://{canary}/"

    observed_response = False
    for param in rule.candidate_params:
        try:
            resp = await session.request("GET", target_url, params={param: external_target}, follow_redirects=False)
        except Exception:
            continue
        if resp.status_code == 404:
            continue
        observed_response = True
        if resp.status_code in _REDIRECT_STATUS_CODES:
            location = resp.headers.get("location", "")
            if canary in location:
                return DynamicFinding(
                    control_id=control_id, verdict=Verdict.FAIL, rule_id=rule.rule_id, severity=rule.severity,
                    url=str(resp.request.url), method="GET",
                    note=f"Param '{param}' drove an unvalidated redirect to the canary domain "
                         f"(Location: {session.redact(location)})",
                    confidence=0.8,
                )

    try:
        resp = await session.request("GET", target_url, headers={"Host": canary}, follow_redirects=False)
        if resp.status_code in _REDIRECT_STATUS_CODES:
            location = resp.headers.get("location", "")
            if canary in location:
                return DynamicFinding(
                    control_id=control_id, verdict=Verdict.FAIL, rule_id=rule.rule_id, severity=rule.severity,
                    url=target_url, method="GET",
                    note=f"A forged Host header reached a redirect Location unchanged "
                         f"({session.redact(location)})",
                    confidence=0.7,
                )
    except Exception:
        pass

    if observed_response:
        return DynamicFinding(
            control_id=control_id, verdict=Verdict.PASS, rule_id=rule.rule_id, severity=rule.severity,
            url=target_url, method="GET",
            note="No candidate redirect parameter or forged Host header produced an unvalidated external redirect",
            confidence=0.55,
        )
    return DynamicFinding(
        control_id=control_id, verdict=Verdict.NOT_TESTED, rule_id=rule.rule_id, severity=rule.severity,
        url=target_url, method="GET",
        note="No candidate redirect parameter was recognized by the target (no confirmed redirect endpoint)",
        confidence=0.25,
    )


def _parse_host_port_scheme(url: str) -> tuple:
    parts = urlsplit(url)
    is_https = parts.scheme == "https"
    port = parts.port or (443 if is_https else 80)
    path = parts.path or "/"
    return parts.hostname, port, is_https, path


def _send_raw_smuggling_probe(host: str, port: int, is_https: bool, payload: bytes) -> str:
    """Blocking raw-socket send/recv — run via asyncio.to_thread. httpx (like
    any well-behaved client) won't let us construct a request with a
    deliberately ambiguous Content-Length/Transfer-Encoding combination, so
    this bypasses it entirely, same rationale as dynamic_probe.py's raw TLS
    socket use for protocol-level checks httpx can't express either."""
    sock = socket.create_connection((host, port), timeout=8.0)
    try:
        if is_https:
            context = ssl.create_default_context()
            sock = context.wrap_socket(sock, server_hostname=host)
        sock.sendall(payload)
        sock.settimeout(4.0)
        chunks = []
        try:
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                chunks.append(chunk)
        except (socket.timeout, ssl.SSLError):
            pass
        return b"".join(chunks).decode("utf-8", errors="replace")
    finally:
        sock.close()


async def _check_request_smuggling(session: DastSession, target_url: str, rule: DynamicQueryRule) -> DynamicFinding:
    control_id = rule.asvs_controls[0]
    host, port, is_https, path = _parse_host_port_scheme(target_url)
    marker = f"dast-smuggle-{secrets.token_hex(4)}"

    # CL.TE-style ambiguity: Content-Length says the body is 4 bytes ("0\r\n"
    # doesn't match), but Transfer-Encoding: chunked says to read a chunked
    # body instead — a front-end/back-end pair that parse this differently
    # can end up treating the trailing marker request as part of the first
    # request's body, or the reverse. Either disagreement can leak the
    # marker into the wrong response.
    probe = (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Content-Length: 4\r\n"
        f"Transfer-Encoding: chunked\r\n"
        f"Connection: keep-alive\r\n"
        f"\r\n"
        f"0\r\n\r\n"
        f"GET /{marker} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Connection: close\r\n"
        f"\r\n"
    ).encode()

    try:
        raw_response = await asyncio.wait_for(
            asyncio.to_thread(_send_raw_smuggling_probe, host, port, is_https, probe),
            timeout=10.0,
        )
    except Exception as exc:
        return DynamicFinding(
            control_id=control_id, verdict=Verdict.NOT_TESTED, rule_id=rule.rule_id, severity=rule.severity,
            url=target_url, method="RAW",
            note=f"Could not complete the smuggling probe: {session.redact(str(exc))}", confidence=0.2,
        )

    if marker in raw_response:
        return DynamicFinding(
            control_id=control_id, verdict=Verdict.FAIL, rule_id=rule.rule_id, severity=rule.severity,
            url=target_url, method="RAW",
            note="An ambiguous Content-Length/Transfer-Encoding request caused a smuggled "
                 "follow-up request's marker to leak into the response — indicates the "
                 "server/proxy chain disagrees on request framing (best-effort indicator, "
                 "not a confirmed exploit chain)",
            confidence=0.6,
        )
    return DynamicFinding(
        control_id=control_id, verdict=Verdict.PASS, rule_id=rule.rule_id, severity=rule.severity,
        url=target_url, method="RAW",
        note="No smuggled-request marker observed in the response to an ambiguous "
             "Content-Length/Transfer-Encoding request",
        confidence=0.45,
    )


def _extract_input_fields(form_body: str) -> Dict[str, str]:
    fields: Dict[str, str] = {}
    for tag_match in _INPUT_TAG_RE.finditer(form_body):
        attrs = dict(_INPUT_ATTR_RE.findall(tag_match.group(0)))
        name = attrs.get("name")
        if name:
            fields[name] = attrs.get("value", "")
    return fields


def _find_state_changing_form(html: str, base_url: str) -> Optional[Tuple[str, str, Dict[str, str]]]:
    for match in _FORM_TAG_RE.finditer(html):
        attrs, body = match.group(1), match.group(2)
        method_match = _FORM_METHOD_ATTR_RE.search(attrs)
        method = method_match.group(1).upper() if method_match else "GET"
        if method not in _STATE_CHANGING_METHODS:
            continue
        action_match = _FORM_ACTION_ATTR_RE.search(attrs)
        action_url = urljoin(base_url, action_match.group(1)) if action_match else base_url
        return method, action_url, _extract_input_fields(body)
    return None


async def _check_csrf_token_validation(session: DastSession, target_url: str, rule: DynamicQueryRule) -> DynamicFinding:
    """Phase 3 — V3.5.1. Fetches target_url, finds the first state-changing
    form containing a CSRF-token-shaped hidden field, then resubmits it with
    that field dropped. requires_active_mode in dynamic_queries.json because
    a genuinely unprotected form really does perform the action."""
    control_id = rule.asvs_controls[0] if rule.asvs_controls else rule.rule_id

    try:
        resp = await session.request("GET", target_url)
    except Exception as exc:
        return DynamicFinding(
            control_id=control_id, verdict=Verdict.NOT_TESTED, rule_id=rule.rule_id, severity=rule.severity,
            url=target_url, method="GET",
            note=f"Could not fetch the page to look for a form: {session.redact(str(exc))}", confidence=0.2,
        )
    if resp.status_code == 404 or "html" not in resp.headers.get("content-type", "html"):
        return DynamicFinding(
            control_id=control_id, verdict=Verdict.NOT_TESTED, rule_id=rule.rule_id, severity=rule.severity,
            url=target_url, method="GET",
            note="Page was unreachable or not HTML — nothing to inspect for a CSRF-protected form",
            confidence=0.2,
        )

    form = _find_state_changing_form(resp.text, target_url)
    if form is None:
        return DynamicFinding(
            control_id=control_id, verdict=Verdict.NOT_TESTED, rule_id=rule.rule_id, severity=rule.severity,
            url=target_url, method="GET",
            note="No state-changing (POST/PUT/PATCH/DELETE) form found on this page to test",
            confidence=0.2,
        )
    method, action_url, fields = form
    csrf_field_name = next(
        (name for name in fields if any(hint in name.lower() for hint in _CSRF_NAME_HINTS)), None,
    )
    if csrf_field_name is None:
        return DynamicFinding(
            control_id=control_id, verdict=Verdict.NOT_TESTED, rule_id=rule.rule_id, severity=rule.severity,
            url=action_url, method=method,
            note="Form has no CSRF-token-shaped hidden field — can't confirm or deny token validation this "
                 "way (the app may rely on SameSite cookies instead, which this check doesn't evaluate)",
            confidence=0.2,
        )

    tampered_data = {name: (value or "dast-probe-value") for name, value in fields.items() if name != csrf_field_name}
    try:
        tampered_resp = await session.request(method, action_url, data=tampered_data, follow_redirects=False)
    except Exception as exc:
        return DynamicFinding(
            control_id=control_id, verdict=Verdict.NOT_TESTED, rule_id=rule.rule_id, severity=rule.severity,
            url=action_url, method=method,
            note=f"Resubmitting the form without the token failed: {session.redact(str(exc))}", confidence=0.2,
        )

    if tampered_resp.status_code in (400, 401, 403, 419, 422):
        return DynamicFinding(
            control_id=control_id, verdict=Verdict.PASS, rule_id=rule.rule_id, severity=rule.severity,
            url=action_url, method=method,
            note=f"Submitting the form without '{csrf_field_name}' was rejected ({tampered_resp.status_code})",
            confidence=0.6,
        )
    if tampered_resp.status_code < 400:
        return DynamicFinding(
            control_id=control_id, verdict=Verdict.FAIL, rule_id=rule.rule_id, severity=rule.severity,
            url=action_url, method=method,
            note=f"Submitting the form without '{csrf_field_name}' returned {tampered_resp.status_code} — "
                 f"the token doesn't appear to be validated server-side (a single test run; a session-bound "
                 f"SameSite cookie could still be providing real protection this check can't see)",
            confidence=0.6,
        )
    return DynamicFinding(
        control_id=control_id, verdict=Verdict.INCONCLUSIVE, rule_id=rule.rule_id, severity=rule.severity,
        url=action_url, method=method,
        note=f"Ambiguous response to the tampered submission: {tampered_resp.status_code}", confidence=0.3,
    )


async def _check_unauthenticated_access(
    session: DastSession, target_url: str, rule: DynamicQueryRule,
) -> DynamicFinding:
    """Phase 3 — V8.2.1 forced-browsing/function-level access control. Requests
    target_url once through the scan's authenticated session, once with no
    credentials at all (DastSession.request_unauthenticated), and compares.
    Only meaningful when the scan actually configured an authenticated
    session — otherwise both requests would be the same request twice."""
    control_id = rule.asvs_controls[0] if rule.asvs_controls else rule.rule_id

    if not session.is_authenticated:
        return DynamicFinding(
            control_id=control_id, verdict=Verdict.NOT_CONFIGURED, rule_id=rule.rule_id, severity=rule.severity,
            url=target_url, method="GET",
            note="This scan has no authenticated session configured, so there's no authenticated baseline "
                 "to compare an anonymous request against",
            confidence=1.0,
        )

    try:
        authed_resp = await session.request("GET", target_url, follow_redirects=False)
    except Exception as exc:
        return DynamicFinding(
            control_id=control_id, verdict=Verdict.NOT_TESTED, rule_id=rule.rule_id, severity=rule.severity,
            url=target_url, method="GET",
            note=f"Authenticated baseline request failed: {session.redact(str(exc))}", confidence=0.2,
        )
    if not (200 <= authed_resp.status_code < 300):
        return DynamicFinding(
            control_id=control_id, verdict=Verdict.NOT_TESTED, rule_id=rule.rule_id, severity=rule.severity,
            url=target_url, method="GET",
            note=f"Authenticated request itself returned {authed_resp.status_code} — no confirmed-reachable "
                 f"baseline to compare an anonymous request against",
            confidence=0.25,
        )

    try:
        anon_resp = await session.request_unauthenticated("GET", target_url, follow_redirects=False)
    except Exception as exc:
        return DynamicFinding(
            control_id=control_id, verdict=Verdict.NOT_TESTED, rule_id=rule.rule_id, severity=rule.severity,
            url=target_url, method="GET",
            note=f"Anonymous request failed: {session.redact(str(exc))}", confidence=0.2,
        )

    if anon_resp.status_code in (401, 403) or anon_resp.status_code in _REDIRECT_STATUS_CODES:
        return DynamicFinding(
            control_id=control_id, verdict=Verdict.PASS, rule_id=rule.rule_id, severity=rule.severity,
            url=target_url, method="GET",
            note=f"Anonymous request was denied/redirected ({anon_resp.status_code}) where the "
                 f"authenticated one succeeded ({authed_resp.status_code})",
            confidence=0.6,
        )
    if 200 <= anon_resp.status_code < 300:
        return DynamicFinding(
            control_id=control_id, verdict=Verdict.FAIL, rule_id=rule.rule_id, severity=rule.severity,
            url=target_url, method="GET",
            note=f"Anonymous request also returned {anon_resp.status_code} — this endpoint doesn't appear "
                 f"to actually require authentication",
            confidence=0.65,
        )
    return DynamicFinding(
        control_id=control_id, verdict=Verdict.INCONCLUSIVE, rule_id=rule.rule_id, severity=rule.severity,
        url=target_url, method="GET",
        note=f"Ambiguous anonymous response: {anon_resp.status_code} "
             f"(authenticated response was {authed_resp.status_code})",
        confidence=0.3,
    )


_CHECK_FUNCTIONS = {
    "DOUBLE_DECODE_BYPASS": _check_double_decode_bypass,
    "CRLF_HEADER_REFLECTION": _check_crlf_header_reflection,
    "OPEN_REDIRECT_LIVE": _check_open_redirect_live,
    "REQUEST_SMUGGLING": _check_request_smuggling,
    "CSRF_TOKEN_NOT_VALIDATED": _check_csrf_token_validation,
    "UNAUTHENTICATED_ACCESS_ALLOWED": _check_unauthenticated_access,
}


async def run_payload_checks(
    session: DastSession,
    target_urls,  # str | List[str] — a single URL (Phase 2A) or crawler-discovered URLs (Phase 3)
    rules: Optional[Dict[str, DynamicQueryRule]] = None,
    active_mode: bool = False,
) -> List[DynamicFinding]:
    if rules is None:
        rules = load_dynamic_queries()
    urls = [target_urls] if isinstance(target_urls, str) else list(target_urls)

    findings: List[DynamicFinding] = []
    for url in urls:
        for rule_id, check_func in _CHECK_FUNCTIONS.items():
            rule = rules.get(rule_id)
            if rule is None or rule.check_type != "payload":
                continue
            if rule.requires_active_mode and not active_mode:
                findings.append(DynamicFinding(
                    control_id=(rule.asvs_controls[0] if rule.asvs_controls else rule_id),
                    verdict=Verdict.SKIPPED_REQUIRES_ACTIVE_AUTHORIZATION, rule_id=rule_id,
                    url=url, method="GET", severity=rule.severity,
                    note="This check has side effects and active_mode was not enabled for this scan",
                    confidence=1.0,
                ))
                continue
            try:
                findings.append(await check_func(session, url, rule))
            except Exception as exc:
                logger.warning(f"DAST payload check {rule_id} raised unexpectedly: {exc}")
                findings.append(DynamicFinding(
                    control_id=(rule.asvs_controls[0] if rule.asvs_controls else rule_id),
                    verdict=Verdict.NOT_TESTED, rule_id=rule_id, url=url, method="GET",
                    severity=rule.severity, note=f"Check raised an unexpected error: {session.redact(str(exc))}",
                    confidence=0.2,
                ))
    return findings
