"""SSRF confirmation via out-of-band collaborator callback (Track A2,
V5.3.2). See collaborator.py's module docstring for why this needs an
out-of-band signal at all, unlike every other check in this engine.

Candidate param names are blindly guessed the way OPEN_REDIRECT_LIVE's are
(a real, if inexhaustive, semantic universe exists — url/webhook/callback/
avatar_url/... are genuinely common SSRF-prone param names), not
param-dependent-only like REFLECTED_XSS_LIVE/SQL_INJECTION_LIVE.

All candidate probes fire first, *then* a single wait window elapses before
checking for callbacks — waiting after each individual param would multiply
the wait by the candidate-param count for no benefit (the target could take
its time regardless of which param triggered the fetch).

requires_active_mode: causing the target to make a real outbound network
request is a side effect on infrastructure this scan doesn't own — same
risk class as CSRF_TOKEN_NOT_VALIDATED/SQL_INJECTION_LIVE.
"""
import asyncio
import logging
from typing import Dict, List, Optional

from app.domain.analysis.dast.collaborator import CollaboratorServer
from app.domain.analysis.dast.findings import DynamicFinding
from app.domain.analysis.dast.session import DastSession
from app.domain.analysis.dast.verdict import Verdict

logger = logging.getLogger(__name__)

RULE_ID = "SSRF_LIVE"
DEFAULT_CONTROL_ID = "V5.3.2"
DEFAULT_CALLBACK_WAIT_SECONDS = 2.0

_SSRF_CANDIDATE_PARAMS = (
    "url", "uri", "link", "src", "image", "avatar", "avatar_url", "callback",
    "webhook", "feed", "endpoint", "target", "fetch", "proxy", "redirect", "next",
)


async def run_ssrf_probe(
    session: DastSession,
    target_url: str,
    collaborator: CollaboratorServer,
    *,
    control_id: str = DEFAULT_CONTROL_ID,
    severity: str = "high",
    active_mode: bool = False,
    callback_wait_seconds: float = DEFAULT_CALLBACK_WAIT_SECONDS,
    candidate_params: Optional[List[str]] = None,
) -> DynamicFinding:
    if not active_mode:
        return DynamicFinding(
            control_id=control_id, verdict=Verdict.SKIPPED_REQUIRES_ACTIVE_AUTHORIZATION,
            rule_id=RULE_ID, url=target_url, method="GET", severity=severity,
            note="This check makes the target fetch an external URL and active_mode was not enabled "
                 "for this scan",
            confidence=1.0,
        )

    params_to_try = candidate_params if candidate_params is not None else list(_SSRF_CANDIDATE_PARAMS)
    tokens_by_param: Dict[str, str] = {}
    observed_response = False

    for param in params_to_try:
        token = collaborator.new_token()
        callback_url = collaborator.callback_url(token)
        try:
            resp = await session.request("GET", target_url, params={param: callback_url}, follow_redirects=False)
        except Exception:
            continue
        if resp.status_code == 404:
            continue
        observed_response = True
        tokens_by_param[param] = token

    if not observed_response:
        return DynamicFinding(
            control_id=control_id, verdict=Verdict.NOT_TESTED, rule_id=RULE_ID, severity=severity,
            url=target_url, method="GET",
            note="No candidate URL-shaped parameter was recognized by the target (no confirmed endpoint)",
            confidence=0.2,
        )

    if callback_wait_seconds:
        await asyncio.sleep(callback_wait_seconds)

    for param, token in tokens_by_param.items():
        hits = collaborator.hits_for(token)
        if hits:
            hit = hits[0]
            return DynamicFinding(
                control_id=control_id, verdict=Verdict.FAIL, rule_id=RULE_ID, severity=severity,
                url=target_url, method="GET",
                note=f"Param '{param}' caused the target to fetch the injected callback URL — confirmed "
                     f"out-of-band via a real inbound request from {hit.remote_addr} "
                     f"({len(hits)} callback(s) total) — the target performs server-side requests to "
                     f"user-controlled URLs",
                confidence=0.85,
            )

    return DynamicFinding(
        control_id=control_id, verdict=Verdict.PASS, rule_id=RULE_ID, severity=severity,
        url=target_url, method="GET",
        note=f"No candidate parameter caused a callback to the collaborator within "
             f"{callback_wait_seconds}s — either the target doesn't perform server-side fetches from "
             f"these params, or the fetch happens somewhere the collaborator isn't reachable from",
        confidence=0.4,
    )
