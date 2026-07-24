"""
Capability Checker — answers "is X implemented (correctly)?" questions that
config_inspector.py and the taint engine can't: ASVS controls whose evidence is
the presence of a *correct* implementation, not a dangerous pattern.

These controls are tagged `finding_polarity: "compliant"` in queries.json and
today only match a tiny hand-picked keyword list — and even a real regex match
never survives SliceClassifier's vulnerability gate (is_vulnerable=False for a
"this isn't a vulnerability" verdict discards the finding entirely, see
semantic_engine/classifier/classifier.py::_combine_results). This module is a
separate side-channel, same shape as ConfigInspector/DependencyScanner: it never
touches the taint engine or SliceClassifier, so that discard problem doesn't
apply to it.

Detection is two-stage per control:
  1. Cheap candidate-file selection: a widened keyword list (superset of the
     old single-purpose regex) OR a file whose path looks topically relevant
     (auth/session/password/security/middleware/user) — the "topical net"
     approach, so differently-named implementations aren't invisible just
     because they don't match one literal identifier.
  2. One LLM call per control that found candidates, asking the direct
     question and requiring it to cite exact file/line — never trusting mere
     keyword presence as proof of a correct implementation.
"""
import logging
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

_ALWAYS_FILE_HINTS = ("auth", "login", "session", "password", "security", "middleware", "user")
_MAX_CONTEXT_CHARS = 12_000
_MAX_CANDIDATE_FILES = 6


@dataclass
class CapabilityFinding:
    control_id: str
    verdict: str  # "pass" | "fail"
    file: Optional[str] = None
    line: Optional[int] = None
    note: str = ""
    confidence: float = 0.65


_CAPABILITY_CHECKS: dict[str, dict] = {
    "V6.2.2": {
        "question": "Does this codebase expose a password-change endpoint or function "
                    "(distinct from initial registration) that lets an authenticated user "
                    "change their password?",
        "keywords": ["change_password", "changepassword", "update_password", "reset_password",
                     "new_password", "newpassword"],
    },
    "V6.2.3": {
        "question": "When a user changes their password, does the code require and verify "
                    "their CURRENT/OLD password before accepting the new one?",
        "keywords": ["old_password", "current_password", "oldpassword", "currentpassword",
                     "change_password", "changepassword", "verify_password"],
    },
    "V6.2.4": {
        "question": "Does the code check new passwords (at registration or change) against a "
                    "list of known-breached or commonly-used passwords (e.g. zxcvbn, "
                    "haveibeenpwned/HIBP, a banned/common-password list)?",
        "keywords": ["zxcvbn", "haveibeenpwned", "hibp", "common_password", "banned_password",
                     "password_strength", "pwned"],
    },
    "V6.3.1": {
        "question": "Does the code apply rate limiting, anti-automation, or account-lockout "
                    "protection to authentication endpoints (login, password reset, etc.) — "
                    "not just define a limiter somewhere, but actually apply it to a route?",
        "keywords": ["limiter", "rate_limit", "ratelimit", "throttle", "flask_limiter", "slowapi",
                     "express-rate-limit", "ratelimiter", "captcha", "recaptcha", "login_attempt",
                     "failed_attempts", "lockout", "brute"],
    },
    "V6.4.1": {
        "question": "For system-generated initial passwords or activation codes, does the code "
                    "force the user to change it (e.g. a must_change_password flag) or make it "
                    "expire after a short time / single use?",
        "keywords": ["must_change_password", "password_expires_at", "temp_password",
                     "temporary_password", "force_password_change", "activation_code"],
    },
    "V7.2.4": {
        "question": "Does the code regenerate/rotate the session identifier or auth token "
                    "immediately after a successful login (to prevent session fixation)?",
        "keywords": ["session.regenerate", "regenerate_id", "cycle_key", "session.rotate",
                     "new_session", "regenerate_session"],
    },
    "V7.4.1": {
        "question": "Does the code invalidate the session/token server-side on logout (e.g. "
                    "clearing session state, destroying the session, or revoking/blacklisting "
                    "the token) rather than only relying on the client to discard it?",
        "keywords": ["session.clear", "session.destroy", "logout", "revoke_token",
                     "blacklist_token", "invalidate_session", "invalidate_token"],
    },
    "V7.4.2": {
        "question": "When a user account is disabled or deleted, does the code terminate that "
                    "user's active sessions/tokens (not just flip an is_active flag with no "
                    "effect on already-issued sessions)?",
        "keywords": ["is_active", "deactivate_user", "disable_user", "delete_user",
                     "revoke_all_sessions", "terminate_sessions"],
    },
    "V14.3.1": {
        "question": "Does client-side code clear authenticated data from browser storage "
                    "(localStorage/sessionStorage/cookies) when the session ends or the user "
                    "logs out?",
        "keywords": ["localstorage.removeitem", "sessionstorage.removeitem",
                     "localstorage.clear", "sessionstorage.clear", "clear-site-data", "logout"],
    },
}


def _normalize(path: str) -> str:
    return (path or "").replace("\\", "/").lower()


def _select_candidates(source_code_map: dict[str, str], keywords: list[str]) -> list[tuple[str, str]]:
    compiled = [re.compile(re.escape(k), re.IGNORECASE) for k in keywords]
    candidates: list[tuple[str, str]] = []
    for path, content in source_code_map.items():
        norm = _normalize(path)
        keyword_hit = any(rx.search(content) for rx in compiled)
        topical_hit = any(hint in norm for hint in _ALWAYS_FILE_HINTS)
        if keyword_hit or topical_hit:
            candidates.append((path, content))
    # Keyword hits are stronger signal than a merely-topical filename — surface them first
    # so the size cap below keeps the most relevant files when a repo has many candidates.
    candidates.sort(key=lambda pc: not any(rx.search(pc[1]) for rx in compiled))
    return candidates[:_MAX_CANDIDATE_FILES]


def _build_context(candidates: list[tuple[str, str]]) -> str:
    parts = []
    budget = _MAX_CONTEXT_CHARS
    for path, content in candidates:
        if budget <= 0:
            break
        chunk = content[:budget]
        parts.append(f"=== {path} ===\n{chunk}")
        budget -= len(chunk)
    return "\n\n".join(parts)


class CapabilityChecker:
    """Stateless — call check(source_code_map) once per repo scan."""

    def __init__(self):
        self._pool = None

    def _get_pool(self):
        if self._pool is None:
            from semantic_engine.classifier.llm_pool import RoleAwareLLMPool
            self._pool = RoleAwareLLMPool(
                role="detection",
                timeout=30,
                system_prompt=self._load_system_prompt(),
                min_interval_ms=250,
            )
        return self._pool

    @staticmethod
    def _load_system_prompt() -> str:
        try:
            p = Path(__file__).parent.parent.parent / "LLM-prompts" / "capability-check-system-prompt.txt"
            if p.exists():
                return p.read_text(encoding="utf-8").strip()
        except Exception as exc:
            logger.warning(f"Could not load capability-check system prompt: {exc}")
        return "You are a code-review engine checking whether a security capability is implemented."

    async def check(self, source_code_map: dict[str, str]) -> list[CapabilityFinding]:
        if not source_code_map:
            return []

        pool = self._get_pool()
        if not pool.is_available:
            return []

        findings: list[CapabilityFinding] = []
        for control_id, cfg in _CAPABILITY_CHECKS.items():
            try:
                finding = await self._check_one(pool, control_id, cfg, source_code_map)
                if finding:
                    findings.append(finding)
            except Exception as exc:
                logger.warning(f"[capability_checker] {control_id} check failed (non-blocking): {exc}")
                continue
        return findings

    async def _check_one(
        self, pool, control_id: str, cfg: dict, source_code_map: dict[str, str]
    ) -> Optional[CapabilityFinding]:
        candidates = _select_candidates(source_code_map, cfg["keywords"])
        if not candidates:
            return None  # No plausible evidence either way — stays not_tested.

        context = _build_context(candidates)
        prompt = (
            f"Question: {cfg['question']}\n\n"
            f"Code from the scanned repository (file paths shown as headers):\n\n{context}\n\n"
            "Answer now, in the required JSON format only."
        )

        raw = await pool.call(messages=[{"role": "user", "content": prompt}], max_tokens=400, temperature=0.1)
        if not raw:
            return None

        parsed = self._parse_response(raw)
        if parsed is None:
            return None

        implemented = bool(parsed.get("implemented"))
        if not implemented:
            return None  # LLM found no evidence — stays not_tested, not a fabricated fail.

        correct = bool(parsed.get("correct"))
        return CapabilityFinding(
            control_id=control_id,
            verdict="pass" if correct else "fail",
            file=parsed.get("file"),
            line=parsed.get("line"),
            note=parsed.get("explanation", ""),
            confidence=0.7,
        )

    @staticmethod
    def _parse_response(raw: str) -> Optional[dict]:
        try:
            from semantic_engine.classifier.llm_service import _extract_json_payload, _safe_json_loads
            return _safe_json_loads(_extract_json_payload(raw))
        except Exception as exc:
            logger.warning(f"[capability_checker] failed to parse LLM response: {exc} | raw[:200]={raw[:200]}")
            return None
