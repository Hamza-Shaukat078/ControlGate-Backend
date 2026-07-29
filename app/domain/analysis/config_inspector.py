"""
Config Inspector — ASVS 5.0.0 L1/L2 configuration checks.

Unlike the taint engine / regex rule catalog (semantic_engine), these controls
can't be answered by scanning source code for a dangerous pattern — they're
answered by reading the deployment configuration: nginx/reverse-proxy conf,
.env files, Dockerfiles, and YAML config. This module parses those file types
and evaluates them against the config_inspection-primary ASVS controls:

  V3.2.1  Content served in the correct context (CSP sandbox / Content-Disposition)
  V3.4.1  HSTS header with max-age >= 1 year
  V3.4.3  Full Content-Security-Policy includes object-src/base-uri/frame-ancestors (L2)
  V3.4.4  X-Content-Type-Options: nosniff header (L2)
  V3.4.5  Referrer-Policy header (L2)
  V3.4.6  Content-Security-Policy frame-ancestors directive (L2)
  V4.1.1  Content-Type header includes a charset
  V5.2.1  Upload size limits configured
  V5.3.1  Uploaded files not executable as server-side code
  V13.4.3 Directory listing (autoindex) disabled (L2)
  V13.4.4 HTTP TRACE method not allowed (L2)
  V14.3.2 Cache-Control: no-store on sensitive (auth/account/api) locations (L2)

nginx config is the primary source of truth for all of these (it's where these
directives actually live in a real deployment); .env/YAML/Dockerfile provide
supplementary, lower-confidence signal — mainly for V5.2.1 and V3.4.1, where
app-level env vars or a security.yaml sometimes carry the same setting.
"""
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import yaml

logger = logging.getLogger(__name__)

_ONE_YEAR_SECONDS = 31_536_000


@dataclass
class ConfigFinding:
    control_id: str
    verdict: str          # "pass" | "fail" | "not_tested"
    file: str
    line: Optional[int] = None
    note: str = ""
    confidence: float = 0.7


def _line_of(content: str, match: re.Match) -> int:
    return content[: match.start()].count("\n") + 1


class ConfigInspector:
    """Stateless — call inspect(file_map) with repo-relative path -> content."""

    def inspect(self, file_map: dict[str, str]) -> list[ConfigFinding]:
        findings: list[ConfigFinding] = []
        for path, content in file_map.items():
            name = Path(path).name.lower()
            try:
                if name == ".env" or name.startswith(".env."):
                    findings += self._inspect_env(path, content)
                elif name == "dockerfile" or name.startswith("dockerfile."):
                    findings += self._inspect_dockerfile(path, content)
                elif name.endswith((".yml", ".yaml")):
                    findings += self._inspect_yaml(path, content)
                elif self._looks_like_nginx(name, content):
                    findings += self._inspect_nginx(path, content)
            except Exception as exc:
                logger.warning(f"Config inspector failed on {path}: {exc}")
        return findings

    # ── File-type detection ──────────────────────────────────────────────────

    @staticmethod
    def _looks_like_nginx(name: str, content: str) -> bool:
        if name.endswith(".conf") or "nginx" in name:
            return True
        return bool(re.search(r"\bserver\s*\{", content) and re.search(r"\blocation\b", content))

    # ── .env ──────────────────────────────────────────────────────────────────

    _ENV_SIZE_KEYS = re.compile(
        r"^(MAX_(?:UPLOAD|CONTENT)_(?:SIZE|LENGTH)|UPLOAD_MAX_SIZE)\s*=\s*(\S+)",
        re.IGNORECASE | re.MULTILINE,
    )

    def _inspect_env(self, path: str, content: str) -> list[ConfigFinding]:
        findings = []
        m = self._ENV_SIZE_KEYS.search(content)
        if m:
            findings.append(ConfigFinding(
                "V5.2.1", "pass", path, _line_of(content, m),
                f"Upload size limit configured via {m.group(1)}={m.group(2)}",
                confidence=0.55,
            ))
        return findings

    # ── Dockerfile ────────────────────────────────────────────────────────────

    def _inspect_dockerfile(self, path: str, content: str) -> list[ConfigFinding]:
        # ENV directives sometimes carry the same size-limit convention as .env.
        findings = []
        for m in re.finditer(r"^ENV\s+(\S+)\s*=?\s*(\S+)", content, re.MULTILINE | re.IGNORECASE):
            key = m.group(1)
            if self._ENV_SIZE_KEYS.match(f"{key}={m.group(2)}"):
                findings.append(ConfigFinding(
                    "V5.2.1", "pass", path, _line_of(content, m),
                    f"Upload size limit configured via Dockerfile ENV {key}={m.group(2)}",
                    confidence=0.4,
                ))
        return findings

    # ── YAML ──────────────────────────────────────────────────────────────────

    def _inspect_yaml(self, path: str, content: str) -> list[ConfigFinding]:
        findings = []
        try:
            docs = list(yaml.safe_load_all(content))
        except yaml.YAMLError:
            return findings

        for doc in docs:
            if not isinstance(doc, dict):
                continue
            hsts_seconds = self._find_key_recursive(doc, {"hsts_max_age", "max_age", "strict_transport_security"})
            if hsts_seconds is not None:
                seconds = self._coerce_int(hsts_seconds)
                if seconds is not None:
                    verdict = "pass" if seconds >= _ONE_YEAR_SECONDS else "fail"
                    findings.append(ConfigFinding(
                        "V3.4.1", verdict, path, None,
                        f"HSTS max-age found in YAML config: {seconds}s "
                        f"({'>= 1 year' if verdict == 'pass' else '< 1 year required'})",
                        confidence=0.5,
                    ))

            size_limit = self._find_key_recursive(doc, {"max_upload_size", "client_max_body_size", "max_content_length"})
            if size_limit is not None:
                findings.append(ConfigFinding(
                    "V5.2.1", "pass", path, None,
                    f"Upload size limit found in YAML config: {size_limit}",
                    confidence=0.5,
                ))
        return findings

    @staticmethod
    def _find_key_recursive(obj, keys: set[str]):
        if isinstance(obj, dict):
            for k, v in obj.items():
                if isinstance(k, str) and k.lower() in keys:
                    return v
                found = ConfigInspector._find_key_recursive(v, keys)
                if found is not None:
                    return found
        elif isinstance(obj, list):
            for item in obj:
                found = ConfigInspector._find_key_recursive(item, keys)
                if found is not None:
                    return found
        return None

    @staticmethod
    def _coerce_int(value) -> Optional[int]:
        if isinstance(value, (int, float)):
            return int(value)
        if isinstance(value, str):
            m = re.search(r"\d+", value)
            if m:
                return int(m.group())
        return None

    # ── nginx / reverse-proxy conf ───────────────────────────────────────────

    def _inspect_nginx(self, path: str, content: str) -> list[ConfigFinding]:
        findings = []

        # V3.4.1 — HSTS
        hsts_matches = list(re.finditer(
            r"add_header\s+Strict-Transport-Security\s+[\"']max-age=(\d+)", content, re.IGNORECASE
        ))
        if hsts_matches:
            m = hsts_matches[0]
            seconds = int(m.group(1))
            verdict = "pass" if seconds >= _ONE_YEAR_SECONDS else "fail"
            findings.append(ConfigFinding(
                "V3.4.1", verdict, path, _line_of(content, m),
                f"Strict-Transport-Security max-age={seconds} "
                f"({'meets' if verdict == 'pass' else 'below'} the 1-year minimum)",
                confidence=0.85,
            ))
        else:
            findings.append(ConfigFinding(
                "V3.4.1", "fail", path, None,
                "No Strict-Transport-Security header directive found in nginx config",
                confidence=0.6,
            ))

        # V4.1.1 — charset on responses
        if re.search(r"^\s*charset\s+\S+;", content, re.MULTILINE | re.IGNORECASE):
            m = re.search(r"^\s*charset\s+\S+;", content, re.MULTILINE | re.IGNORECASE)
            findings.append(ConfigFinding(
                "V4.1.1", "pass", path, _line_of(content, m),
                "Explicit charset directive found", confidence=0.6,
            ))
        else:
            findings.append(ConfigFinding(
                "V4.1.1", "fail", path, None,
                "No explicit charset directive found in nginx config", confidence=0.4,
            ))

        # V5.2.1 — client_max_body_size
        size_match = re.search(r"client_max_body_size\s+(\S+);", content, re.IGNORECASE)
        if size_match:
            findings.append(ConfigFinding(
                "V5.2.1", "pass", path, _line_of(content, size_match),
                f"client_max_body_size {size_match.group(1)} configured", confidence=0.85,
            ))
        else:
            findings.append(ConfigFinding(
                "V5.2.1", "fail", path, None,
                "No client_max_body_size directive found — falls back to the nginx default (1m), verify it matches policy",
                confidence=0.5,
            ))

        # V3.4.4 — X-Content-Type-Options: nosniff
        nosniff_match = re.search(
            r"add_header\s+X-Content-Type-Options\s+[\"']?nosniff[\"']?", content, re.IGNORECASE
        )
        if nosniff_match:
            findings.append(ConfigFinding(
                "V3.4.4", "pass", path, _line_of(content, nosniff_match),
                "X-Content-Type-Options: nosniff header directive found", confidence=0.8,
            ))
        else:
            findings.append(ConfigFinding(
                "V3.4.4", "fail", path, None,
                "No X-Content-Type-Options: nosniff header directive found in nginx config",
                confidence=0.55,
            ))

        # V3.4.5 — Referrer-Policy
        referrer_match = re.search(r"add_header\s+Referrer-Policy\s+[\"']?([\w-]+)", content, re.IGNORECASE)
        if referrer_match:
            findings.append(ConfigFinding(
                "V3.4.5", "pass", path, _line_of(content, referrer_match),
                f"Referrer-Policy: {referrer_match.group(1)} header directive found", confidence=0.8,
            ))
        else:
            findings.append(ConfigFinding(
                "V3.4.5", "fail", path, None,
                "No Referrer-Policy header directive found in nginx config", confidence=0.55,
            ))

        # V3.4.6 — CSP frame-ancestors
        frame_ancestors_match = re.search(
            r"Content-Security-Policy[^\n]*frame-ancestors", content, re.IGNORECASE
        )
        if frame_ancestors_match:
            findings.append(ConfigFinding(
                "V3.4.6", "pass", path, _line_of(content, frame_ancestors_match),
                "Content-Security-Policy frame-ancestors directive found", confidence=0.75,
            ))
        else:
            findings.append(ConfigFinding(
                "V3.4.6", "fail", path, None,
                "No Content-Security-Policy frame-ancestors directive found in nginx config",
                confidence=0.5,
            ))

        # V3.2.1 — CSP sandbox / Content-Disposition for served content
        csp_match = re.search(r"Content-Security-Policy[^\n]*", content, re.IGNORECASE)
        object_none_match = re.search(r"Content-Security-Policy[^\n]*object-src\s+['\"]?none['\"]?", content, re.IGNORECASE)
        base_none_match = re.search(r"Content-Security-Policy[^\n]*base-uri\s+['\"]?none['\"]?", content, re.IGNORECASE)
        if csp_match and frame_ancestors_match and object_none_match and base_none_match:
            findings.append(ConfigFinding(
                "V3.4.3", "pass", path, _line_of(content, csp_match),
                "Content-Security-Policy includes frame-ancestors, object-src 'none', and base-uri 'none'",
                confidence=0.75,
            ))
        else:
            missing = []
            if not frame_ancestors_match:
                missing.append("frame-ancestors")
            if not object_none_match:
                missing.append("object-src 'none'")
            if not base_none_match:
                missing.append("base-uri 'none'")
            findings.append(ConfigFinding(
                "V3.4.3", "fail", path, _line_of(content, csp_match) if csp_match else None,
                "Content-Security-Policy missing " + ", ".join(missing),
                confidence=0.55,
            ))

        has_csp_sandbox = re.search(r"Content-Security-Policy[^;\"']*sandbox", content, re.IGNORECASE)
        has_content_disposition = re.search(r"Content-Disposition[^;]*attachment", content, re.IGNORECASE)
        upload_locations = list(re.finditer(
            r"location\s*[^{]*(?:upload|media|user[-_]?content|attachment)[^{]*\{", content, re.IGNORECASE
        ))
        if upload_locations:
            if has_csp_sandbox or has_content_disposition:
                findings.append(ConfigFinding(
                    "V3.2.1", "pass", path, _line_of(content, upload_locations[0]),
                    "Upload/media location found with a Content-Disposition or CSP sandbox control in the same config",
                    confidence=0.5,
                ))
            else:
                findings.append(ConfigFinding(
                    "V3.2.1", "fail", path, _line_of(content, upload_locations[0]),
                    "Upload/media location found without a Content-Disposition or CSP sandbox directive",
                    confidence=0.5,
                ))
        # else: nothing resembling a user-content location block — not_tested (no finding emitted)

        # V5.3.1 — uploaded files not executed as server-side code
        if upload_locations:
            deny_script_exec = re.search(
                r"location\s*~[^{]*(?:php|py|pl|cgi|jsp|asp)[^{]*\{[^}]*deny\s+all", content,
                re.IGNORECASE | re.DOTALL,
            )
            has_script_handler_near_upload = any(
                re.search(r"fastcgi_pass|proxy_pass", content[m.start():m.start() + 400], re.IGNORECASE)
                for m in upload_locations
            )
            if deny_script_exec and not has_script_handler_near_upload:
                findings.append(ConfigFinding(
                    "V5.3.1", "pass", path, _line_of(content, deny_script_exec),
                    "Script-extension deny rule found alongside upload/media serving location",
                    confidence=0.55,
                ))
            else:
                findings.append(ConfigFinding(
                    "V5.3.1", "fail", path, _line_of(content, upload_locations[0]),
                    "Upload/media location found without a script-extension deny rule (php/py/cgi/jsp/asp)",
                    confidence=0.55,
                ))

        # V13.4.3 — directory listing (autoindex) disabled
        autoindex_on = re.search(r"autoindex\s+on\s*;", content, re.IGNORECASE)
        if autoindex_on:
            findings.append(ConfigFinding(
                "V13.4.3", "fail", path, _line_of(content, autoindex_on),
                "autoindex on found — directory listing is enabled", confidence=0.85,
            ))
        else:
            # nginx's own default is autoindex off, so absence of the directive is
            # a (lower-confidence) pass rather than a fail, unlike the header checks above.
            autoindex_off = re.search(r"autoindex\s+off\s*;", content, re.IGNORECASE)
            findings.append(ConfigFinding(
                "V13.4.3", "pass", path, _line_of(content, autoindex_off) if autoindex_off else None,
                "autoindex off directive found" if autoindex_off else
                "No autoindex directive found — nginx defaults to autoindex off",
                confidence=0.8 if autoindex_off else 0.4,
            ))

        # V13.4.4 — HTTP TRACE method not allowed
        trace_deny = re.search(
            r"if\s*\(\s*\$request_method\s*=\s*TRACE\s*\)\s*\{[^}]*(?:return\s+40[45]|deny\s+all)",
            content, re.IGNORECASE | re.DOTALL,
        )
        limit_except_trace = re.search(r"limit_except\s+[^{]*\bTRACE\b", content, re.IGNORECASE)
        if trace_deny:
            findings.append(ConfigFinding(
                "V13.4.4", "pass", path, _line_of(content, trace_deny),
                "Explicit TRACE method block found", confidence=0.7,
            ))
        elif limit_except_trace:
            findings.append(ConfigFinding(
                "V13.4.4", "fail", path, _line_of(content, limit_except_trace),
                "limit_except directive explicitly allows the TRACE method", confidence=0.6,
            ))
        # else: no explicit TRACE handling either way — nginx itself doesn't natively
        # proxy TRACE, so absence isn't proof of a problem; leave not_tested (no finding).

        # V14.3.2 — Cache-Control: no-store on sensitive locations
        sensitive_locations = list(re.finditer(
            r"location\s*[^{]*(?:/api|/account|/profile|/admin|/dashboard|/auth)[^{]*\{",
            content, re.IGNORECASE,
        ))
        if sensitive_locations:
            for m in sensitive_locations:
                block_end = content.find("}", m.end())
                block = content[m.end():block_end if block_end != -1 else m.end() + 400]
                if re.search(r"Cache-Control[^;]*no-store", block, re.IGNORECASE):
                    findings.append(ConfigFinding(
                        "V14.3.2", "pass", path, _line_of(content, m),
                        "Sensitive location found with Cache-Control: no-store configured",
                        confidence=0.55,
                    ))
                else:
                    findings.append(ConfigFinding(
                        "V14.3.2", "fail", path, _line_of(content, m),
                        "Sensitive location (api/account/profile/admin/dashboard/auth) found "
                        "without Cache-Control: no-store", confidence=0.5,
                    ))
        # else: no location resembling a sensitive endpoint — not_tested (no finding emitted)

        return findings
