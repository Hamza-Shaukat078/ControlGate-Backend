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
  V3.4.7  Content-Security-Policy violation reporting endpoint (L3)
  V3.4.8  Cross-Origin-Opener-Policy header (L3)
  V3.5.8  Cross-Origin-Resource-Policy header for embeddable resources (L3)
  V4.1.1  Content-Type header includes a charset
  V4.1.2  HTTP->HTTPS redirect scoped to user-facing endpoints, not API/service ones (L1)
  V13.2.2 Least-privilege IAM for backend/service-account access (L1)
  V13.3.2 Least-privilege IAM for the secrets vault itself (L1)
  V16.4.2 Least-privilege IAM for log storage/access (L1)
  V5.2.1  Upload size limits configured
  V5.3.1  Uploaded files not executable as server-side code
  V12.1.2 Only recommended/strong TLS cipher suites enabled (L2)
  V13.2.5 Server-level allowlist restricting egress to external resources (L2)
  V13.4.3 Directory listing (autoindex) disabled (L2)
  V13.4.4 HTTP TRACE method not allowed (L2)
  V4.1.4  Only explicitly supported HTTP methods allowed (limit_except allowlist) (L3)
  V14.3.2 Cache-Control: no-store on sensitive (auth/account/api) locations (L2)
  V17.1.1 TURN server restricts relay to non-internal IPs (L1)
  V17.2.2 Only approved DTLS-SRTP cipher suites enabled (L1)
  V12.1.4 OCSP stapling enabled (ssl_stapling on) (L3)
  V12.1.5 Encrypted Client Hello (ECH) enabled (L3, weak — emerging directive)
  V12.3.5 Kubernetes/Istio PeerAuthentication enforces mTLS between services (L3)
  V13.3.4 Secrets configured to expire/rotate (Terraform Secrets Manager rotation / Vault lease TTL) (L3)
  V13.4.6 Backend component version info not exposed (server_tokens off) (L3, paired with a live header probe)
  V13.4.7 Web tier only serves an explicit allowlist of file extensions (L3)
  V14.2.5 Web Cache Deception — proxy_cache/fastcgi_cache on sensitive locations bypassed for authenticated requests (L3)
  V15.2.4 Third-party/transitive dependencies sourced from the expected (private, pinned) registry (L3)
  V17.1.2 TURN service resists resource exhaustion (min-port/max-port range + user-quota/total-quota) (L3, weak)

nginx config is the primary source of truth for all of these (it's where these
directives actually live in a real deployment); .env/YAML/Dockerfile provide
supplementary, lower-confidence signal — mainly for V5.2.1 and V3.4.1, where
app-level env vars or a security.yaml sometimes carry the same setting.

The IAM controls (V13.2.2, V13.3.2, V16.4.2) read Terraform (.tf) and
standalone AWS-style IAM policy JSON documents instead — the only place
service-account/vault/log-access privilege actually gets defined as
repo-visible config. Detection is deliberately narrow: only a bare `"*"`
action or `"*"` resource on an Allow statement counts as a violation
(service-scoped wildcards like `s3:*` are common, defensible practice and
are not flagged) — this trades recall for precision rather than drowning
real "god-mode" policies in noise.
"""
import json
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
                elif name.endswith(".tf"):
                    findings += self._inspect_terraform(path, content)
                elif name.endswith(".json") and self._looks_like_iam_policy(content):
                    findings += self._inspect_iam_policy_json(path, content)
                elif name.endswith(".json") and self._looks_like_secrets_manager_json(content):
                    findings += self._inspect_secrets_manager_json(path, content)
                elif self._looks_like_coturn(name, content):
                    findings += self._inspect_coturn(path, content)
                elif self._looks_like_nginx(name, content):
                    findings += self._inspect_nginx(path, content)
            except Exception as exc:
                logger.warning(f"Config inspector failed on {path}: {exc}")

        # V15.2.4 — dependency-confusion registry pinning. Correlates package
        # manifests against their registry-pin files (.npmrc / pip.conf), which
        # commonly live in different files than the manifest itself, so this
        # runs once over the whole repo rather than per-file like the checks above.
        try:
            findings += self._inspect_dependency_registry_pinning(file_map)
        except Exception as exc:
            logger.warning(f"Config inspector dependency-registry check failed: {exc}")

        return findings

    # ── File-type detection ──────────────────────────────────────────────────

    @staticmethod
    def _looks_like_nginx(name: str, content: str) -> bool:
        if name.endswith(".conf") or "nginx" in name:
            return True
        return bool(re.search(r"\bserver\s*\{", content) and re.search(r"\blocation\b", content))

    @staticmethod
    def _looks_like_coturn(name: str, content: str) -> bool:
        # coturn's own config also commonly ends in .conf, so this must be
        # checked (and win) before the nginx catch-all above.
        if "turnserver" in name or "coturn" in name:
            return True
        return bool(
            re.search(r"^\s*listening-port\s*=", content, re.MULTILINE | re.IGNORECASE)
            and re.search(r"^\s*realm\s*=", content, re.MULTILINE | re.IGNORECASE)
        )

    @staticmethod
    def _looks_like_iam_policy(content: str) -> bool:
        try:
            doc = json.loads(content)
        except (json.JSONDecodeError, ValueError):
            return False
        return isinstance(doc, dict) and isinstance(doc.get("Statement"), list)

    @staticmethod
    def _looks_like_secrets_manager_json(content: str) -> bool:
        try:
            doc = json.loads(content)
        except (json.JSONDecodeError, ValueError):
            return False
        return isinstance(doc, dict) and "RotationEnabled" in doc

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

            # V13.2.5 — Kubernetes NetworkPolicy restricting egress destinations.
            # A policyTypes: [Egress] policy with concrete egress rules is a
            # server-level allowlist for outbound traffic, same shape as
            # OUTBOUND_REQUEST_ALLOWLIST_CHECK (V13.2.4) but enforced at the
            # infra layer instead of in application code.
            if doc.get("kind") == "NetworkPolicy":
                spec = doc.get("spec") or {}
                policy_types = spec.get("policyTypes") or []
                egress_rules = spec.get("egress")
                if isinstance(policy_types, list) and "Egress" in policy_types and \
                        isinstance(egress_rules, list) and len(egress_rules) > 0:
                    findings.append(ConfigFinding(
                        "V13.2.5", "pass", path, None,
                        "Kubernetes NetworkPolicy restricts egress with explicit rules "
                        f"({len(egress_rules)} rule(s))",
                        confidence=0.6,
                    ))

            # V13.2.2 — Kubernetes RBAC (Role/ClusterRole) least privilege. A rule
            # granting verbs: ["*"] or resources: ["*"] is the RBAC equivalent of
            # a bare "*" in an AWS IAM statement — same wildcard-only heuristic.
            if doc.get("kind") in ("Role", "ClusterRole"):
                rules = doc.get("rules") or []
                if isinstance(rules, list) and rules:
                    has_wildcard_rule = any(
                        isinstance(rule, dict)
                        and ("*" in (rule.get("verbs") or []) or "*" in (rule.get("resources") or []))
                        for rule in rules
                    )
                    if has_wildcard_rule:
                        findings.append(ConfigFinding(
                            "V13.2.2", "fail", path, None,
                            f"Kubernetes {doc['kind']} grants a wildcard verb or resource in an RBAC rule",
                            confidence=0.55,
                        ))
                    else:
                        findings.append(ConfigFinding(
                            "V13.2.2", "pass", path, None,
                            f"Kubernetes {doc['kind']} rules are scoped (no wildcard verb/resource)",
                            confidence=0.4,
                        ))

            # V12.3.5 — Istio PeerAuthentication enforcing mTLS between services.
            # STRICT mode rejects plaintext traffic; PERMISSIVE/DISABLE accept it,
            # so only STRICT counts as verified mutual authentication.
            if doc.get("kind") == "PeerAuthentication":
                spec = doc.get("spec") or {}
                mode = ((spec.get("mtls") or {}).get("mode"))
                if mode is not None:
                    verdict = "pass" if mode == "STRICT" else "fail"
                    findings.append(ConfigFinding(
                        "V12.3.5", verdict, path, None,
                        f"Istio PeerAuthentication mtls.mode is {mode} "
                        f"({'enforces' if verdict == 'pass' else 'does not enforce'} strict mTLS)",
                        confidence=0.6,
                    ))
                # else: PeerAuthentication with no mtls.mode set — not_tested (no finding)
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

    # ── IAM least-privilege (Terraform + standalone policy JSON) ─────────────

    _SECRETS_RESOURCE_HINTS = (
        "secretsmanager", "kms:", "kms.amazonaws", "vault", "ssm:", "parameter-store",
    )
    _LOG_RESOURCE_HINTS = ("logs:", "log-group", "cloudwatch", "arn:aws:logs")
    _IAM_CONTROL_BY_CLASS = {"secrets": "V13.3.2", "logs": "V16.4.2", "general": "V13.2.2"}

    @classmethod
    def _classify_iam_resource(cls, text: str) -> str:
        lowered = text.lower()
        if any(h in lowered for h in cls._SECRETS_RESOURCE_HINTS):
            return "secrets"
        if any(h in lowered for h in cls._LOG_RESOURCE_HINTS):
            return "logs"
        return "general"

    def _inspect_iam_policy_json(self, path: str, content: str) -> list[ConfigFinding]:
        findings = []
        try:
            doc = json.loads(content)
        except (json.JSONDecodeError, ValueError):
            return findings
        statements = doc.get("Statement")
        if not isinstance(statements, list):
            return findings

        # Any "*" action/resource on an Allow statement wins for its control;
        # otherwise a scoped statement is (low-confidence) evidence of least
        # privilege. One finding per control per file — a fail from any
        # statement for that resource class always wins over a pass.
        verdict_by_control: dict[str, tuple[str, str]] = {}
        for stmt in statements:
            if not isinstance(stmt, dict) or stmt.get("Effect") != "Allow":
                continue
            actions = stmt.get("Action")
            resources = stmt.get("Resource")
            action_list = actions if isinstance(actions, list) else ([actions] if actions else [])
            resource_list = resources if isinstance(resources, list) else ([resources] if resources else [])
            control_id = self._IAM_CONTROL_BY_CLASS[
                self._classify_iam_resource(" ".join(str(x) for x in resource_list + action_list))
            ]
            has_wildcard = "*" in action_list or "*" in resource_list

            if has_wildcard:
                verdict_by_control[control_id] = (
                    "fail",
                    f"IAM statement grants unrestricted (\"*\") access: Action={action_list}, Resource={resource_list}",
                )
            elif control_id not in verdict_by_control:
                verdict_by_control[control_id] = (
                    "pass",
                    f"IAM statement scopes access: Action={action_list}, Resource={resource_list}",
                )

        for control_id, (verdict, note) in verdict_by_control.items():
            findings.append(ConfigFinding(
                control_id, verdict, path, None, note,
                confidence=0.6 if verdict == "fail" else 0.4,
            ))
        return findings

    def _inspect_secrets_manager_json(self, path: str, content: str) -> list[ConfigFinding]:
        # V13.3.4 — AWS CLI `describe-secret` output (or an equivalent exported
        # document) carries RotationEnabled/RotationRules directly, no HCL parsing
        # needed for this shape.
        try:
            doc = json.loads(content)
        except (json.JSONDecodeError, ValueError):
            return []
        enabled = doc.get("RotationEnabled")
        if enabled is True:
            rules = doc.get("RotationRules") or {}
            days = rules.get("AutomaticallyAfterDays")
            return [ConfigFinding(
                "V13.3.4", "pass", path, None,
                f"Secret has RotationEnabled=true" + (f" (every {days} days)" if days else ""),
                confidence=0.6,
            )]
        if enabled is False:
            return [ConfigFinding(
                "V13.3.4", "fail", path, None,
                "Secret has RotationEnabled=false — no rotation schedule configured",
                confidence=0.55,
            )]
        return []

    _TF_WILDCARD_ACTION = re.compile(r'"?Action"?\s*[:=]\s*(?:"\*"|\[\s*"\*"\s*\])', re.IGNORECASE)
    _TF_WILDCARD_RESOURCE = re.compile(r'"?Resource"?\s*[:=]\s*(?:"\*"|\[\s*"\*"\s*\])', re.IGNORECASE)
    _TF_IAM_POLICY_RESOURCE = re.compile(
        r'resource\s+"aws_iam_(?:policy|role_policy|user_policy|group_policy)"', re.IGNORECASE
    )

    _TF_SECRETSMANAGER_SECRET = re.compile(r'resource\s+"aws_secretsmanager_secret"\s+"', re.IGNORECASE)
    _TF_SECRETSMANAGER_ROTATION = re.compile(
        r'resource\s+"aws_secretsmanager_secret_rotation"[\s\S]*?rotation_rules\s*\{[^}]*automatically_after_days\s*=\s*(\d+)',
        re.IGNORECASE,
    )
    _TF_VAULT_LEASE_TTL = re.compile(
        r'resource\s+"vault_mount"\s+"[^"]*"\s*\{[^}]*(?:default_lease_ttl_seconds|max_lease_ttl_seconds)\s*=\s*(\d+)',
        re.IGNORECASE,
    )

    def _inspect_secret_rotation_terraform(self, path: str, content: str) -> list[ConfigFinding]:
        # V13.3.4 — secrets configured to expire/rotate. An aws_secretsmanager_secret
        # with a matching _rotation resource (rotation_rules block), or a Vault mount
        # with an explicit lease TTL, is evidence secrets don't live forever; a bare
        # secret resource with neither is a real gap, not just missing evidence.
        rotation_match = self._TF_SECRETSMANAGER_ROTATION.search(content)
        vault_ttl_match = self._TF_VAULT_LEASE_TTL.search(content)
        if rotation_match:
            return [ConfigFinding(
                "V13.3.4", "pass", path, _line_of(content, rotation_match),
                f"aws_secretsmanager_secret_rotation configured (every {rotation_match.group(1)} days)",
                confidence=0.6,
            )]
        if vault_ttl_match:
            return [ConfigFinding(
                "V13.3.4", "pass", path, _line_of(content, vault_ttl_match),
                f"Vault mount configures a lease TTL of {vault_ttl_match.group(1)}s",
                confidence=0.5,
            )]
        secret_match = self._TF_SECRETSMANAGER_SECRET.search(content)
        if secret_match:
            return [ConfigFinding(
                "V13.3.4", "fail", path, _line_of(content, secret_match),
                "aws_secretsmanager_secret defined with no matching "
                "aws_secretsmanager_secret_rotation resource in the same file",
                confidence=0.45,
            )]
        return []  # no secrets-manager/vault resource found — not_tested

    def _inspect_terraform(self, path: str, content: str) -> list[ConfigFinding]:
        # Terraform's HCL isn't JSON, but IAM policies embedded via jsonencode()
        # or heredoc still carry "Action"/"Resource" tokens in the raw text, so
        # the same wildcard check works as a plain-text scan.
        findings = self._inspect_secret_rotation_terraform(path, content)
        wildcard_matches = (
            list(self._TF_WILDCARD_ACTION.finditer(content))
            + list(self._TF_WILDCARD_RESOURCE.finditer(content))
        )
        if not wildcard_matches:
            if self._TF_IAM_POLICY_RESOURCE.search(content):
                findings.append(ConfigFinding(
                    "V13.2.2", "pass", path, None,
                    "Terraform IAM policy resource found with no bare wildcard Action/Resource",
                    confidence=0.35,
                ))
            return findings

        seen_controls = set()
        for m in wildcard_matches:
            window = content[max(0, m.start() - 300):m.end() + 300]
            control_id = self._IAM_CONTROL_BY_CLASS[self._classify_iam_resource(window)]
            if control_id in seen_controls:
                continue
            seen_controls.add(control_id)
            findings.append(ConfigFinding(
                control_id, "fail", path, _line_of(content, m),
                "Terraform IAM policy grants unrestricted (\"*\") Action or Resource",
                confidence=0.5,
            ))
        return findings

    # ── coturn (TURN/STUN server) conf ────────────────────────────────────────

    def _inspect_coturn(self, path: str, content: str) -> list[ConfigFinding]:
        findings = []

        # V17.1.1 — TURN relay restricted to non-internal IPs. coturn's default,
        # absent any denied-peer-ip directive, is to relay to *any* address —
        # including internal/private ranges — so absence is a real fail signal,
        # not just missing evidence (same reasoning as the nginx autoindex check).
        denied_peer_matches = list(re.finditer(
            r"^\s*denied-peer-ip\s*=\s*(\S+)", content, re.MULTILINE | re.IGNORECASE
        ))
        no_loopback = re.search(r"^\s*no-loopback-peers\b", content, re.MULTILINE | re.IGNORECASE)
        no_multicast = re.search(r"^\s*no-multicast-peers\b", content, re.MULTILINE | re.IGNORECASE)
        if denied_peer_matches:
            findings.append(ConfigFinding(
                "V17.1.1", "pass", path, _line_of(content, denied_peer_matches[0]),
                f"denied-peer-ip restricts relay to non-internal ranges "
                f"({len(denied_peer_matches)} rule(s) found)",
                confidence=0.6,
            ))
        elif no_loopback and no_multicast:
            findings.append(ConfigFinding(
                "V17.1.1", "pass", path, _line_of(content, no_loopback),
                "no-loopback-peers and no-multicast-peers configured, partially restricting relay targets",
                confidence=0.4,
            ))
        else:
            findings.append(ConfigFinding(
                "V17.1.1", "fail", path, None,
                "No denied-peer-ip (or no-loopback-peers/no-multicast-peers) directive found — "
                "coturn's default is to relay to any address, including internal ranges",
                confidence=0.5,
            ))

        # V17.1.2 — TURN service resists resource exhaustion when legitimate
        # users open many ports: a bounded relay port range (min-port/max-port)
        # plus a per-user or total allocation quota. Weak/heuristic — presence
        # of the directives is treated as evidence, not their specific values.
        min_port = re.search(r"^\s*min-port\s*=\s*(\d+)", content, re.MULTILINE | re.IGNORECASE)
        max_port = re.search(r"^\s*max-port\s*=\s*(\d+)", content, re.MULTILINE | re.IGNORECASE)
        user_quota = re.search(r"^\s*user-quota\s*=\s*(\d+)", content, re.MULTILINE | re.IGNORECASE)
        total_quota = re.search(r"^\s*total-quota\s*=\s*(\d+)", content, re.MULTILINE | re.IGNORECASE)
        has_port_range = bool(min_port and max_port)
        has_quota = bool(user_quota or total_quota)
        if has_port_range and has_quota:
            findings.append(ConfigFinding(
                "V17.1.2", "pass", path, _line_of(content, min_port),
                f"Bounded relay port range (min-port={min_port.group(1)}, max-port={max_port.group(1)}) "
                "and an allocation quota (user-quota/total-quota) are both configured",
                confidence=0.5,
            ))
        elif has_port_range or has_quota:
            m = min_port or user_quota or total_quota
            findings.append(ConfigFinding(
                "V17.1.2", "pass", path, _line_of(content, m),
                "Partial resource-exhaustion protection found: " +
                ("bounded relay port range" if has_port_range else "allocation quota (user-quota/total-quota)") +
                " configured, but not both",
                confidence=0.3,
            ))
        else:
            findings.append(ConfigFinding(
                "V17.1.2", "fail", path, None,
                "No min-port/max-port relay range or user-quota/total-quota directive found — "
                "coturn's default allows unbounded port allocation per user",
                confidence=0.4,
            ))

        # V17.2.2 — only approved DTLS-SRTP cipher suites. Only assessed when
        # cipher-list is actually set; coturn's OpenSSL-default suite varies by
        # build, so silence isn't itself evidence of a weak config.
        cipher_match = re.search(r"^\s*cipher-list\s*=\s*[\"']?([^\"'\n]+)", content, re.MULTILINE | re.IGNORECASE)
        if cipher_match:
            cipher_list = cipher_match.group(1)
            weak_token = re.search(
                r"(?<!!)\b(?:RC4|3DES|DES|MD5|NULL|EXPORT|ADH|aNULL|eNULL)\b",
                cipher_list, re.IGNORECASE,
            )
            if weak_token:
                findings.append(ConfigFinding(
                    "V17.2.2", "fail", path, _line_of(content, cipher_match),
                    f"cipher-list allows a weak cipher token ({weak_token.group(0)}): {cipher_list.strip()}",
                    confidence=0.7,
                ))
            else:
                findings.append(ConfigFinding(
                    "V17.2.2", "pass", path, _line_of(content, cipher_match),
                    f"cipher-list restricted to a suite with no weak tokens: {cipher_list.strip()}",
                    confidence=0.6,
                ))
        # else: no cipher-list directive — not_tested (no finding)

        return findings

    # ── package registry pinning (V15.2.4 — dependency confusion) ────────────

    _SCOPED_PACKAGE = re.compile(r'"(@[\w.-]+/[\w.-]+)"\s*:\s*"')
    _NPM_SCOPED_REGISTRY = re.compile(r'^\s*(@[\w.-]+):registry\s*=\s*(\S+)', re.MULTILINE)
    _NPM_DEFAULT_REGISTRY = re.compile(r'^\s*registry\s*=\s*(\S+)', re.MULTILINE)
    _PIP_INDEX_URL = re.compile(r'^\s*(?:index-url|extra-index-url)\s*=\s*(\S+)', re.MULTILINE | re.IGNORECASE)

    def _inspect_dependency_registry_pinning(self, file_map: dict[str, str]) -> list[ConfigFinding]:
        # Dependency confusion: an internal/private scoped package (@org/pkg) is
        # resolvable from the public npm registry unless .npmrc explicitly pins
        # that scope (or the registry as a whole) elsewhere. Same idea for pip
        # via pip.conf's index-url. Manifest and pin file commonly live in
        # different files, so this correlates across the whole repo rather than
        # per-file like the checks in inspect() above.
        findings: list[ConfigFinding] = []
        package_json_entries: list[tuple[str, str]] = []
        npmrc_content: Optional[str] = None
        npmrc_path: Optional[str] = None
        pip_conf_content: Optional[str] = None
        pip_conf_path: Optional[str] = None

        for path, content in file_map.items():
            name = Path(path).name.lower()
            if name == "package.json":
                package_json_entries.append((path, content))
            elif name == ".npmrc":
                npmrc_content, npmrc_path = content, path
            elif name in ("pip.conf", "pip.ini"):
                pip_conf_content, pip_conf_path = content, path

        for path, content in package_json_entries:
            scopes = {m.split("/")[0] for m in self._SCOPED_PACKAGE.findall(content)}
            if not scopes:
                continue  # no scoped/private-looking packages declared — not_tested

            if not npmrc_content:
                findings.append(ConfigFinding(
                    "V15.2.4", "fail", path, None,
                    f"package.json declares scoped package(s) ({', '.join(sorted(scopes))}) but no "
                    ".npmrc pins them to a private registry — resolvable from the public npm "
                    "registry (dependency confusion risk)",
                    confidence=0.4,
                ))
                continue

            pinned_scopes = {m.group(1) for m in self._NPM_SCOPED_REGISTRY.finditer(npmrc_content)}
            default_registry = self._NPM_DEFAULT_REGISTRY.search(npmrc_content)
            pins_all = bool(default_registry) and "registry.npmjs.org" not in default_registry.group(1)
            unpinned = scopes - pinned_scopes

            if pins_all or not unpinned:
                findings.append(ConfigFinding(
                    "V15.2.4", "pass", npmrc_path, None,
                    ".npmrc pins " + ("all packages" if pins_all else ", ".join(sorted(pinned_scopes))) +
                    " to a private registry",
                    confidence=0.5,
                ))
            else:
                findings.append(ConfigFinding(
                    "V15.2.4", "fail", path, None,
                    f"package.json declares scoped package(s) ({', '.join(sorted(unpinned))}) with no "
                    "matching registry pin in .npmrc — resolvable from the public npm registry "
                    "(dependency confusion risk)",
                    confidence=0.45,
                ))

        if pip_conf_content:
            m = self._PIP_INDEX_URL.search(pip_conf_content)
            if m and "pypi.org" not in m.group(1) and "files.pythonhosted.org" not in m.group(1):
                findings.append(ConfigFinding(
                    "V15.2.4", "pass", pip_conf_path, _line_of(pip_conf_content, m),
                    f"pip index-url pinned to a private registry: {m.group(1)}",
                    confidence=0.5,
                ))

        return findings

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

        # V4.1.2 — HTTP->HTTPS redirect scoped to user-facing endpoints, not API/service
        # ones. Only assessed when an API/service-shaped location block is present;
        # whether *some* location redirects HTTP->HTTPS elsewhere in the file isn't
        # itself evidence either way for this control.
        api_location_matches = list(re.finditer(
            r"location\s*[^{]*(?:/api|/graphql|/rpc)[^{]*\{([^}]*)\}",
            content, re.IGNORECASE | re.DOTALL,
        ))
        if api_location_matches:
            redirecting_api_location = next(
                (m for m in api_location_matches
                 if re.search(r"return\s+301\s+https|rewrite\s+\^[^\n]*https", m.group(1), re.IGNORECASE)),
                None,
            )
            if redirecting_api_location:
                findings.append(ConfigFinding(
                    "V4.1.2", "fail", path, _line_of(content, redirecting_api_location),
                    "API/service location block redirects HTTP to HTTPS instead of rejecting "
                    "plaintext requests outright",
                    confidence=0.5,
                ))
            else:
                findings.append(ConfigFinding(
                    "V4.1.2", "pass", path, _line_of(content, api_location_matches[0]),
                    "API/service location block found with no HTTP->HTTPS redirect inside it "
                    "(scoped correctly, assuming plaintext is rejected rather than redirected)",
                    confidence=0.4,
                ))
        # else: no API/service-shaped location block found — not_tested (no finding)

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

        # V3.4.7 — CSP violation reporting endpoint
        csp_report_match = re.search(
            r"Content-Security-Policy[^\n]*(?:report-uri\s+\S+|report-to\s+[a-zA-Z0-9_-]+)",
            content,
            re.IGNORECASE,
        )
        if csp_report_match:
            findings.append(ConfigFinding(
                "V3.4.7", "pass", path, _line_of(content, csp_report_match),
                "Content-Security-Policy includes a report-uri or report-to directive",
                confidence=0.75,
            ))
        else:
            findings.append(ConfigFinding(
                "V3.4.7", "fail", path, None,
                "Content-Security-Policy does not include a report-uri or report-to directive",
                confidence=0.5,
            ))

        # V3.4.8 — Cross-Origin-Opener-Policy
        coop_match = re.search(
            r"add_header\s+Cross-Origin-Opener-Policy\s+[\"']?(same-origin|same-origin-allow-popups)[\"']?",
            content,
            re.IGNORECASE,
        )
        if coop_match:
            findings.append(ConfigFinding(
                "V3.4.8", "pass", path, _line_of(content, coop_match),
                f"Cross-Origin-Opener-Policy: {coop_match.group(1)} header directive found",
                confidence=0.8,
            ))
        else:
            findings.append(ConfigFinding(
                "V3.4.8", "fail", path, None,
                "No Cross-Origin-Opener-Policy same-origin/same-origin-allow-popups header directive found",
                confidence=0.55,
            ))

        # V3.5.8 — Cross-Origin-Resource-Policy for cross-origin embedding control
        corp_match = re.search(
            r"add_header\s+Cross-Origin-Resource-Policy\s+[\"']?(same-origin|same-site)[\"']?",
            content,
            re.IGNORECASE,
        )
        if corp_match:
            findings.append(ConfigFinding(
                "V3.5.8", "pass", path, _line_of(content, corp_match),
                f"Cross-Origin-Resource-Policy: {corp_match.group(1)} header directive found",
                confidence=0.75,
            ))
        else:
            findings.append(ConfigFinding(
                "V3.5.8", "fail", path, None,
                "No restrictive Cross-Origin-Resource-Policy header directive found",
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

        # V4.1.4 — only explicitly supported HTTP methods allowed, unused ones
        # blocked. nginx passes through any method by default, so — unlike TRACE
        # above, which nginx doesn't natively proxy — absence of an explicit
        # allowlist here is real evidence of a gap, not just missing evidence.
        limit_except_block = re.search(
            r"limit_except\s+[^{]+\{[^}]*(?:deny\s+all|return\s+40[13])",
            content, re.IGNORECASE | re.DOTALL,
        )
        if limit_except_block:
            findings.append(ConfigFinding(
                "V4.1.4", "pass", path, _line_of(content, limit_except_block),
                "limit_except directive restricts requests to an explicit allowlist of HTTP methods",
                confidence=0.6,
            ))
        else:
            findings.append(ConfigFinding(
                "V4.1.4", "fail", path, None,
                "No limit_except directive found — HTTP methods are not explicitly "
                "restricted to an allowlist (nginx passes through any method by default)",
                confidence=0.45,
            ))

        # V12.1.2 — only recommended/strong TLS cipher suites enabled.
        # Only assessed when the directive is present; nginx build defaults vary
        # by version/distro, so silence isn't itself evidence of a weak config.
        ciphers_match = re.search(r"ssl_ciphers\s+[\"']?([^;\"']+)[\"']?\s*;", content, re.IGNORECASE)
        if ciphers_match:
            cipher_list = ciphers_match.group(1)
            weak_token = re.search(
                r"(?<!!)\b(?:RC4|3DES|DES|MD5|NULL|EXPORT|ADH|aNULL|eNULL)\b",
                cipher_list, re.IGNORECASE,
            )
            if weak_token:
                findings.append(ConfigFinding(
                    "V12.1.2", "fail", path, _line_of(content, ciphers_match),
                    f"ssl_ciphers allows a weak cipher token ({weak_token.group(0)}): {cipher_list.strip()}",
                    confidence=0.8,
                ))
            else:
                findings.append(ConfigFinding(
                    "V12.1.2", "pass", path, _line_of(content, ciphers_match),
                    f"ssl_ciphers restricted to a suite with no weak tokens: {cipher_list.strip()}",
                    confidence=0.7,
                ))

        # V13.2.5 — server-level allowlist restricting egress to external resources.
        # Heuristic: a location acting as an outbound/forward-proxy gateway
        # (dynamic resolver + variable proxy_pass target) should carry an
        # allow/deny ACL restricting which destinations it will relay to.
        resolver_present = re.search(r"^\s*resolver\s+\S+", content, re.IGNORECASE | re.MULTILINE)
        egress_gateway_matches = list(re.finditer(
            r"location\s*[^{]*\{[^}]*proxy_pass\s+\$[^;]+;[^}]*\}",
            content, re.IGNORECASE | re.DOTALL,
        ))
        if resolver_present and egress_gateway_matches:
            m = egress_gateway_matches[0]
            block = m.group(0)
            has_acl = re.search(r"^\s*(?:allow|deny)\s+\S+\s*;", block, re.IGNORECASE | re.MULTILINE)
            if has_acl:
                findings.append(ConfigFinding(
                    "V13.2.5", "pass", path, _line_of(content, m),
                    "Outbound proxy location restricts destinations with an allow/deny ACL",
                    confidence=0.5,
                ))
            else:
                findings.append(ConfigFinding(
                    "V13.2.5", "fail", path, _line_of(content, m),
                    "Outbound proxy location (dynamic resolver + variable proxy_pass) found "
                    "without an allow/deny ACL restricting egress destinations",
                    confidence=0.5,
                ))
        # else: no forward-proxy/egress-gateway shape detected — not_tested (no finding)

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

        # V14.2.5 — Web Cache Deception: proxy_cache/fastcgi_cache on a sensitive
        # location must not cache authenticated responses without a bypass guard
        # keyed on the request's auth state — an app-level Cache-Control header
        # alone (V14.3.2) doesn't stop a misconfigured upstream proxy cache from
        # serving one user's cached sensitive response to another.
        if sensitive_locations:
            for m in sensitive_locations:
                block_end = content.find("}", m.end())
                block = content[m.end():block_end if block_end != -1 else m.end() + 400]
                cache_directive = re.search(r"\b(?:proxy_cache|fastcgi_cache)\s+\S+;", block, re.IGNORECASE)
                if not cache_directive:
                    continue  # nothing proxy/fastcgi-cached here — no deception surface, not_tested
                bypass_guard = re.search(
                    r"(?:proxy_cache_bypass|proxy_no_cache|fastcgi_cache_bypass|fastcgi_no_cache)"
                    r"\s+[^;]*\$(?:http_cookie|http_authorization|cookie_\w+)",
                    block, re.IGNORECASE,
                )
                if bypass_guard:
                    findings.append(ConfigFinding(
                        "V14.2.5", "pass", path, _line_of(content, cache_directive),
                        "Sensitive location caches via proxy_cache/fastcgi_cache but bypasses the "
                        "cache for authenticated requests (cookie/auth-header guard found)",
                        confidence=0.5,
                    ))
                else:
                    findings.append(ConfigFinding(
                        "V14.2.5", "fail", path, _line_of(content, cache_directive),
                        "Sensitive location caches responses via proxy_cache/fastcgi_cache with no "
                        "cookie/auth-header bypass guard — risk of Web Cache Deception serving "
                        "cached sensitive content to other users",
                        confidence=0.5,
                    ))
        # else: no location resembling a sensitive endpoint — not_tested (no finding emitted)

        # V12.1.4 — OCSP stapling. nginx's default is off, so absence is real
        # evidence of a gap, not just missing evidence (same reasoning as autoindex).
        if re.search(r"ssl_stapling\s+on\s*;", content, re.IGNORECASE):
            m = re.search(r"ssl_stapling\s+on\s*;", content, re.IGNORECASE)
            findings.append(ConfigFinding(
                "V12.1.4", "pass", path, _line_of(content, m),
                "ssl_stapling on directive found (OCSP stapling enabled)", confidence=0.75,
            ))
        else:
            findings.append(ConfigFinding(
                "V12.1.4", "fail", path, None,
                "No ssl_stapling on directive found — nginx defaults to OCSP stapling disabled",
                confidence=0.5,
            ))

        # V12.1.5 — Encrypted Client Hello (ECH). nginx ECH support is newer/limited
        # and there's no single settled directive name, so this only ever produces a
        # low-confidence pass when something resembling it is found; absence is not
        # meaningful evidence either way given how rare ECH configs still are.
        ech_match = re.search(
            r"(?i)ssl_ech_config\s+\S+|ssl_ech_grease\s+on|encrypted[-_ ]client[-_ ]hello.{0,40}(?:on\b|enabled|true)",
            content,
        )
        if ech_match:
            findings.append(ConfigFinding(
                "V12.1.5", "pass", path, _line_of(content, ech_match),
                "Encrypted Client Hello (ECH) directive found", confidence=0.3,
            ))
        # else: no ECH directive found — not_tested (feature is emerging/rare, silence isn't evidence)

        # V13.4.6 — backend version info not exposed. nginx's default is `server_tokens on`
        # (version leaked in the Server header and default error pages), so absence of the
        # `off` directive is a real gap.
        if re.search(r"server_tokens\s+off\s*;", content, re.IGNORECASE):
            m = re.search(r"server_tokens\s+off\s*;", content, re.IGNORECASE)
            findings.append(ConfigFinding(
                "V13.4.6", "pass", path, _line_of(content, m),
                "server_tokens off directive found", confidence=0.7,
            ))
        else:
            findings.append(ConfigFinding(
                "V13.4.6", "fail", path, None,
                "No server_tokens off directive found — nginx defaults to exposing its "
                "version in the Server header and default error pages",
                confidence=0.5,
            ))

        # V13.4.7 — web tier only serves an explicit allowlist of file extensions.
        # Only assessed when the config actually serves static files (root/alias
        # present); a location regex matching a specific extension alternation
        # (e.g. \.(html|css|js|png)$) is the allowlist shape, vs a bare catch-all
        # location with no extension restriction at all.
        static_serving = re.search(r"^\s*(?:root|alias)\s+\S+;", content, re.IGNORECASE | re.MULTILINE)
        if static_serving:
            ext_allowlist = re.search(r"location\s+~\*?\s+\\\.\([\w|]+\)\$", content, re.IGNORECASE)
            if ext_allowlist:
                findings.append(ConfigFinding(
                    "V13.4.7", "pass", path, _line_of(content, ext_allowlist),
                    "Location block restricts serving to an explicit file-extension allowlist",
                    confidence=0.5,
                ))
            else:
                findings.append(ConfigFinding(
                    "V13.4.7", "fail", path, _line_of(content, static_serving),
                    "Static content served (root/alias) with no location block restricting "
                    "which file extensions are served",
                    confidence=0.45,
                ))
        # else: no static-file-serving location found — not_tested (no finding emitted)

        return findings
