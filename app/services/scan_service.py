import asyncio
import re as _re
import tempfile
import os
import time
import uuid
from datetime import datetime, timezone
import logging
from typing import Dict, Any, Optional
from pathlib import Path
import shutil
import subprocess
from dataclasses import asdict

from motor.motor_asyncio import AsyncIOMotorDatabase

from semantic_engine.pipeline import get_pipeline, PipelineConfig
from app.enums.role import UserRole
from app.schemas.scan import ScanStatusRead, ScanSummary
from app.db.mongo import to_object_id
from app.core.config import settings
from app.core.trace import trace_step
from app.domain.analysis.dynamic_probe import DynamicProbe
from app.core.archive import safe_extract_archive
from app.core.crypto import decrypt_secret
from app.core.network import validate_public_git_url, validate_public_http_url

logger = logging.getLogger(__name__)

# Phase 5.2 — reverse bridge: how much a static finding's confidence is
# discounted when its bridged dynamic check comes back a definitive PASS
# against the exact route it flagged. Halved, not zeroed — a PASS is real
# live evidence the bug class didn't reproduce, but it can just as easily
# mean the check couldn't trigger it at all (wrong param guess, a WAF, an
# auth wall), so this downgrades rather than deletes; see
# ScanService._run_repository_scan's hybrid block.
DYNAMIC_CONTRADICTION_CONFIDENCE_FACTOR = 0.5


# Bug fix — some rules (MISSING_RATE_LIMITING, and any other rule with
# "finding_polarity": "compliant" in queries.json) are deliberately written
# to detect *evidence a security control exists* (e.g. matching the actual
# rate-limiter middleware definition) rather than a vulnerability — pipeline.py
# already tags these correctly (asvs_finding_polarity="compliant" on the
# formatted finding, verified against a real scan: MISSING_RATE_LIMITING hits
# on services/shared/middleware/security.js's own `rateLimiter = rateLimit(...)`
# definition all came back "compliant", exactly as intended) and
# asvs_service.py's compliance scoring already reads that field correctly.
# What was missing: every vulnerabilities_found/by_severity count in this
# file summed *every* entry in `vulnerabilities` regardless of polarity, so
# "compliant" evidence for a control silently inflated the Findings stat and
# severity chart as if it were a real vulnerability — the exact opposite of
# what it represents. asvs_service.py's own compliance % is unaffected by
# this fix (it already filters by polarity itself, reading the same
# unfiltered `vulnerabilities` list this function's *input* still is —
# only the aggregate counts below exclude compliant entries, the stored
# list itself is untouched).
def _summarize_static_findings(vulnerabilities: list[dict]) -> tuple[int, dict]:
    by_severity = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    vulnerabilities_found = 0
    for vuln in vulnerabilities:
        if vuln.get("asvs_finding_polarity") == "compliant":
            continue
        vulnerabilities_found += 1
        severity = vuln.get("severity", "low")
        by_severity[severity] = by_severity.get(severity, 0) + 1
    return vulnerabilities_found, by_severity


class ScanService:
    # Stores DB reference and initializes the analysis pipeline with LLM enabled
    def __init__(self, db: AsyncIOMotorDatabase) -> None:
        self.db = db
        self.pipeline = get_pipeline(PipelineConfig(enable_llm=True))

    # Creates a scan document in MongoDB and dispatches the appropriate async scan task
    async def start(
        self,
        user_id: str,
        code: Optional[str] = None,
        language: Optional[str] = None,
        filename: Optional[str] = None,
        repo_id: Optional[int] = None,
        branch: str = "main",
        scan_mode: str = "DEEP",
        scan_type: str = "static",
        repo_url: Optional[str] = None,
        repo_provider: Optional[str] = None,
        repo_token: Optional[str] = None,
        file_paths: Optional[list[str]] = None,
        target_url: Optional[str] = None,
        dynamic_additional_target_urls: Optional[list[str]] = None,
        dynamic_auth_mode: str = "none",
        dynamic_bearer_token: Optional[str] = None,
        dynamic_form_login: Optional[dict] = None,
        dynamic_active_mode: bool = False,
        dynamic_second_actor_auth_mode: str = "none",
        dynamic_second_actor_bearer_token: Optional[str] = None,
        dynamic_second_actor_form_login: Optional[dict] = None,
        dynamic_scenarios: Optional[list[dict]] = None,
        dynamic_race_probes: Optional[list[dict]] = None,
        dynamic_idor_probes: Optional[list[dict]] = None,
        dynamic_mass_assignment_probes: Optional[list[dict]] = None,
        dynamic_timing_probes: Optional[list[dict]] = None,
        dynamic_signaling_fuzz_probes: Optional[list[dict]] = None,
        dynamic_media_flood_probes: Optional[list[dict]] = None,
        dynamic_malformed_packet_probes: Optional[list[dict]] = None,
        dynamic_srtp_auth_probes: Optional[list[dict]] = None,
        dynamic_crawl_max_pages: Optional[int] = None,
        dynamic_crawl_max_depth: Optional[int] = None,
        dynamic_rule_ids: Optional[list[str]] = None,
        dynamic_ssrf_collaborator_host: Optional[str] = None,
        dynamic_ssrf_collaborator_port: Optional[int] = None,
        dynamic_openapi_spec_url: Optional[str] = None,
        dynamic_openapi_spec: Optional[str] = None,
        dynamic_use_headless_browser: bool = False,
        enable_llm: bool = True,
        dynamic_oauth2: Optional[dict] = None,
        dynamic_api_key_header: Optional[str] = None,
        dynamic_api_key_value: Optional[str] = None,
        dynamic_second_actor_oauth2: Optional[dict] = None,
        dynamic_second_actor_api_key_header: Optional[str] = None,
        dynamic_second_actor_api_key_value: Optional[str] = None,
        dynamic_state_crawl_max_forms: Optional[int] = None,
        dynamic_state_crawl_max_depth: Optional[int] = None,
    ) -> tuple[str, str]:
        trace_step("Service: ScanService.start() (app/services/scan_service.py)")
        scan_id = f"scan-{uuid.uuid4().hex[:12]}"
        input_type = "DYNAMIC" if scan_type == "dynamic" else ("DIRECT_CODE" if code else "REPOSITORY")

        object_id = to_object_id(user_id)
        if not object_id:
            raise ValueError("Invalid user_id")

        now = datetime.now(timezone.utc).replace(tzinfo=None)
        scan_doc: Dict[str, Any] = {
            "scan_id": scan_id,
            "user_id": object_id,
            "repo_id": repo_id,
            "branch": branch,
            "mode": scan_mode,
            "scan_type": scan_type,
            "dynamic_auth_mode": dynamic_auth_mode,
            "repo_url": repo_url,
            "repo_provider": repo_provider,
            "file_paths": file_paths or None,
            "target_url": target_url,
            "dynamic_additional_target_urls": dynamic_additional_target_urls or None,
            "state": "PENDING",
            "progress": 0,
            "started_at": None,
            "finished_at": None,
            "created_at": now,
            "updated_at": now,
            "input_type": input_type,
            "current_file": None,
            "files_scanned": 0,
            "total_files": 0,
            "vulnerabilities": [],
            "summary": None,
            "logs": [],
        }
        await self.db.scans.insert_one(scan_doc)

        if scan_type == "dynamic":
            trace_step("Dispatch: create_task(_run_dynamic_scan)")
            # Every argument below is passed by keyword, deliberately: this
            # callee's signature has grown several times (Track C6 auth
            # modes, mass-assignment probes, state-crawl caps) with new
            # parameters inserted *between* existing ones, not just
            # appended — a positional call here silently misaligns the
            # instant the two signatures drift, which already broke this
            # exact call once (values landing in the wrong parameter with
            # no error until something downstream chokes on a nonsense
            # type). Keyword-only removes that whole failure class.
            asyncio.create_task(self._run_dynamic_scan(
                scan_id=scan_id, target_url=target_url,
                dynamic_additional_target_urls=dynamic_additional_target_urls,
                dynamic_auth_mode=dynamic_auth_mode, dynamic_bearer_token=dynamic_bearer_token,
                dynamic_form_login=dynamic_form_login, dynamic_oauth2=dynamic_oauth2,
                dynamic_api_key_header=dynamic_api_key_header, dynamic_api_key_value=dynamic_api_key_value,
                dynamic_active_mode=dynamic_active_mode,
                dynamic_second_actor_auth_mode=dynamic_second_actor_auth_mode,
                dynamic_second_actor_bearer_token=dynamic_second_actor_bearer_token,
                dynamic_second_actor_form_login=dynamic_second_actor_form_login,
                dynamic_second_actor_oauth2=dynamic_second_actor_oauth2,
                dynamic_second_actor_api_key_header=dynamic_second_actor_api_key_header,
                dynamic_second_actor_api_key_value=dynamic_second_actor_api_key_value,
                dynamic_scenarios=dynamic_scenarios, dynamic_race_probes=dynamic_race_probes,
                dynamic_idor_probes=dynamic_idor_probes,
                dynamic_mass_assignment_probes=dynamic_mass_assignment_probes,
                dynamic_timing_probes=dynamic_timing_probes,
                dynamic_signaling_fuzz_probes=dynamic_signaling_fuzz_probes,
                dynamic_media_flood_probes=dynamic_media_flood_probes,
                dynamic_malformed_packet_probes=dynamic_malformed_packet_probes,
                dynamic_srtp_auth_probes=dynamic_srtp_auth_probes,
                dynamic_crawl_max_pages=dynamic_crawl_max_pages,
                dynamic_crawl_max_depth=dynamic_crawl_max_depth,
                dynamic_state_crawl_max_forms=dynamic_state_crawl_max_forms,
                dynamic_state_crawl_max_depth=dynamic_state_crawl_max_depth,
                dynamic_rule_ids=dynamic_rule_ids,
                dynamic_ssrf_collaborator_host=dynamic_ssrf_collaborator_host,
                dynamic_ssrf_collaborator_port=dynamic_ssrf_collaborator_port,
                dynamic_openapi_spec_url=dynamic_openapi_spec_url, dynamic_openapi_spec=dynamic_openapi_spec,
                dynamic_use_headless_browser=dynamic_use_headless_browser,
            ))
        elif code:
            trace_step("Dispatch: create_task(_run_direct_code_scan)")
            asyncio.create_task(
                self._run_direct_code_scan(scan_id, code, language, filename, scan_mode, enable_llm)
            )
        else:
            trace_step("Dispatch: create_task(_run_repository_scan)")
            # Keyword-only, same reasoning as the _run_dynamic_scan dispatch
            # above — this callee's signature has grown by keyword-appended
            # insertion in some spots and mid-sequence insertion in others
            # across its various dynamic_* families; positional-by-position
            # correspondence between caller and callee isn't something to
            # keep hand-verifying on every future addition.
            asyncio.create_task(
                self._run_repository_scan(
                    scan_id=scan_id,
                    repo_id=repo_id,
                    branch=branch,
                    scan_mode=scan_mode,
                    repo_url=repo_url,
                    repo_provider=repo_provider,
                    repo_token=repo_token,
                    file_paths=file_paths,
                    target_url=target_url,
                    dynamic_additional_target_urls=dynamic_additional_target_urls,
                    scan_type=scan_type,
                    dynamic_auth_mode=dynamic_auth_mode,
                    dynamic_bearer_token=dynamic_bearer_token,
                    dynamic_form_login=dynamic_form_login,
                    dynamic_oauth2=dynamic_oauth2,
                    dynamic_api_key_header=dynamic_api_key_header,
                    dynamic_api_key_value=dynamic_api_key_value,
                    dynamic_active_mode=dynamic_active_mode,
                    dynamic_second_actor_auth_mode=dynamic_second_actor_auth_mode,
                    dynamic_second_actor_bearer_token=dynamic_second_actor_bearer_token,
                    dynamic_second_actor_form_login=dynamic_second_actor_form_login,
                    dynamic_second_actor_oauth2=dynamic_second_actor_oauth2,
                    dynamic_second_actor_api_key_header=dynamic_second_actor_api_key_header,
                    dynamic_second_actor_api_key_value=dynamic_second_actor_api_key_value,
                    dynamic_scenarios=dynamic_scenarios,
                    dynamic_race_probes=dynamic_race_probes,
                    dynamic_idor_probes=dynamic_idor_probes,
                    dynamic_mass_assignment_probes=dynamic_mass_assignment_probes,
                    dynamic_timing_probes=dynamic_timing_probes,
                    dynamic_signaling_fuzz_probes=dynamic_signaling_fuzz_probes,
                    dynamic_media_flood_probes=dynamic_media_flood_probes,
                    dynamic_malformed_packet_probes=dynamic_malformed_packet_probes,
                    dynamic_srtp_auth_probes=dynamic_srtp_auth_probes,
                    dynamic_crawl_max_pages=dynamic_crawl_max_pages,
                    dynamic_crawl_max_depth=dynamic_crawl_max_depth,
                    dynamic_state_crawl_max_forms=dynamic_state_crawl_max_forms,
                    dynamic_state_crawl_max_depth=dynamic_state_crawl_max_depth,
                    dynamic_rule_ids=dynamic_rule_ids,
                    dynamic_ssrf_collaborator_host=dynamic_ssrf_collaborator_host,
                    dynamic_ssrf_collaborator_port=dynamic_ssrf_collaborator_port,
                    dynamic_openapi_spec_url=dynamic_openapi_spec_url,
                    dynamic_openapi_spec=dynamic_openapi_spec,
                    dynamic_use_headless_browser=dynamic_use_headless_browser,
                    enable_llm=enable_llm,
                )
            )

        return scan_id, input_type

    # Maps a file extension to its corresponding language string
    def _detect_language(self, path: Path) -> Optional[str]:
        ext = path.suffix.lower()
        return {
            ".py": "python",
            ".js": "javascript",
            ".ts": "typescript",
            ".tsx": "typescript",
            ".jsx": "javascript",
            ".html": "html",
            ".htm": "html",
            ".jinja": "html",
            ".j2": "html",
            ".ejs": "html",
            ".hbs": "html",
            ".handlebars": "html",
            ".mustache": "html",
            ".pug": "html",
        }.get(ext)

    # Recursively finds all scannable source files under the given root directory
    def _collect_source_files(self, root: Path) -> list[Path]:
        files = []
        for path in root.rglob("*"):
            if path.is_file():
                lang = self._detect_language(path)
                if lang:
                    files.append(path)
        return files

    # Normalizes a file path to a consistent lowercase/forward-slash key for comparison
    def _path_key(self, path: Optional[str]) -> str:
        if not path:
            return ""
        normalized = str(path).replace("\\", "/")
        return normalized.lower() if os.name == "nt" else normalized

    # Converts an absolute or relative path to a repo-relative forward-slash path
    def _normalize_repo_path(
        self,
        repo_root: Path,
        file_path: Optional[str],
        rel_paths: Optional[list[str]] = None,
    ) -> Optional[str]:
        if not file_path:
            return None
        path_str = str(file_path).replace("\\", "/")
        try:
            path_obj = Path(path_str)
            if path_obj.is_absolute():
                rel = path_obj.resolve().relative_to(repo_root.resolve())
                path_str = str(rel).replace("\\", "/")
        except Exception:
            pass
        repo_root_str = str(repo_root.resolve()).replace("\\", "/")
        if path_str.startswith(repo_root_str + "/"):
            path_str = path_str[len(repo_root_str) + 1 :]
        if path_str.startswith("./"):
            path_str = path_str[2:]
        if rel_paths and (":" in path_str or path_str.startswith("/")):
            norm = self._path_key(path_str)
            best = None
            for rel in rel_paths:
                rel_norm = self._path_key(rel)
                if norm.endswith("/" + rel_norm) or norm.endswith(rel_norm):
                    if not best or len(rel_norm) > len(self._path_key(best)):
                        best = rel
            if best:
                path_str = best
        return path_str

    # Groups a vulnerability type string into a canonical category key
    @staticmethod
    def _vuln_type_group(type_str: str) -> str:
        t = (type_str or "").lower()
        if "sql injection" in t:                                   return "sql_injection"
        if "os command" in t or "command injection" in t:         return "command_injection"
        if "code injection" in t or "eval" in t:                  return "code_injection"
        if "server-side template" in t or "template inject" in t: return "ssti"
        if "ssrf" in t or "server-side request forgery" in t:     return "ssrf"
        if "sensitive data" in t:                                  return "sensitive_data"
        if "insecure direct object" in t or "idor" in t or "broken access control" in t:
            return "broken_access_control"
        if "file upload" in t:                                     return "file_upload"
        if "cross-site scripting" in t or "xss" in t:             return "xss"
        return t.replace(" ", "_").replace("-", "_")

    # Returns a sortable tuple ranking a vulnerability by DFG flow, path length, and confidence
    @staticmethod
    def _vuln_score(vuln: dict) -> tuple:
        evidence = vuln.get("evidence") or {}
        is_dfg   = 1 if (evidence.get("pattern") or "") == "DFG_FLOW" else 0
        path_len = len(evidence.get("data_flow_path") or [])
        conf     = vuln.get("confidence") or 0
        return (is_dfg, path_len, conf)

    @staticmethod
    def _extract_sink_line(vuln: dict) -> int:
        """Find the line where the sink function actually appears in the snippet.

        DFG paths can run top-down (source L22 → sink L27) or bottom-up
        (sink L111 → source L138). Using end_line breaks the bottom-up case.
        Instead, scan the code_snippet for the first line that contains the
        sink function name — that is the true sink line regardless of direction.
        """
        evidence = vuln.get("evidence") or {}
        location = vuln.get("location") or {}
        snippet  = evidence.get("code_snippet") or ""
        sink     = str(evidence.get("sink") or "")
        if sink and sink != "regex":
            for raw_line in snippet.split("\n"):
                m = _re.match(r"(?:>>>)?\s*(\d+)\s*\|", raw_line)
                if m and sink in raw_line:
                    return int(m.group(1))
        return location.get("end_line") or location.get("start_line") or 0

    # Collapses duplicate findings by type, file, and sink line, preferring highest-quality evidence
    def _dedupe_vulnerabilities(
        self,
        repo_root: Optional[Path],
        vulnerabilities: list[dict],
        rel_paths: Optional[list[str]] = None,
    ) -> list[dict]:
        if not vulnerabilities:
            return []

        # ── Step 0: normalise file paths ─────────────────────────────────
        for vuln in vulnerabilities:
            location  = vuln.get("location") or {}
            file_path = location.get("file")
            if repo_root:
                normalized = self._normalize_repo_path(repo_root, file_path, rel_paths)
            else:
                normalized = str(file_path).replace("\\", "/") if file_path else None
            if normalized:
                location["file"] = normalized
                vuln["location"]  = location

        # ── Step 1: collapse DFG findings by (type_group, file, sink_line, sink)
        # Uses the actual sink line extracted from the code snippet so that
        # multiple sub-paths to the same sink (differing only in their source
        # start line) all resolve to the same key. Keeps the longest / highest-
        # confidence path.
        dfg_seen: dict[tuple, dict] = {}
        regex_vulns: list[dict]     = []

        for vuln in vulnerabilities:
            location = vuln.get("location") or {}
            evidence = vuln.get("evidence") or {}
            pattern  = str(evidence.get("pattern") or "")
            file_key = self._path_key(location.get("file"))
            type_key = self._vuln_type_group(vuln.get("type"))

            if pattern == "DFG_FLOW":
                sink_line = self._extract_sink_line(vuln)
                sink      = str(evidence.get("sink") or "")
                key       = (type_key, file_key, sink_line, sink)
                existing  = dfg_seen.get(key)
                if existing is None or self._vuln_score(vuln) > self._vuln_score(existing):
                    dfg_seen[key] = vuln
            else:
                regex_vulns.append(vuln)

        # ── Step 1b: drop REGEX findings superseded by a nearby DFG sink ─
        # A REGEX finding at line R is redundant when a DFG finding already
        # covers the same vulnerability at a sink within 3 lines of R.
        dfg_sink_lines: dict[tuple, set] = {}
        for (tg, fk, sl, _), _ in dfg_seen.items():
            dfg_sink_lines.setdefault((tg, fk), set()).add(sl)

        surviving_regex: list[dict] = []
        for vuln in regex_vulns:
            location = vuln.get("location") or {}
            file_key = self._path_key(location.get("file"))
            type_key = self._vuln_type_group(vuln.get("type"))
            r_line   = location.get("start_line") or 0
            nearby   = dfg_sink_lines.get((type_key, file_key), set())
            if any(abs(r_line - sl) <= 3 for sl in nearby):
                continue  # DFG result supersedes this REGEX entry
            surviving_regex.append(vuln)

        # ── Step 1c: collapse surviving REGEX findings among themselves ───
        # Multiple regex patterns can fire on the same line (e.g. both
        # "Code Injection" and "Code Injection via eval()" at L36).
        regex_seen: dict[tuple, dict] = {}
        for vuln in surviving_regex:
            location = vuln.get("location") or {}
            file_key = self._path_key(location.get("file"))
            type_key = self._vuln_type_group(vuln.get("type"))
            r_line   = location.get("start_line") or 0
            rkey     = (type_key, file_key, r_line)
            existing = regex_seen.get(rkey)
            if existing is None or self._vuln_score(vuln) > self._vuln_score(existing):
                regex_seen[rkey] = vuln

        step1 = list(dfg_seen.values()) + list(regex_seen.values())

        # ── Step 2: collapse by identical data_flow_path ─────────────────
        # Catches the same taint trace classified as multiple vuln types
        # (e.g. the SQL-injection DFG path also filed as IDOR/BAC).
        # Keeps the higher-scoring classification.
        path_seen: dict[tuple, int] = {}
        final: list[dict] = []
        for vuln in step1:
            evidence = vuln.get("evidence") or {}
            path     = tuple(evidence.get("data_flow_path") or [])
            if not path:
                final.append(vuln)
                continue
            existing_idx = path_seen.get(path)
            if existing_idx is None:
                path_seen[path] = len(final)
                final.append(vuln)
            elif self._vuln_score(vuln) > self._vuln_score(final[existing_idx]):
                final[existing_idx] = vuln

        return final

    # Filters a global graph down to only the nodes and edges belonging to one file
    def _filter_graph_for_file(
        self,
        graph_data: dict,
        repo_root: Path,
        rel_path: str
    ) -> dict:
        nodes = []
        node_ids = set()
        has_file_info = False
        for node in graph_data.get("nodes", []):
            file_prop = (node.get("properties") or {}).get("file")
            if file_prop:
                has_file_info = True
            normalized = self._normalize_repo_path(repo_root, file_prop) if file_prop else None
            if normalized:
                norm_key = self._path_key(normalized)
                rel_key = self._path_key(rel_path)
                if (
                    norm_key == rel_key
                    or norm_key.endswith("/" + rel_key)
                    or rel_key.endswith("/" + norm_key)
                ):
                    props = dict(node.get("properties") or {})
                    props["file"] = rel_path
                    node_copy = dict(node)
                    node_copy["properties"] = props
                    nodes.append(node_copy)
                    node_ids.add(node_copy.get("id"))
        if not nodes and not has_file_info:
            return graph_data

        edges = [
            edge for edge in graph_data.get("edges", [])
            if edge.get("source") in node_ids and edge.get("target") in node_ids
        ]
        source_content = ""
        try:
            source_content = (repo_root / rel_path).read_text(encoding="utf-8")
        except UnicodeDecodeError:
            try:
                source_content = (repo_root / rel_path).read_text(encoding="utf-8", errors="replace")
            except Exception:
                source_content = ""
        except Exception:
            source_content = ""
        return {"nodes": nodes, "edges": edges, "source_content": source_content}

    # Extracts a ZIP or TAR archive to the destination directory
    def _extract_archive(self, archive_path: Path, dest_dir: Path) -> None:
        safe_extract_archive(archive_path, dest_dir)

    # Git-clones a repository at the requested branch, falling back to main or master on failure
    def _clone_repo(self, url: str, branch: str, token: Optional[str], dest_dir: Path) -> None:
        validate_public_git_url(url)
        clone_url = url
        if token and url.startswith("https://"):
            clone_url = url.replace("https://", f"https://{token}@", 1)
        env = os.environ.copy()
        env["GIT_TERMINAL_PROMPT"] = "0"

        # Try the requested branch, then fall back to main/master automatically
        fallback = "master" if branch == "main" else "main"
        for attempt_branch in [branch, fallback]:
            result = subprocess.run(
                ["git", "clone", "--depth", "1", "--branch", attempt_branch, clone_url, str(dest_dir)],
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            if result.returncode == 0:
                return
            # Clean up partial clone before retrying
            if dest_dir.exists():
                import shutil
                shutil.rmtree(dest_dir)

        raise subprocess.CalledProcessError(result.returncode, result.args, result.stderr)

    # Pushes new log lines to the scan document in MongoDB
    async def _append_logs(self, scan_id: str, logs: list[str]) -> None:
        if not logs:
            return
        await self.db.scans.update_one(
            {"scan_id": scan_id},
            {
                "$push": {"logs": {"$each": logs}},
                "$set": {"updated_at": datetime.now(timezone.utc).replace(tzinfo=None)},
            },
        )

    # Updates scan fields and optionally appends log lines in a single atomic write
    async def _update_scan(self, scan_id: str, updates: Dict[str, Any], logs: Optional[list[str]] = None) -> None:
        update_doc: Dict[str, Any] = {"$set": {**updates, "updated_at": datetime.now(timezone.utc).replace(tzinfo=None)}}
        if logs:
            update_doc["$push"] = {"logs": {"$each": logs}}
        await self.db.scans.update_one({"scan_id": scan_id}, update_doc)

    # Polls a shared dict a sync progress_callback (running on
    # analyze_repository's worker thread — see MultiFileRepositoryGraph's
    # docstring) writes into, and periodically reflects it into the scan
    # doc. Exists because analyze_repository() is a single, potentially
    # multi-minute await on a large real repo with nothing else visible to
    # the caller otherwise — without this, a scan that's genuinely still
    # working looks identical (in the UI/DB) to one that's hung. Cancelled
    # by the caller once analyze_repository returns (success or timeout);
    # only writes when the parsed-count actually changed, so a slow/stalled
    # parse doesn't spam identical log lines.
    async def _report_parse_progress(self, scan_id: str, state: Dict[str, Any], interval: float = 3.0) -> None:
        last_reported = -1
        while True:
            await asyncio.sleep(interval)
            parsed = state["parsed"]
            if parsed == last_reported:
                continue
            last_reported = parsed
            total = state["total"] or 1
            pct = 20 + int(min(parsed / total, 1.0) * 60)  # 20-80%; post-parse steps take it to 100
            await self._update_scan(
                scan_id,
                {"progress": pct, "current_file": state["file"], "files_scanned": parsed},
                [f"[INFO] Parsing repository: {parsed}/{state['total']} files ({state['file']})"],
            )

    # Async worker that runs the pipeline on pasted code and writes results to MongoDB
    async def _run_direct_code_scan(
        self,
        scan_id: str,
        code: str,
        language: str,
        filename: Optional[str],
        scan_mode: str,
        enable_llm: bool = True,
    ):
        trace_step("Worker: _run_direct_code_scan() (app/services/scan_service.py)")
        start_time = time.time()
        try:
            await self._update_scan(
                scan_id,
                {"state": "RUNNING", "started_at": datetime.now(timezone.utc).replace(tzinfo=None).isoformat(), "progress": 10},
                ["[INFO] Starting direct code scan"],
            )

            ext_map = {
                "python": ".py",
                "javascript": ".js",
                "typescript": ".ts",
                "java": ".java",
                "c": ".c",
                "cpp": ".cpp",
                "go": ".go",
                "php": ".php",
            }
            ext = ext_map.get(language, ".txt")
            if not filename:
                filename = f"code{ext}"

            await self._update_scan(
                scan_id,
                {"current_file": filename, "progress": 25},
                [f"[INFO] Analyzing file: {filename}"],
            )

            with tempfile.NamedTemporaryFile(
                mode="w",
                suffix=ext,
                delete=False,
                encoding="utf-8",
            ) as tmp_file:
                tmp_file.write(code)
                tmp_path = tmp_file.name

            try:
                await self._append_logs(scan_id, ["[INFO] Building semantic graph..."])
                pipeline = get_pipeline(PipelineConfig(enable_llm=enable_llm))
                trace_step("SemanticPipeline: analyze_code()")
                scan_timeout = int(os.getenv("SCAN_TIMEOUT_SECONDS", "300"))
                try:
                    result = await asyncio.wait_for(
                        pipeline.analyze_code(filename=filename, code=code, language=language),
                        timeout=scan_timeout,
                    )
                except asyncio.TimeoutError:
                    logger.warning(f"[scan:{scan_id}] analyze_code timed out after {scan_timeout}s")
                    from semantic_engine.pipeline import AnalysisResult
                    result = AnalysisResult(
                        filename=filename, language=language,
                        lines_of_code=len(code.split('\n')),
                        analysis_time_seconds=float(scan_timeout),
                        graph_nodes=0, graph_edges=0, rules_executed=0,
                        slices_found=0, vulnerabilities_found=0,
                        vulnerabilities=[], graph_data=None,
                        warnings=["Scan timed out — partial results only"],
                        errors=[], success=False,
                    )

                vulnerabilities = self._dedupe_vulnerabilities(None, result.vulnerabilities)
                vulnerabilities_found, by_severity = _summarize_static_findings(vulnerabilities)

                duration = time.time() - start_time
                summary = {
                    "scan_id": scan_id,
                    "status": "COMPLETED",
                    "input_type": "DIRECT_CODE",
                    "total_files": 1,
                    "files_scanned": 1,
                    "vulnerabilities_found": vulnerabilities_found,
                    "by_severity": by_severity,
                    "duration_seconds": round(duration, 2),
                    "created_at": datetime.now(timezone.utc).replace(tzinfo=None).isoformat(),
                    "completed_at": datetime.now(timezone.utc).replace(tzinfo=None).isoformat(),
                    "vulnerabilities": vulnerabilities,
                }

                stored_graph_data = dict(result.graph_data or {"nodes": [], "edges": []})
                stored_graph_data["source_content"] = code
                stored_graph_data["file_path"] = filename

                await self._update_scan(
                    scan_id,
                    {
                        "state": "COMPLETED",
                        "progress": 100,
                        "finished_at": datetime.now(timezone.utc).replace(tzinfo=None).isoformat(),
                        "summary": summary,
                        "vulnerabilities": vulnerabilities,
                        "files_scanned": 1,
                        "total_files": 1,
                        "graph_data": stored_graph_data,
                    },
                    [
                        f"[INFO] Graph built: {result.graph_nodes} nodes, {result.graph_edges} edges",
                        f"[INFO] Rules executed: {result.rules_executed}",
                        f"[INFO] Vulnerabilities found: {len(vulnerabilities)}",
                        f"[SUCCESS] Scan completed in {duration:.2f}s",
                    ],
                )

            finally:
                if os.path.exists(tmp_path):
                    os.unlink(tmp_path)
        except Exception as e:
            logger.error(f"Direct code scan failed: {e}", exc_info=True)
            await self._update_scan(
                scan_id,
                {
                    "state": "FAILED",
                    "finished_at": datetime.now(timezone.utc).replace(tzinfo=None).isoformat(),
                    "summary": {"scan_id": scan_id, "status": "FAILED", "error": str(e)},
                },
                [f"[ERROR] Scan failed: {str(e)}"],
            )

    # Multi-target sweeps (dynamic_additional_target_urls) call
    # _run_dynamic_checks once per target, and form_login re-authenticates
    # fresh on every one of those calls — hitting the same shared login
    # endpoint N times in quick succession, which tripped a real target's
    # own login rate limiter in practice (429 on targets 2+ while target 1
    # succeeded, confirmed against a live app during Track testing
    # 2026-08-15). Pre-authenticates ONCE here and, if the login response
    # carried a JSON bearer token (session.py's
    # _extract_bearer_token_from_json), returns 'bearer' mode with that
    # token instead — every target then reuses the same token via a plain
    # header, no repeated login at all. Falls back to the original
    # form_login config unchanged when no token could be extracted (a pure
    # cookie-session target): cookies don't cross origins anyway (see the
    # ScanPage.js multi-target form_login warning), so there's nothing this
    # can help with there, and per-target login behavior is unaffected.
    # Only called when there's more than one target — zero behavior change
    # for the single-target case this app had before
    # dynamic_additional_target_urls existed.
    async def _resolve_shared_multi_target_auth(
        self,
        auth_mode: str,
        bearer_token: Optional[str],
        form_login: Optional[dict],
        oauth2: Optional[dict],
        api_key_header: Optional[str],
        api_key_value: Optional[str],
    ) -> tuple[str, Optional[str], Optional[dict], Optional[dict], Optional[str], Optional[str]]:
        if auth_mode != "form_login" or not form_login:
            return auth_mode, bearer_token, form_login, oauth2, api_key_header, api_key_value

        from app.domain.analysis.dast.config import ActorConfig, AuthMode, FormLoginConfig
        from app.domain.analysis.dast.session import DastSession

        try:
            actor = ActorConfig(auth_mode=AuthMode.FORM_LOGIN, form_login=FormLoginConfig(**form_login))
            async with DastSession(actor) as session:
                _, headers = session.browser_auth_state()
            auth_header = headers.get("Authorization", "")
            if auth_header.startswith("Bearer "):
                return "bearer", auth_header[len("Bearer "):], None, oauth2, api_key_header, api_key_value
        except Exception as exc:
            logger.warning(
                f"Shared pre-authentication for multi-target sweep failed, "
                f"falling back to a fresh login per target: {exc}"
            )
        return auth_mode, bearer_token, form_login, oauth2, api_key_header, api_key_value

    # Runs the full DAST engine (crawler, payload checks, logout scenario,
    # user-supplied scenarios, race probes) and returns plain-dict
    # (dynamic_findings, discovered_forms), ready to drop into a scan
    # summary. Shared by _run_dynamic_scan (scan_type="dynamic") and
    # _run_repository_scan (scan_type="hybrid") so the engine-orchestration
    # logic exists exactly once.
    async def _run_dynamic_checks(
        self,
        scan_id: str,
        target_url: str,
        dynamic_auth_mode: str = "none",
        dynamic_bearer_token: Optional[str] = None,
        dynamic_form_login: Optional[dict] = None,
        dynamic_active_mode: bool = False,
        dynamic_second_actor_auth_mode: str = "none",
        dynamic_second_actor_bearer_token: Optional[str] = None,
        dynamic_second_actor_form_login: Optional[dict] = None,
        dynamic_scenarios: Optional[list[dict]] = None,
        dynamic_race_probes: Optional[list[dict]] = None,
        dynamic_idor_probes: Optional[list[dict]] = None,
        dynamic_crawl_max_pages: Optional[int] = None,
        dynamic_crawl_max_depth: Optional[int] = None,
        dynamic_rule_ids: Optional[list[str]] = None,
        dynamic_ssrf_collaborator_host: Optional[str] = None,
        dynamic_ssrf_collaborator_port: Optional[int] = None,
        bridge_targets: Optional[list] = None,
        dynamic_openapi_spec_url: Optional[str] = None,
        dynamic_openapi_spec: Optional[str] = None,
        dynamic_use_headless_browser: bool = False,
        repo_root: Optional[Path] = None,
        dynamic_mass_assignment_probes: Optional[list[dict]] = None,
        dynamic_timing_probes: Optional[list[dict]] = None,
        dynamic_signaling_fuzz_probes: Optional[list[dict]] = None,
        dynamic_media_flood_probes: Optional[list[dict]] = None,
        dynamic_malformed_packet_probes: Optional[list[dict]] = None,
        dynamic_srtp_auth_probes: Optional[list[dict]] = None,
        dynamic_oauth2: Optional[dict] = None,
        dynamic_api_key_header: Optional[str] = None,
        dynamic_api_key_value: Optional[str] = None,
        dynamic_second_actor_oauth2: Optional[dict] = None,
        dynamic_second_actor_api_key_header: Optional[str] = None,
        dynamic_second_actor_api_key_value: Optional[str] = None,
        dynamic_state_crawl_max_forms: Optional[int] = None,
        dynamic_state_crawl_max_depth: Optional[int] = None,
        progress_start: int = 10,
        progress_end: int = 95,
    ) -> tuple[list[dict], list[dict]]:
        """repo_root: only ever set by _run_repository_scan's hybrid path —
        a dynamic-only scan has no cloned repo to derive routes from. When
        present, automatic source-route discovery (bridge.py) runs
        unconditionally, no user opt-in needed: unlike the OpenAPI-spec URL
        (which only helps if the target happens to publish one) or the
        headless browser (extra cost, only helps for SPAs), extracting
        routes straight from source the scan already has on disk is free
        and always safe to attempt.
        """
        from urllib.parse import parse_qs, urlsplit

        from app.domain.analysis.dast.api_scenario import build_scenario_from_request
        from app.domain.analysis.dast.checks import run_payload_checks
        from app.domain.analysis.dast.collaborator import CollaboratorServer
        from app.domain.analysis.dast.config import (
            ActorConfig,
            AuthMode,
            DynamicScanConfig,
            FormLoginConfig,
            OAuth2Config,
        )
        from app.domain.analysis.dast.crawler import crawl
        from app.domain.analysis.dast.findings import DynamicFinding
        from app.domain.analysis.dast.idor_probe import IdorProbeConfig, run_idor_probe
        from app.domain.analysis.dast.logout_discovery import (
            build_logout_invalidates_session_scenario,
            check_logout_visible_on_every_page,
            discover_logout_url,
        )
        from app.domain.analysis.dast.bridge import discover_routes_from_source
        from app.domain.analysis.dast.browser_crawler import crawl_with_browser
        from app.domain.analysis.dast.state_crawler import crawl_form_transitions
        from app.domain.analysis.dast.dom_xss_probe import run_dom_xss_probe
        from app.domain.analysis.dast.redirect_warning_probe import run_redirect_warning_probe
        from app.domain.analysis.dast.jwt_probe import run_jwt_probe
        from app.domain.analysis.dast.mass_assignment_probe import (
            MassAssignmentProbeConfig,
            run_mass_assignment_probe,
        )
        from app.domain.analysis.dast.padding_oracle_probe import (
            TimingComparisonProbeConfig,
            TimingProbeVariant,
            run_timing_comparison_probe,
        )
        from app.domain.analysis.dast.websocket_fuzz_probe import (
            CONNECT_TIMEOUT_SECONDS as WS_FUZZ_CONNECT_TIMEOUT_SECONDS,
            WebSocketFuzzProbeConfig,
            run_websocket_fuzz_probe,
        )
        from app.domain.analysis.dast.webrtc_probe import (
            ICE_CONNECT_TIMEOUT_SECONDS,
            MalformedPacketProbeConfig,
            MediaFloodProbeConfig,
            SrtpAuthEnforcementProbeConfig,
            WebRtcConnectionConfig,
            run_malformed_packet_probe,
            run_media_flood_probe,
            run_srtp_auth_enforcement_probe,
        )
        from app.domain.analysis.dast.openapi_discovery import (
            fetch_openapi_spec,
            parse_openapi_spec,
            parse_spec_text,
        )
        from app.domain.analysis.dast.race_probe import RaceProbeConfig, run_race_probe
        from app.domain.analysis.dast.rule_loader import load_dynamic_queries
        from app.domain.analysis.dast.scenario_runner import run_scenario
        from app.domain.analysis.dast.session import DastSessionPair
        from app.domain.analysis.dast.ssrf_probe import run_ssrf_probe
        from app.domain.analysis.dast.verdict import FAILING_VERDICTS, Verdict
        from app.domain.analysis.dast.xss_probe import run_stored_xss_probe

        MAX_ADDITIONAL_CRAWL_URLS = 5
        MAX_FORMS_TO_PROBE = 5
        MAX_SSRF_URLS_TO_PROBE = 5
        # Same budget-capping precedent as MAX_ADDITIONAL_CRAWL_URLS — a spec
        # can legitimately describe far more operations than is sane to fire
        # a full payload-check sweep against in one scan.
        MAX_OPENAPI_URLS = 15
        # No cap here, unlike MAX_ADDITIONAL_CRAWL_URLS/MAX_OPENAPI_URLS —
        # explicit user request: source-route discovery only reads files
        # already on local disk (the repo is already cloned for static
        # analysis), so unlike those two there's no live-request cost to
        # discovering every route. Every discovered route still gets a real
        # payload-check sweep against the live target, so a repo defining
        # hundreds of routes does mean hundreds of routes' worth of live
        # requests — that's the tradeoff of "no limit", by design here.
        # Same budget-capping precedent as MAX_SSRF_URLS_TO_PROBE — each one
        # is a real headless-browser page navigation, materially slower than
        # an httpx request.
        MAX_DOM_XSS_URLS_TO_PROBE = 5
        # Same reasoning as MAX_DOM_XSS_URLS_TO_PROBE — each one is a real
        # browser navigation plus a click, run in the same shared browser
        # context right after the DOM-XSS sweep below.
        MAX_REDIRECT_WARNING_URLS_TO_PROBE = 5
        # C1 — the crawler and run_payload_checks loops are already strictly
        # sequential (one request in flight at a time, no gather/concurrency
        # to bound with a semaphore) and are the actual volume driver here
        # (crawl pages × payload checks per page) — a plain pacing delay
        # between iterations is enough to stop a large crawl
        # (dynamic_crawl_max_pages) from firing a rapid-fire burst at a real
        # target. 0.15s ≈ under 7 req/s, deliberately conservative. Default
        # is 0.0 on both crawl()/run_payload_checks() so direct/test callers
        # are unaffected; the smaller, already-capped-at-20 bridge/xss/
        # scenario/race/idor loops below are left unpaced — much lower
        # burst risk, not worth the added test-suite wall-clock cost.
        REQUEST_PACING_SECONDS = 0.15
        # Bug fix — the payload-check sweep below used to run under a flat
        # 60s asyncio.wait_for regardless of how many URLs it covered. That
        # was fine when the crawler was the only URL source (usually 1-5
        # URLs), but source-route discovery above is explicitly uncapped
        # (see its comment) — a repo with 22 routes x the 13 payload rules,
        # each paced by REQUEST_PACING_SECONDS, comfortably exceeds 60s in
        # practice. Hitting that timeout doesn't degrade gracefully either:
        # run_payload_checks' findings list is local to that coroutine, so
        # asyncio.wait_for's cancellation on timeout discards every finding
        # already gathered, and the outer except also skips every probe
        # after it (bridge/XSS/SSRF/JWT/scenario/race/IDOR/mass-assignment)
        # — a hybrid scan against a real app can silently finish with 0
        # dynamic findings and no visible error. Scaling the budget by URL
        # count keeps the flat 60s floor for small crawls (unchanged
        # behavior) while giving large route counts room to actually finish.
        PAYLOAD_CHECK_SECONDS_PER_URL = 6.0

        def _build_actor(
            auth_mode_str: str,
            bearer_token: Optional[str],
            form_login: Optional[dict],
            oauth2: Optional[dict] = None,
            api_key_header: Optional[str] = None,
            api_key_value: Optional[str] = None,
        ) -> ActorConfig:
            mode = AuthMode(auth_mode_str)
            built = ActorConfig(auth_mode=mode)
            if mode == AuthMode.BEARER:
                built.bearer_token = bearer_token
            elif mode == AuthMode.FORM_LOGIN and form_login:
                built.form_login = FormLoginConfig(**form_login)
            elif mode == AuthMode.OAUTH2 and oauth2:
                built.oauth2 = OAuth2Config(**oauth2)
            elif mode == AuthMode.API_KEY:
                built.api_key_header = api_key_header
                built.api_key_value = api_key_value
            return built

        auth_mode = AuthMode(dynamic_auth_mode)
        actor = _build_actor(
            dynamic_auth_mode, dynamic_bearer_token, dynamic_form_login,
            dynamic_oauth2, dynamic_api_key_header, dynamic_api_key_value,
        )
        second_actor = None
        if dynamic_second_actor_auth_mode != "none":
            second_actor = _build_actor(
                dynamic_second_actor_auth_mode, dynamic_second_actor_bearer_token,
                dynamic_second_actor_form_login, dynamic_second_actor_oauth2,
                dynamic_second_actor_api_key_header, dynamic_second_actor_api_key_value,
            )

        config = DynamicScanConfig(
            target_url=target_url, actor=actor, second_actor=second_actor,
            active_mode=dynamic_active_mode,
        )

        # None means "use crawl()'s own defaults" — only pass overrides that were
        # actually supplied so a scan that doesn't set these behaves exactly as
        # before this option existed.
        crawl_kwargs: Dict[str, Any] = {"request_delay": REQUEST_PACING_SECONDS}
        if dynamic_crawl_max_pages is not None:
            crawl_kwargs["max_pages"] = dynamic_crawl_max_pages
        if dynamic_crawl_max_depth is not None:
            crawl_kwargs["max_depth"] = dynamic_crawl_max_depth

        selected_rules = None
        if dynamic_rule_ids:
            selected_rules = {
                rule_id: rule for rule_id, rule in load_dynamic_queries().items() if rule_id in dynamic_rule_ids
            }

        # Structured record of every check that actually performed a
        # side-effecting (active_mode-gated) request against the target —
        # logged once at the end of this scan for post-scan/compliance
        # review. Skipped/not-configured findings never touched the target,
        # so they're excluded.
        active_mode_audit: list[dict] = []

        def _audit(finding: DynamicFinding) -> None:
            if finding.verdict in (Verdict.SKIPPED_REQUIRES_ACTIVE_AUTHORIZATION, Verdict.NOT_CONFIGURED):
                return
            active_mode_audit.append({
                "rule_id": finding.rule_id, "control_id": finding.control_id,
                "url": finding.url, "method": finding.method, "verdict": finding.verdict.value,
            })

        # Live dynamic-scan viewer (see ScanStatusRead.current_dynamic_action):
        # unlike the static phase (_report_parse_progress ticks current_file/
        # progress every few seconds off a shared dict), every DAST step
        # below is a single multi-second-to-multi-minute await with nothing
        # visible in between — without this, a scan genuinely still working
        # looks identical to one that's hung, for the entire dynamic phase.
        # _DAST_TOTAL_CHECKPOINTS is the number of _dast_step() call sites
        # below; progress_start/progress_end let the two callers (a pure
        # dynamic-only scan vs. the hybrid path, which only gives this phase
        # the tail end of the overall bar) each claim their own slice
        # without this function needing to know which one it's in.
        _DAST_TOTAL_CHECKPOINTS = 15
        _dast_checkpoint = 0

        async def _dast_step(action: str, findings_so_far: int = 0) -> None:
            nonlocal _dast_checkpoint
            _dast_checkpoint = min(_dast_checkpoint + 1, _DAST_TOTAL_CHECKPOINTS)
            pct = progress_start + int(
                (progress_end - progress_start) * (_dast_checkpoint / _DAST_TOTAL_CHECKPOINTS)
            )
            await self._update_scan(
                scan_id,
                {
                    "progress": min(pct, progress_end),
                    "current_dynamic_action": action,
                    "dynamic_findings_count": findings_so_far,
                },
                [f"[DAST] {action}"],
            )

        PER_ITEM_TIMEOUT = 30.0

        # The out-of-band collaborator (Track A2) is created once for the
        # whole dynamic run, not just for SSRF: run_payload_checks below and
        # every probe in this function (bridge loop, SSRF loop, Phase 3+
        # OOB-provable checks) share the same listener/token namespace,
        # rather than each spinning up its own socket+thread. Only started
        # when dynamic_active_mode is set: any check that needs it treats a
        # None collaborator as a no-op (SKIPPED_REQUIRES_ACTIVE_AUTHORIZATION),
        # so there's nothing for a listener to catch anyway. Stopped in the
        # finally below so it's torn down even if the scan raises partway
        # through — not only on the happy path.
        collaborator: Optional[CollaboratorServer] = None
        if dynamic_active_mode:
            collaborator_kwargs: Dict[str, Any] = {}
            if dynamic_ssrf_collaborator_host:
                collaborator_kwargs["host"] = dynamic_ssrf_collaborator_host
            else:
                # No host override means CollaboratorServer binds its own
                # default (loopback) — only reachable from a target on the
                # same host/network as the scanner. That's fine for a local
                # fixture/dev target, but it silently can't confirm SSRF
                # against a real external target (the OOB callback would
                # never leave the target's own network to reach it). Worth
                # surfacing in the scan log up front rather than only in this
                # field's schema description, which nobody reads mid-scan.
                await self._append_logs(
                    scan_id,
                    ["[WARN] SSRF collaborator using its default loopback listener — only reachable from "
                     "targets on the same host/network as the scanner. Set dynamic_ssrf_collaborator_host "
                     "to a publicly-reachable host to confirm SSRF against a real external target."],
                )
            if dynamic_ssrf_collaborator_port:
                collaborator_kwargs["port"] = dynamic_ssrf_collaborator_port
            collaborator = CollaboratorServer(**collaborator_kwargs).start()

        findings = []
        discovered_forms: list[dict] = []
        discovered_form_objects: list = []
        try:
            async with DastSessionPair(config) as pair:
                await _dast_step(f"Crawling {target_url}...")
                check_urls = [target_url]
                try:
                    crawl_result = await asyncio.wait_for(
                        crawl(pair.primary, target_url, **crawl_kwargs), timeout=30.0,
                    )
                    discovered_forms = [asdict(f) for f in crawl_result.forms]
                    discovered_form_objects = crawl_result.forms
                    additional_urls = [u for u in crawl_result.urls if u != target_url]
                    check_urls = [target_url] + additional_urls[:MAX_ADDITIONAL_CRAWL_URLS]
                except asyncio.TimeoutError:
                    logger.warning(f"[scan:{scan_id}] Crawler timed out for {target_url}")
                except Exception as exc:
                    logger.warning(f"[scan:{scan_id}] Crawler failed (non-blocking): {exc}")
                await _dast_step(
                    f"Crawl found {len(discovered_forms)} form(s), {len(check_urls)} URL(s) to test"
                )

                # Track C3 — OpenAPI/spec-driven discovery. A second, optional
                # source of URLs for check_urls, folded in alongside whatever
                # the regex crawler found. Wrapped in try/except so a
                # malformed/unreachable spec degrades the scan (crawler
                # results still stand on their own), never aborts it — same
                # philosophy every other optional discovery step here follows.
                if dynamic_openapi_spec_url or dynamic_openapi_spec:
                    try:
                        spec = (
                            parse_spec_text(dynamic_openapi_spec) if dynamic_openapi_spec
                            else await fetch_openapi_spec(pair.primary, dynamic_openapi_spec_url)
                        )
                        endpoints = parse_openapi_spec(spec, target_url)
                        openapi_urls = [e.url for e in endpoints if e.url not in check_urls]
                        check_urls = check_urls + openapi_urls[:MAX_OPENAPI_URLS]
                    except Exception as exc:
                        logger.warning(f"[scan:{scan_id}] OpenAPI spec resolution failed (non-blocking): {exc}")
                await _dast_step(f"OpenAPI/spec discovery done — {len(check_urls)} URL(s) known so far")

                # Automatic source-route discovery — only available for a
                # hybrid scan (repo_root is None otherwise). Unconditional,
                # no opt-in flag: unlike the OpenAPI-spec URL (only helps if
                # the target happens to publish one), this is free — the
                # repo is already cloned on disk for static analysis, so
                # extracting its own route definitions costs nothing extra
                # and is exactly what makes a hybrid scan against a pure
                # JSON API (no crawlable HTML, no published spec) able to
                # discover its real endpoints at all.
                if repo_root is not None:
                    try:
                        source_endpoints = discover_routes_from_source(repo_root, target_url)
                        source_urls = [e.url for e in source_endpoints if e.url not in check_urls]
                        check_urls = check_urls + source_urls
                    except Exception as exc:
                        logger.warning(f"[scan:{scan_id}] Source route discovery failed (non-blocking): {exc}")
                    await _dast_step(f"Source-route discovery done — {len(check_urls)} URL(s) known so far")

                # Track C2 — headless-browser crawl. Merged into check_urls
                # alongside the regex crawler's own output, not replacing
                # it: a target with a mix of server-rendered and JS-rendered
                # pages still benefits from both. browser_auth_state()
                # exports whatever this session already authenticated with
                # (never a second login) for the browser context to reuse.
                # Mandatory graceful degradation: missing playwright
                # package, missing Chromium binary, and a sandbox/permission
                # failure in a constrained container are all real
                # possibilities here and none of them may abort the scan —
                # the regex crawler's results already stand on their own.
                browser_cookies: list = []
                browser_headers: Dict[str, str] = {}
                if dynamic_use_headless_browser:
                    browser_cookies, browser_headers = pair.primary.browser_auth_state()
                    browser_crawl_kwargs: Dict[str, Any] = {}
                    if dynamic_crawl_max_pages is not None:
                        browser_crawl_kwargs["max_pages"] = dynamic_crawl_max_pages
                    if dynamic_crawl_max_depth is not None:
                        browser_crawl_kwargs["max_depth"] = dynamic_crawl_max_depth
                    try:
                        browser_result = await asyncio.wait_for(
                            crawl_with_browser(
                                target_url,
                                cookies=browser_cookies or None,
                                extra_headers=browser_headers or None,
                                **browser_crawl_kwargs,
                            ),
                            timeout=45.0,
                        )
                        browser_urls = [u for u in browser_result.urls if u not in check_urls]
                        check_urls = check_urls + browser_urls[:MAX_ADDITIONAL_CRAWL_URLS]
                        new_forms = [f for f in browser_result.forms if f not in discovered_form_objects]
                        discovered_form_objects.extend(new_forms)
                        discovered_forms.extend(asdict(f) for f in new_forms)
                    except asyncio.TimeoutError:
                        logger.warning(f"[scan:{scan_id}] Headless browser crawl timed out for {target_url}")
                    except Exception as exc:
                        logger.warning(
                            f"[scan:{scan_id}] Headless browser crawl failed, continuing without it: {exc}"
                        )
                    await _dast_step(f"Headless-browser crawl done — {len(check_urls)} URL(s) known so far")

                # Track C6 — state/form-transition crawl: submits each
                # already-discovered form (benign, non-adversarial values —
                # this is not itself a vulnerability probe) and follows
                # whatever page that lands on, reaching pages that only
                # exist *after* a submission (search results, a checkout's
                # next step, a password-reset confirmation, the
                # authenticated dashboard a login form redirects to) that
                # neither crawler above can reach by following links alone.
                # Side-effecting, so active_mode-gated exactly like
                # xss_probe/race_probe; crawl_form_transitions itself
                # returns an empty result immediately when active_mode is
                # False, so calling it unconditionally here is safe and
                # keeps this block's shape identical to the crawl steps
                # above it.
                if discovered_form_objects:
                    state_crawl_kwargs: Dict[str, Any] = {"request_delay": REQUEST_PACING_SECONDS}
                    if dynamic_state_crawl_max_forms is not None:
                        state_crawl_kwargs["max_forms"] = dynamic_state_crawl_max_forms
                    if dynamic_state_crawl_max_depth is not None:
                        state_crawl_kwargs["max_depth"] = dynamic_state_crawl_max_depth
                    try:
                        transition_result = await asyncio.wait_for(
                            crawl_form_transitions(
                                pair.primary, discovered_form_objects, target_url,
                                active_mode=dynamic_active_mode, **state_crawl_kwargs,
                            ),
                            timeout=45.0,
                        )
                        transition_urls = [u for u in transition_result.urls if u not in check_urls]
                        check_urls = check_urls + transition_urls[:MAX_ADDITIONAL_CRAWL_URLS]
                        new_transition_forms = [
                            f for f in transition_result.forms if f not in discovered_form_objects
                        ]
                        discovered_form_objects.extend(new_transition_forms)
                        discovered_forms.extend(asdict(f) for f in new_transition_forms)
                    except asyncio.TimeoutError:
                        logger.warning(f"[scan:{scan_id}] State/form-transition crawl timed out for {target_url}")
                    except Exception as exc:
                        logger.warning(
                            f"[scan:{scan_id}] State/form-transition crawl failed, continuing without it: {exc}"
                        )
                    await _dast_step(f"State/form-transition crawl done — {len(check_urls)} URL(s) known so far")

                rule_count = len(selected_rules) if selected_rules is not None else "all"
                await _dast_step(f"Running {rule_count} payload check rule(s) across {len(check_urls)} URL(s)...")
                findings = await asyncio.wait_for(
                    run_payload_checks(
                        pair.primary, check_urls, rules=selected_rules, active_mode=dynamic_active_mode,
                        request_delay=REQUEST_PACING_SECONDS, collaborator=collaborator,
                    ),
                    timeout=max(60.0, len(check_urls) * PAYLOAD_CHECK_SECONDS_PER_URL),
                )
                _fail_so_far = sum(1 for f in findings if f.verdict in FAILING_VERDICTS)
                await _dast_step(
                    f"Payload checks done — {len(findings)} result(s), {_fail_so_far} failing",
                    findings_so_far=len(findings),
                )

                # Track C2 — DOM-XSS probe. A real browser is launched once
                # here (separate from crawl_with_browser's own, already-closed
                # browser above — a fresh short-lived one is reused across
                # every URL in this loop, not per-URL) since run_dom_xss_probe
                # needs a live BrowserContext, not just a URL. Only runs when
                # the browser feature is enabled; same graceful-degradation
                # posture as the crawl above — a missing package/binary/
                # sandbox failure here never aborts the scan.
                if dynamic_use_headless_browser:
                    try:
                        from playwright.async_api import async_playwright
                        async with async_playwright() as pw:
                            dom_xss_browser = await pw.chromium.launch(headless=True)
                            try:
                                dom_xss_context = await dom_xss_browser.new_context()
                                if browser_cookies:
                                    await dom_xss_context.add_cookies(browser_cookies)
                                if browser_headers:
                                    await dom_xss_context.set_extra_http_headers(browser_headers)
                                for dom_url in check_urls[:MAX_DOM_XSS_URLS_TO_PROBE]:
                                    dom_finding = await asyncio.wait_for(
                                        run_dom_xss_probe(
                                            dom_xss_context, dom_url, active_mode=dynamic_active_mode,
                                        ),
                                        timeout=PER_ITEM_TIMEOUT,
                                    )
                                    findings.append(dom_finding)
                                    _audit(dom_finding)

                                # V3.7.3 — same shared browser context, same
                                # gate, run right after the DOM-XSS sweep so
                                # this feature-flagged block only ever pays
                                # for one browser launch.
                                for redirect_url in check_urls[:MAX_REDIRECT_WARNING_URLS_TO_PROBE]:
                                    redirect_finding = await asyncio.wait_for(
                                        run_redirect_warning_probe(
                                            dom_xss_context, redirect_url, active_mode=dynamic_active_mode,
                                        ),
                                        timeout=PER_ITEM_TIMEOUT,
                                    )
                                    findings.append(redirect_finding)
                                    _audit(redirect_finding)
                            finally:
                                await dom_xss_browser.close()
                    except Exception as exc:
                        logger.warning(
                            f"[scan:{scan_id}] Headless-browser DOM-XSS probe failed, continuing without it: {exc}"
                        )
                    await _dast_step("DOM-XSS probe done", findings_so_far=len(findings))

                # Bridge targets (app/domain/analysis/dast/bridge.py): specific
                # routes a *static* finding flagged, re-tested live with the one
                # dynamic rule that matches that static rule_id — independent of
                # whatever the crawler happened to discover on its own.
                # SSRF_LIVE and DOM_XSS_LIVE are special-cased: neither is a
                # checks.py payload check (one needs the collaborator above,
                # the other a live browser context), so neither can go
                # through run_payload_checks like the others.
                bridge_rules = load_dynamic_queries() if bridge_targets else {}
                for target in (bridge_targets or []):
                    if target.dynamic_rule_id == "SSRF_LIVE":
                        if collaborator is None:
                            continue
                        param_name = next(iter(parse_qs(urlsplit(target.url).query)), None)
                        try:
                            bridge_results = [await asyncio.wait_for(
                                run_ssrf_probe(
                                    pair.primary, target.url, collaborator,
                                    control_id=(target.asvs_controls[0] if target.asvs_controls else "V5.3.2"),
                                    active_mode=dynamic_active_mode,
                                    candidate_params=[param_name] if param_name else None,
                                ),
                                timeout=15.0,
                            )]
                        except Exception as exc:
                            logger.warning(
                                f"[scan:{scan_id}] Bridge SSRF check failed for {target.url}: {exc}"
                            )
                            continue
                    elif target.dynamic_rule_id == "DOM_XSS_LIVE":
                        # Same feature gate as the non-bridge DOM-XSS sweep
                        # above: it needs a real headless browser, which this
                        # scan only pays the cost of launching when the user
                        # opted in. A short-lived browser+context is launched
                        # here, scoped to just this one bridge target, rather
                        # than trying to reuse the (already-closed-by-now)
                        # browser from that earlier block.
                        if not dynamic_use_headless_browser:
                            continue
                        try:
                            from playwright.async_api import async_playwright
                            async with async_playwright() as pw:
                                dom_browser = await pw.chromium.launch(headless=True)
                                try:
                                    dom_context = await dom_browser.new_context()
                                    bridge_results = [await asyncio.wait_for(
                                        run_dom_xss_probe(
                                            dom_context, target.url,
                                            control_id=(target.asvs_controls[0] if target.asvs_controls else "V1.2.1"),
                                            active_mode=dynamic_active_mode,
                                        ),
                                        timeout=20.0,
                                    )]
                                finally:
                                    await dom_browser.close()
                        except Exception as exc:
                            logger.warning(
                                f"[scan:{scan_id}] Bridge DOM-XSS check failed for {target.url}: {exc}"
                            )
                            continue
                    elif target.dynamic_rule_id == "JWT_WEAKNESS_LIVE":
                        # Only meaningful for a bearer-token session (see
                        # the non-bridge JWT sweep above) — tests the
                        # bridge-resolved route specifically as the
                        # protected route to replay a forged token against,
                        # rather than only ever target_url itself.
                        if auth_mode != AuthMode.BEARER:
                            continue
                        try:
                            bridge_results = [await asyncio.wait_for(
                                run_jwt_probe(
                                    pair.primary, target.url,
                                    control_id=(target.asvs_controls[0] if target.asvs_controls else "V3.5.3"),
                                    active_mode=dynamic_active_mode,
                                ),
                                timeout=15.0,
                            )]
                        except Exception as exc:
                            logger.warning(
                                f"[scan:{scan_id}] Bridge JWT check failed for {target.url}: {exc}"
                            )
                            continue
                    else:
                        rule = bridge_rules.get(target.dynamic_rule_id)
                        if rule is None:
                            continue
                        try:
                            bridge_results = await asyncio.wait_for(
                                run_payload_checks(
                                    pair.primary, target.url, {target.dynamic_rule_id: rule},
                                    active_mode=dynamic_active_mode, collaborator=collaborator,
                                    # target.method is the real verb bridge.py resolved from
                                    # the route decorator (e.g. POST for /transfer) — only
                                    # checks.py's _METHOD_AWARE_CHECKS actually use it, every
                                    # other check ignores it and stays GET-only (see that
                                    # set's docstring for why).
                                    method=target.method,
                                ),
                                timeout=15.0,
                            )
                        except Exception as exc:
                            logger.warning(
                                f"[scan:{scan_id}] Bridge check {target.dynamic_rule_id} "
                                f"failed for {target.url}: {exc}"
                            )
                            continue
                    for finding in bridge_results:
                        # bridge_static_finding_id (Phase 2.4) is what the
                        # confirmation-marking block below matches on —
                        # `evidence` stays a human-readable string purely
                        # for report_service's display (_bridge_origin_label),
                        # not a machine-parsed correlation key.
                        finding.bridge_static_finding_id = target.static_finding_id
                        finding.evidence = (
                            f"bridge:{target.static_finding_id}:{target.source_file}:{target.source_line}"
                        )
                    findings.extend(bridge_results)

                await _dast_step(
                    f"Bridge re-tests done — {len(bridge_targets or [])} static finding(s) re-checked live",
                    findings_so_far=len(findings),
                )

                # REQUEST_SMUGGLING/CSRF_TOKEN_NOT_VALIDATED/SSRF_LIVE are the
                # only fixed rule_ids among the checks above with real side
                # effects when they actually ran (everything else in
                # run_payload_checks — redirect/CRLF/double-decode/
                # unauthenticated-access — is read-only) — audit those
                # specifically, wherever they came from (check_urls or a
                # bridge target). The *general* SSRF loop further down
                # audits its own findings directly instead of relying on
                # this block, since it runs later.
                for finding in findings:
                    if finding.rule_id in ("REQUEST_SMUGGLING", "CSRF_TOKEN_NOT_VALIDATED", "SSRF_LIVE"):
                        _audit(finding)

                # Stored-XSS probe (Phase 4): submits each crawler-discovered
                # form with a marker payload, then checks for unescaped
                # reflection across check_urls. Bounded to the first
                # MAX_FORMS_TO_PROBE forms — each is a real (side-effecting,
                # active_mode-gated) submission, same budget reasoning as
                # MAX_ADDITIONAL_CRAWL_URLS above.
                for form in discovered_form_objects[:MAX_FORMS_TO_PROBE]:
                    try:
                        xss_finding = await asyncio.wait_for(
                            run_stored_xss_probe(
                                pair.primary, form, check_urls, active_mode=dynamic_active_mode,
                            ),
                            timeout=20.0,
                        )
                        findings.append(xss_finding)
                        _audit(xss_finding)
                    except Exception as exc:
                        logger.warning(
                            f"[scan:{scan_id}] Stored-XSS probe failed for form "
                            f"{form.action_url}: {exc}"
                        )

                await _dast_step("Stored-XSS probe done", findings_so_far=len(findings))

                # SSRF probe (Track A2): out-of-band confirmation via the
                # collaborator created up front (see collaborator.py's module
                # docstring for why this needs an out-of-band signal at all).
                # Bounded to the first MAX_SSRF_URLS_TO_PROBE crawled URLs,
                # same budget reasoning as the loops above.
                if collaborator is not None:
                    for url in check_urls[:MAX_SSRF_URLS_TO_PROBE]:
                        try:
                            ssrf_finding = await asyncio.wait_for(
                                run_ssrf_probe(
                                    pair.primary, url, collaborator, active_mode=dynamic_active_mode,
                                ),
                                timeout=15.0,
                            )
                            findings.append(ssrf_finding)
                            _audit(ssrf_finding)
                        except Exception as exc:
                            logger.warning(f"[scan:{scan_id}] SSRF probe failed for {url}: {exc}")

                await _dast_step("SSRF out-of-band probe done", findings_so_far=len(findings))

                # JWT algorithm confusion (Phase 3, item 5): forges the
                # scan's own bearer token and replays it against target_url.
                # Only meaningful for a bearer-token session — a form_login
                # session's cookie-based auth carries no JWT this check can
                # forge variants of. Once per scan, not once per check_url:
                # unlike the payload checks above, this isn't about a
                # specific route's own behavior, it's about whether *this
                # session's auth material* is forgeable at all.
                if auth_mode == AuthMode.BEARER:
                    try:
                        jwt_finding = await asyncio.wait_for(
                            run_jwt_probe(pair.primary, target_url, active_mode=dynamic_active_mode),
                            timeout=15.0,
                        )
                        findings.append(jwt_finding)
                        _audit(jwt_finding)
                    except Exception as exc:
                        logger.warning(f"[scan:{scan_id}] JWT probe failed for {target_url}: {exc}")

                await _dast_step("JWT algorithm-confusion probe done", findings_so_far=len(findings))

                if auth_mode != AuthMode.NONE:
                    logout_url = await discover_logout_url(pair.primary, target_url)
                    if logout_url:
                        # target_url is the scan target's bare origin — for a
                        # frontend/SPA target it's the public shell page, and
                        # for a bare backend microservice it's very often a
                        # public health/service-info root (e.g. `GET /` ->
                        # {"service": "...", "status": "running"}), neither of
                        # which is gated by the session in the first place.
                        # Running the post-logout assertion against a URL that
                        # was never protected produces a misleading FAIL (it
                        # returns 200 after logout because it *always* returns
                        # 200, logged in or not) — confirmed false positive
                        # against a real scan. A quick unauthenticated
                        # baseline request establishes whether target_url is
                        # actually gated before trusting that assertion.
                        target_is_public = False
                        try:
                            baseline = await pair.primary.request_unauthenticated("GET", target_url)
                            target_is_public = baseline.status_code < 400
                        except Exception:
                            pass  # Can't establish a baseline — fall through and run the scenario as before.

                        if target_is_public:
                            findings.append(DynamicFinding(
                                control_id="V7.4.1", verdict=Verdict.NOT_TESTED,
                                rule_id="LOGOUT_INVALIDATES_SESSION", url=target_url, method="SCENARIO",
                                severity="high",
                                note="target_url is publicly reachable without authentication (baseline "
                                     "unauthenticated request also succeeded) — not a suitable resource to "
                                     "test session invalidation against",
                                confidence=0.2,
                            ))
                        else:
                            scenario = build_logout_invalidates_session_scenario(logout_url, target_url)
                            findings.append(
                                await run_scenario(pair, scenario, active_mode=dynamic_active_mode)
                            )
                    else:
                        findings.append(DynamicFinding(
                            control_id="V7.4.1", verdict=Verdict.NOT_TESTED,
                            rule_id="LOGOUT_INVALIDATES_SESSION", url=target_url, method="SCENARIO",
                            severity="high",
                            note="No logout endpoint could be discovered for this target",
                            confidence=0.2,
                        ))
                    await _dast_step("Logout-invalidates-session check done", findings_so_far=len(findings))

                    # V7.4.4 — reuses the same check_urls this scan already
                    # crawled/discovered for the payload-check sweep above,
                    # rather than crawling a second time just for this. Same
                    # auth_mode != NONE gate as the block above: "every
                    # authenticated page" needs an authenticated session to
                    # mean anything.
                    try:
                        logout_visibility_finding = await asyncio.wait_for(
                            check_logout_visible_on_every_page(pair.primary, check_urls),
                            timeout=max(30.0, len(check_urls) * PAYLOAD_CHECK_SECONDS_PER_URL),
                        )
                        findings.append(logout_visibility_finding)
                        _audit(logout_visibility_finding)
                    except Exception as exc:
                        logger.warning(f"[scan:{scan_id}] Logout-visibility check failed: {exc}")
                    await _dast_step("Logout-visible-on-every-page check done", findings_so_far=len(findings))

                # dynamic_scenarios/dynamic_race_probes/dynamic_idor_probes are
                # user-supplied and schema-capped at 20 each (ScanStart), but
                # each individual one can still hang against a slow/broken
                # target — PER_ITEM_TIMEOUT bounds worst-case wall-clock per
                # item on top of that count cap, same defense-in-depth
                # reasoning as the bridge/xss loops' per-item timeouts above.
                for scenario_data in (dynamic_scenarios or []):
                    try:
                        user_scenario = build_scenario_from_request(scenario_data)
                        # V10.4.3's delay_seconds (a real wall-clock wait for an
                        # authorization code to expire) would otherwise just get
                        # cut off mid-sleep by the flat PER_ITEM_TIMEOUT below —
                        # extend this scenario's own budget by exactly the wait
                        # it asked for, every other scenario's timeout unchanged.
                        scenario_timeout = PER_ITEM_TIMEOUT + sum(
                            (step.delay_seconds or 0) for step in user_scenario.steps
                        )
                        scenario_finding = await asyncio.wait_for(
                            run_scenario(pair, user_scenario, active_mode=dynamic_active_mode),
                            timeout=scenario_timeout,
                        )
                        findings.append(scenario_finding)
                        _audit(scenario_finding)
                    except Exception as exc:
                        logger.warning(
                            f"[scan:{scan_id}] User-supplied scenario "
                            f"'{scenario_data.get('scenario_id', '?')}' failed to run: {exc}"
                        )

                for race_data in (dynamic_race_probes or []):
                    try:
                        race_config = RaceProbeConfig(**race_data)
                        race_finding = await asyncio.wait_for(
                            run_race_probe(pair, race_config, active_mode=dynamic_active_mode),
                            timeout=PER_ITEM_TIMEOUT,
                        )
                        findings.append(race_finding)
                        _audit(race_finding)
                    except Exception as exc:
                        logger.warning(
                            f"[scan:{scan_id}] Race probe "
                            f"'{race_data.get('scenario_id', '?')}' failed to run: {exc}"
                        )

                for idor_data in (dynamic_idor_probes or []):
                    try:
                        idor_config = IdorProbeConfig(**idor_data)
                        idor_finding = await asyncio.wait_for(
                            run_idor_probe(pair, idor_config, active_mode=dynamic_active_mode),
                            timeout=PER_ITEM_TIMEOUT,
                        )
                        findings.append(idor_finding)
                        _audit(idor_finding)
                    except Exception as exc:
                        logger.warning(
                            f"[scan:{scan_id}] IDOR probe "
                            f"'{idor_data.get('scenario_id', '?')}' failed to run: {exc}"
                        )

                for mass_assignment_data in (dynamic_mass_assignment_probes or []):
                    try:
                        mass_assignment_config = MassAssignmentProbeConfig(**mass_assignment_data)
                        mass_assignment_finding = await asyncio.wait_for(
                            run_mass_assignment_probe(pair, mass_assignment_config, active_mode=dynamic_active_mode),
                            timeout=PER_ITEM_TIMEOUT,
                        )
                        findings.append(mass_assignment_finding)
                        _audit(mass_assignment_finding)
                    except Exception as exc:
                        logger.warning(
                            f"[scan:{scan_id}] Mass assignment probe "
                            f"'{mass_assignment_data.get('scenario_id', '?')}' failed to run: {exc}"
                        )

                for timing_data in (dynamic_timing_probes or []):
                    try:
                        timing_config = TimingComparisonProbeConfig(**{
                            **timing_data,
                            "variant_a": TimingProbeVariant(**timing_data["variant_a"]),
                            "variant_b": TimingProbeVariant(**timing_data["variant_b"]),
                        })
                        timing_finding = await asyncio.wait_for(
                            run_timing_comparison_probe(pair, timing_config, active_mode=dynamic_active_mode),
                            timeout=PER_ITEM_TIMEOUT,
                        )
                        findings.append(timing_finding)
                        _audit(timing_finding)
                    except Exception as exc:
                        logger.warning(
                            f"[scan:{scan_id}] Timing-comparison probe "
                            f"'{timing_data.get('scenario_id', '?')}' failed to run: {exc}"
                        )

                for signaling_data in (dynamic_signaling_fuzz_probes or []):
                    try:
                        signaling_kwargs = dict(signaling_data)
                        # "payloads": None (the API default, meaning "use the
                        # built-in corpus") must be OMITTED, not passed —
                        # WebSocketFuzzProbeConfig's default_factory only
                        # fires when the key is absent, same reasoning as
                        # the timing probe's variant conversion above.
                        if signaling_kwargs.get("payloads") is None:
                            signaling_kwargs.pop("payloads", None)
                        signaling_config = WebSocketFuzzProbeConfig(**signaling_kwargs)
                        # This probe does its own connect()s (not routed
                        # through DastSession/pair), and needs up to two
                        # handshake attempts per payload plus one baseline —
                        # PER_ITEM_TIMEOUT alone would cut off a legitimately
                        # slow-but-working target well before a healthy run
                        # completes.
                        signaling_timeout = min(
                            300.0,
                            max(
                                PER_ITEM_TIMEOUT,
                                (len(signaling_config.payloads) * 2 + 1) * WS_FUZZ_CONNECT_TIMEOUT_SECONDS,
                            ),
                        )
                        signaling_finding = await asyncio.wait_for(
                            run_websocket_fuzz_probe(signaling_config, active_mode=dynamic_active_mode),
                            timeout=signaling_timeout,
                        )
                        findings.append(signaling_finding)
                        _audit(signaling_finding)
                    except Exception as exc:
                        logger.warning(
                            f"[scan:{scan_id}] Signaling fuzz probe "
                            f"'{signaling_data.get('scenario_id', '?')}' failed to run: {exc}"
                        )

                for flood_data in (dynamic_media_flood_probes or []):
                    try:
                        flood_config = MediaFloodProbeConfig(
                            scenario_id=flood_data["scenario_id"],
                            control_connection=WebRtcConnectionConfig(**flood_data["control_connection"]),
                            flood_connections=[
                                WebRtcConnectionConfig(**c) for c in flood_data["flood_connections"]
                            ],
                            **{k: v for k, v in flood_data.items()
                               if k not in ("scenario_id", "control_connection", "flood_connections")},
                        )
                        # Each connection is a real signaling round-trip plus
                        # an ICE_CONNECT_TIMEOUT_SECONDS wait, on top of the
                        # probe's own hold_seconds — a flat PER_ITEM_TIMEOUT
                        # would cut off a legitimately-working flood test
                        # with several connections well before it finishes.
                        flood_timeout = min(
                            300.0,
                            max(
                                PER_ITEM_TIMEOUT,
                                ICE_CONNECT_TIMEOUT_SECONDS * (len(flood_config.flood_connections) + 2)
                                + flood_config.hold_seconds * 2,
                            ),
                        )
                        flood_finding = await asyncio.wait_for(
                            run_media_flood_probe(flood_config, active_mode=dynamic_active_mode),
                            timeout=flood_timeout,
                        )
                        findings.append(flood_finding)
                        _audit(flood_finding)
                    except Exception as exc:
                        logger.warning(
                            f"[scan:{scan_id}] Media flood probe "
                            f"'{flood_data.get('scenario_id', '?')}' failed to run: {exc}"
                        )

                for malformed_data in (dynamic_malformed_packet_probes or []):
                    try:
                        malformed_kwargs = dict(malformed_data)
                        malformed_kwargs["connection"] = WebRtcConnectionConfig(**malformed_kwargs["connection"])
                        # Hex-encoded on the wire (raw bytes aren't JSON-safe);
                        # None (the API default, "use the built-in corpus")
                        # must be OMITTED so MalformedPacketProbeConfig's
                        # default_factory fires, same reasoning as every
                        # other probe's optional-corpus conversion above.
                        if malformed_kwargs.get("payloads") is None:
                            malformed_kwargs.pop("payloads", None)
                        else:
                            malformed_kwargs["payloads"] = [bytes.fromhex(p) for p in malformed_kwargs["payloads"]]
                        malformed_config = MalformedPacketProbeConfig(**malformed_kwargs)
                        malformed_timeout = min(
                            300.0,
                            max(
                                PER_ITEM_TIMEOUT,
                                ICE_CONNECT_TIMEOUT_SECONDS + len(malformed_config.payloads) * 1.0,
                            ),
                        )
                        malformed_finding = await asyncio.wait_for(
                            run_malformed_packet_probe(malformed_config, active_mode=dynamic_active_mode),
                            timeout=malformed_timeout,
                        )
                        findings.append(malformed_finding)
                        _audit(malformed_finding)
                    except Exception as exc:
                        logger.warning(
                            f"[scan:{scan_id}] Malformed-packet probe "
                            f"'{malformed_data.get('scenario_id', '?')}' failed to run: {exc}"
                        )

                for srtp_data in (dynamic_srtp_auth_probes or []):
                    try:
                        srtp_config = SrtpAuthEnforcementProbeConfig(
                            scenario_id=srtp_data["scenario_id"],
                            attacker_connection=WebRtcConnectionConfig(**srtp_data["attacker_connection"]),
                            observer_connection=WebRtcConnectionConfig(**srtp_data["observer_connection"]),
                            **{k: v for k, v in srtp_data.items()
                               if k not in ("scenario_id", "attacker_connection", "observer_connection")},
                        )
                        srtp_finding = await asyncio.wait_for(
                            run_srtp_auth_enforcement_probe(srtp_config, active_mode=dynamic_active_mode),
                            timeout=min(300.0, max(PER_ITEM_TIMEOUT, ICE_CONNECT_TIMEOUT_SECONDS * 4 + 10.0)),
                        )
                        findings.append(srtp_finding)
                        _audit(srtp_finding)
                    except Exception as exc:
                        logger.warning(
                            f"[scan:{scan_id}] SRTP auth-enforcement probe "
                            f"'{srtp_data.get('scenario_id', '?')}' failed to run: {exc}"
                        )

                await _dast_step(
                    f"Dynamic checks complete — {len(findings)} total result(s)", findings_so_far=len(findings),
                )
        except asyncio.TimeoutError:
            logger.warning(f"[scan:{scan_id}] Dynamic payload checks timed out for {target_url}")
            await self._append_logs(scan_id, ["[DAST] Dynamic checks timed out — 0 result(s)"])
        except Exception as exc:
            # Was logger.warning only — a real, common failure mode (wrong
            # auth mode for this target's login shape, e.g. form_login's
            # x-www-form-urlencoded POST against a JSON-only API, which
            # raises httpx.HTTPStatusError here on the 415/400 the target
            # sends back) was previously invisible anywhere a user could
            # see it: the scan just quietly finished with 0 dynamic
            # findings, indistinguishable from "nothing to find here".
            # Exception text from httpx's raise_for_status() never echoes
            # the request body/credentials, so this is safe to surface
            # verbatim without redaction.
            # Bug fix — httpx's own timeout/connection exceptions (ReadTimeout,
            # ConnectTimeout, ConnectError, ...) very often carry no message
            # text at all (str(exc) == ""), which made this line collapse to
            # "Reason: " — silently defeating the exact visibility the fix
            # above this block was written to add. Falls back to the
            # exception's class name so there's always *something* to go on
            # (e.g. "ReadTimeout") instead of a blank reason indistinguishable
            # from a clean 0-finding result.
            reason = str(exc) or f"{type(exc).__name__} (no further detail from the exception)"
            logger.warning(f"[scan:{scan_id}] Dynamic payload checks failed (non-blocking): {reason}")
            await self._append_logs(scan_id, [f"[DAST] Dynamic checks failed — 0 result(s). Reason: {reason}"])
        finally:
            if collaborator is not None:
                collaborator.stop()

        if active_mode_audit:
            logger.info(
                f"[scan:{scan_id}] Active-mode (side-effecting) checks executed against "
                f"{target_url}: {active_mode_audit}"
            )

        dynamic_findings = []
        for finding in findings:
            finding_dict = asdict(finding)
            finding_dict["verdict"] = finding.verdict.value
            dynamic_findings.append(finding_dict)

        return dynamic_findings, discovered_forms

    # Async worker for scan_type="dynamic" — no source, targets a live URL directly.
    # Phase 2A's payload checks run unauthenticated or authenticated alike (the
    # session abstracts that away). Phase 2B's LOGOUT_INVALIDATES_SESSION scenario
    # only runs when an authenticated actor is actually configured — it needs a
    # real session to invalidate. A second actor exists solely for cross-session
    # scenarios (e.g. V7.4.3), which also need dynamic_active_mode.
    async def _run_dynamic_scan(
        self,
        scan_id: str,
        target_url: str,
        dynamic_additional_target_urls: Optional[list[str]] = None,
        dynamic_auth_mode: str = "none",
        dynamic_bearer_token: Optional[str] = None,
        dynamic_form_login: Optional[dict] = None,
        dynamic_active_mode: bool = False,
        dynamic_second_actor_auth_mode: str = "none",
        dynamic_second_actor_bearer_token: Optional[str] = None,
        dynamic_second_actor_form_login: Optional[dict] = None,
        dynamic_scenarios: Optional[list[dict]] = None,
        dynamic_race_probes: Optional[list[dict]] = None,
        dynamic_idor_probes: Optional[list[dict]] = None,
        dynamic_crawl_max_pages: Optional[int] = None,
        dynamic_crawl_max_depth: Optional[int] = None,
        dynamic_rule_ids: Optional[list[str]] = None,
        dynamic_ssrf_collaborator_host: Optional[str] = None,
        dynamic_ssrf_collaborator_port: Optional[int] = None,
        dynamic_openapi_spec_url: Optional[str] = None,
        dynamic_openapi_spec: Optional[str] = None,
        dynamic_use_headless_browser: bool = False,
        dynamic_mass_assignment_probes: Optional[list[dict]] = None,
        dynamic_timing_probes: Optional[list[dict]] = None,
        dynamic_signaling_fuzz_probes: Optional[list[dict]] = None,
        dynamic_media_flood_probes: Optional[list[dict]] = None,
        dynamic_malformed_packet_probes: Optional[list[dict]] = None,
        dynamic_srtp_auth_probes: Optional[list[dict]] = None,
        dynamic_oauth2: Optional[dict] = None,
        dynamic_api_key_header: Optional[str] = None,
        dynamic_api_key_value: Optional[str] = None,
        dynamic_second_actor_oauth2: Optional[dict] = None,
        dynamic_second_actor_api_key_header: Optional[str] = None,
        dynamic_second_actor_api_key_value: Optional[str] = None,
        dynamic_state_crawl_max_forms: Optional[int] = None,
        dynamic_state_crawl_max_depth: Optional[int] = None,
    ):
        trace_step("Worker: _run_dynamic_scan() (app/services/scan_service.py)")
        start_time = time.time()
        try:
            # A microservice app's sibling services each live on their own
            # origin (crawler.py's same-origin rule means target_url alone
            # can never reach them) — every one of these gets swept within
            # this SAME scan and merged into one report below, rather than
            # needing a separate scan per service. dict.fromkeys dedupes
            # while keeping target_url first (it's what "input_type"/the
            # scan doc's own target_url field, set at insert time, reports
            # as *the* target — the rest are additive, not a replacement).
            all_targets = list(dict.fromkeys([target_url, *(dynamic_additional_target_urls or [])]))
            for t in all_targets:
                validate_public_http_url(t, allow_http=True)
            await self._update_scan(
                scan_id,
                {"state": "RUNNING", "started_at": datetime.now(timezone.utc).replace(tzinfo=None).isoformat(), "progress": 10},
                [
                    f"[INFO] Starting dynamic scan against {len(all_targets)} target(s): "
                    f"{', '.join(all_targets)}"
                ],
            )

            # ASVS dynamic-probe controls (V12.1.1, V12.1.3, V12.2.1, V12.2.2,
            # V12.3.4, V13.4.1, V3.3.5, V3.7.4 — plus V3.4.1/V13.4.6, which
            # accept this as alternate evidence alongside a config finding)
            # were previously only wired into the hybrid (repo + target_url)
            # path — a scan_type="dynamic" run, whose entire point is testing
            # a live target_url, never populated dynamic_probe_findings at
            # all, so every one of those catalog-labeled controls came back
            # not_tested for exactly the scan type they matter most for. See
            # the matching block in _run_repository_scan for the same
            # pattern (graceful timeout/failure — never aborts the scan).
            #
            # Both this passive probe and the full _run_dynamic_checks sweep
            # below run once per target and get merged into one set of lists
            # — everything downstream (by_severity, the summary dict, the
            # Reports UI) already operates on these generically, so no
            # further change is needed past this loop.
            dynamic_probe_findings: list[dict] = []
            dynamic_findings: list[dict] = []
            discovered_forms: list[dict] = []
            target_count = len(all_targets)
            progress_window = (95 - 10) / target_count

            # See _resolve_shared_multi_target_auth's docstring — avoids
            # every target re-triggering its own form_login, which can trip
            # a shared login endpoint's own rate limiter. Single-target
            # scans skip this entirely (target_count > 1 guard) and behave
            # exactly as before this existed.
            eff_auth_mode, eff_bearer_token, eff_form_login, eff_oauth2, eff_api_key_header, eff_api_key_value = (
                await self._resolve_shared_multi_target_auth(
                    dynamic_auth_mode, dynamic_bearer_token, dynamic_form_login,
                    dynamic_oauth2, dynamic_api_key_header, dynamic_api_key_value,
                ) if target_count > 1 else
                (dynamic_auth_mode, dynamic_bearer_token, dynamic_form_login,
                 dynamic_oauth2, dynamic_api_key_header, dynamic_api_key_value)
            )
            (
                eff_second_auth_mode, eff_second_bearer_token, eff_second_form_login,
                eff_second_oauth2, eff_second_api_key_header, eff_second_api_key_value,
            ) = (
                await self._resolve_shared_multi_target_auth(
                    dynamic_second_actor_auth_mode, dynamic_second_actor_bearer_token,
                    dynamic_second_actor_form_login, dynamic_second_actor_oauth2,
                    dynamic_second_actor_api_key_header, dynamic_second_actor_api_key_value,
                ) if target_count > 1 else
                (dynamic_second_actor_auth_mode, dynamic_second_actor_bearer_token,
                 dynamic_second_actor_form_login, dynamic_second_actor_oauth2,
                 dynamic_second_actor_api_key_header, dynamic_second_actor_api_key_value)
            )

            for i, t in enumerate(all_targets):
                if target_count > 1:
                    await self._append_logs(scan_id, [f"[DAST] Target {i + 1}/{target_count}: {t}"])

                try:
                    probe_results = await asyncio.wait_for(
                        DynamicProbe().probe(t),
                        timeout=25.0,
                    )
                    dynamic_probe_findings.extend(asdict(f) for f in probe_results)
                except asyncio.TimeoutError:
                    logger.warning(f"[scan:{scan_id}] Dynamic probe timed out for {t}")
                except Exception as exc:
                    logger.warning(f"[scan:{scan_id}] Dynamic probe failed (non-blocking) for {t}: {exc}")

                # Keyword-only — see the matching comment on start()'s
                # _run_dynamic_scan dispatch for why: _run_dynamic_checks'
                # signature has dynamic_oauth2/api_key_*/state_crawl_* inserted
                # *between* existing parameters, not appended, so a positional
                # call here silently misaligns everything after the insertion
                # point the moment the two signatures next drift apart.
                try:
                    target_findings, target_forms = await self._run_dynamic_checks(
                        scan_id=scan_id, target_url=t,
                        dynamic_auth_mode=eff_auth_mode, dynamic_bearer_token=eff_bearer_token,
                        dynamic_form_login=eff_form_login, dynamic_oauth2=eff_oauth2,
                        dynamic_api_key_header=eff_api_key_header, dynamic_api_key_value=eff_api_key_value,
                        dynamic_active_mode=dynamic_active_mode,
                        dynamic_second_actor_auth_mode=eff_second_auth_mode,
                        dynamic_second_actor_bearer_token=eff_second_bearer_token,
                        dynamic_second_actor_form_login=eff_second_form_login,
                        dynamic_second_actor_oauth2=eff_second_oauth2,
                        dynamic_second_actor_api_key_header=eff_second_api_key_header,
                        dynamic_second_actor_api_key_value=eff_second_api_key_value,
                        # User-supplied scenarios/probes carry their own
                        # absolute URL, independent of which target this
                        # iteration is sweeping — attaching them to every
                        # target would run the identical probe once per
                        # target instead of once total (worse for a race
                        # probe: "5 concurrent requests" becomes 5x that
                        # many real requests against the target). Gated to
                        # the first (primary) target only, matching the
                        # single-target semantics this had before
                        # dynamic_additional_target_urls existed.
                        dynamic_scenarios=dynamic_scenarios if i == 0 else None,
                        dynamic_race_probes=dynamic_race_probes if i == 0 else None,
                        dynamic_idor_probes=dynamic_idor_probes if i == 0 else None,
                        dynamic_mass_assignment_probes=dynamic_mass_assignment_probes if i == 0 else None,
                        dynamic_timing_probes=dynamic_timing_probes if i == 0 else None,
                        dynamic_signaling_fuzz_probes=dynamic_signaling_fuzz_probes if i == 0 else None,
                        dynamic_media_flood_probes=dynamic_media_flood_probes if i == 0 else None,
                        dynamic_malformed_packet_probes=dynamic_malformed_packet_probes if i == 0 else None,
                        dynamic_srtp_auth_probes=dynamic_srtp_auth_probes if i == 0 else None,
                        dynamic_crawl_max_pages=dynamic_crawl_max_pages,
                        dynamic_crawl_max_depth=dynamic_crawl_max_depth,
                        dynamic_state_crawl_max_forms=dynamic_state_crawl_max_forms,
                        dynamic_state_crawl_max_depth=dynamic_state_crawl_max_depth,
                        dynamic_rule_ids=dynamic_rule_ids,
                        dynamic_ssrf_collaborator_host=dynamic_ssrf_collaborator_host,
                        dynamic_ssrf_collaborator_port=dynamic_ssrf_collaborator_port,
                        dynamic_openapi_spec_url=dynamic_openapi_spec_url, dynamic_openapi_spec=dynamic_openapi_spec,
                        dynamic_use_headless_browser=dynamic_use_headless_browser,
                        progress_start=int(10 + i * progress_window),
                        progress_end=int(10 + (i + 1) * progress_window),
                    )
                    dynamic_findings.extend(target_findings)
                    discovered_forms.extend(target_forms)
                except Exception as exc:
                    # Same "never let one target's failure wipe out every
                    # other target's real results" reasoning as the
                    # per-target try/except above — before this loop
                    # existed, an unhandled exception here (e.g. one
                    # service being unreachable) would propagate to the
                    # outer try/except and mark the WHOLE scan FAILED, with
                    # 0 results, even when 3 of 4 targets had already
                    # produced real findings.
                    reason = str(exc) or f"{type(exc).__name__} (no further detail from the exception)"
                    logger.warning(f"[scan:{scan_id}] Dynamic checks failed for {t} (non-blocking): {reason}")
                    await self._append_logs(
                        scan_id, [f"[DAST] Dynamic checks failed for {t} — 0 result(s). Reason: {reason}"]
                    )

            from app.domain.analysis.dast.verdict import FAILING_VERDICTS

            by_severity = {"critical": 0, "high": 0, "medium": 0, "low": 0}
            fail_count = 0
            for finding_dict in dynamic_findings:
                if finding_dict["verdict"] in FAILING_VERDICTS:
                    fail_count += 1
                    by_severity[finding_dict["severity"]] = by_severity.get(finding_dict["severity"], 0) + 1
            # dynamic_probe_findings (TLS/HSTS/cookie/git-exposure/version-
            # disclosure) is a separate detection module from the payload-
            # check findings above and was previously never folded into these
            # totals at all — every failing live-probe check was invisible to
            # vulnerabilities_found/by_severity (and everything downstream
            # that reads them: Reports list, dashboard Open Findings, this
            # scan's own stat cards) even though it showed up correctly in
            # the raw findings table, which reads dynamic_probe_findings
            # directly instead of these aggregates.
            for finding_dict in dynamic_probe_findings:
                if finding_dict["verdict"] == "fail":
                    fail_count += 1
                    sev = finding_dict.get("severity", "medium")
                    by_severity[sev] = by_severity.get(sev, 0) + 1

            duration = time.time() - start_time
            summary = {
                "scan_id": scan_id,
                "status": "COMPLETED",
                "input_type": "DYNAMIC",
                "total_files": 0,
                "files_scanned": 0,
                "vulnerabilities_found": fail_count,
                "by_severity": by_severity,
                "duration_seconds": round(duration, 2),
                "created_at": datetime.now(timezone.utc).replace(tzinfo=None).isoformat(),
                "completed_at": datetime.now(timezone.utc).replace(tzinfo=None).isoformat(),
                "vulnerabilities": [],
                "dynamic_probe_findings": dynamic_probe_findings,
                "dynamic_findings": dynamic_findings,
                "discovered_forms": discovered_forms,
            }
            await self._update_scan(
                scan_id,
                {
                    "state": "COMPLETED",
                    "progress": 100,
                    "finished_at": datetime.now(timezone.utc).replace(tzinfo=None).isoformat(),
                    "summary": summary,
                    "vulnerabilities": [],
                },
                [
                    f"[INFO] Dynamic checks run: {len(dynamic_findings)}, failed: {fail_count}",
                    f"[INFO] Live ASVS dynamic-probe checks run: {len(dynamic_probe_findings)}",
                    f"[SUCCESS] Dynamic scan completed in {duration:.2f}s",
                ],
            )
        except Exception as e:
            logger.error(f"Dynamic scan failed: {e}", exc_info=True)
            await self._update_scan(
                scan_id,
                {
                    "state": "FAILED",
                    "finished_at": datetime.now(timezone.utc).replace(tzinfo=None).isoformat(),
                    "summary": {"scan_id": scan_id, "status": "FAILED", "error": str(e)},
                },
                [f"[ERROR] Scan failed: {str(e)}"],
            )

    # Async worker that clones or extracts a repo, runs the pipeline, and saves results to MongoDB
    async def _run_repository_scan(
        self,
        scan_id: str,
        repo_id: int,
        branch: str,
        scan_mode: str,
        repo_url: Optional[str],
        repo_provider: Optional[str],
        repo_token: Optional[str],
        file_paths: Optional[list[str]],
        target_url: Optional[str] = None,
        dynamic_additional_target_urls: Optional[list[str]] = None,
        scan_type: str = "static",
        dynamic_auth_mode: str = "none",
        dynamic_bearer_token: Optional[str] = None,
        dynamic_form_login: Optional[dict] = None,
        dynamic_active_mode: bool = False,
        dynamic_second_actor_auth_mode: str = "none",
        dynamic_second_actor_bearer_token: Optional[str] = None,
        dynamic_second_actor_form_login: Optional[dict] = None,
        dynamic_scenarios: Optional[list[dict]] = None,
        dynamic_race_probes: Optional[list[dict]] = None,
        dynamic_idor_probes: Optional[list[dict]] = None,
        dynamic_crawl_max_pages: Optional[int] = None,
        dynamic_crawl_max_depth: Optional[int] = None,
        dynamic_rule_ids: Optional[list[str]] = None,
        dynamic_ssrf_collaborator_host: Optional[str] = None,
        dynamic_ssrf_collaborator_port: Optional[int] = None,
        dynamic_openapi_spec_url: Optional[str] = None,
        dynamic_openapi_spec: Optional[str] = None,
        dynamic_use_headless_browser: bool = False,
        enable_llm: bool = True,
        dynamic_mass_assignment_probes: Optional[list[dict]] = None,
        dynamic_timing_probes: Optional[list[dict]] = None,
        dynamic_signaling_fuzz_probes: Optional[list[dict]] = None,
        dynamic_media_flood_probes: Optional[list[dict]] = None,
        dynamic_malformed_packet_probes: Optional[list[dict]] = None,
        dynamic_srtp_auth_probes: Optional[list[dict]] = None,
        dynamic_oauth2: Optional[dict] = None,
        dynamic_api_key_header: Optional[str] = None,
        dynamic_api_key_value: Optional[str] = None,
        dynamic_second_actor_oauth2: Optional[dict] = None,
        dynamic_second_actor_api_key_header: Optional[str] = None,
        dynamic_second_actor_api_key_value: Optional[str] = None,
        dynamic_state_crawl_max_forms: Optional[int] = None,
        dynamic_state_crawl_max_depth: Optional[int] = None,
    ):
        trace_step("Worker: _run_repository_scan() (app/services/scan_service.py)")
        start_time = time.time()
        temp_root = None
        try:
            await self._update_scan(
                scan_id,
                {"state": "RUNNING", "started_at": datetime.now(timezone.utc).replace(tzinfo=None).isoformat(), "progress": 5},
                ["[INFO] Starting repository scan"],
            )

            await self._append_logs(scan_id, [f"[INFO] Repository ID: {repo_id}", f"[INFO] Branch: {branch}"])

            temp_root = Path(tempfile.mkdtemp(prefix="vulcan-repo-"))
            repo_root = temp_root / "repo"
            if repo_provider == "LOCAL":
                trace_step("Repo source: LOCAL archive extract")
                upload_dir = Path(settings.REPO_STORAGE_DIR) / str(repo_id)
                if not upload_dir.exists():
                    raise ValueError("No uploaded archive found for this repository")
                archives = list(upload_dir.glob("*"))
                if not archives:
                    raise ValueError("No uploaded archive found for this repository")
                archive_path = archives[0]
                await self._append_logs(scan_id, [f"[INFO] Extracting archive: {archive_path.name}"])
                self._extract_archive(archive_path, repo_root)
            elif repo_url:
                trace_step("Repo source: git clone")
                await self._append_logs(scan_id, [f"[INFO] Cloning repository: {repo_url}"])
                self._clone_repo(repo_url, branch, repo_token, repo_root)
            else:
                raise ValueError("Repository URL is missing")

            trace_step("Collecting source files for scan")
            files = self._collect_source_files(repo_root)
            if file_paths:
                allowed = {
                    path.strip().replace("\\", "/").lstrip("./")
                    for path in file_paths
                    if path
                }
                files = [
                    path
                    for path in files
                    if str(path.relative_to(repo_root)).replace("\\", "/") in allowed
                ]
            if not files:
                duration = time.time() - start_time
                summary = {
                    "scan_id": scan_id,
                    "status": "FAILED",
                    "input_type": "REPOSITORY",
                    "total_files": 0,
                    "files_scanned": 0,
                    "vulnerabilities_found": 0,
                    "by_severity": {"critical": 0, "high": 0, "medium": 0, "low": 0},
                    "duration_seconds": round(duration, 2),
                    "created_at": datetime.now(timezone.utc).replace(tzinfo=None).isoformat(),
                    "completed_at": datetime.now(timezone.utc).replace(tzinfo=None).isoformat(),
                    "error": "No scannable files found for the selected scope.",
                }
                await self._update_scan(
                    scan_id,
                    {
                        "state": "FAILED",
                        "progress": 100,
                        "finished_at": datetime.now(timezone.utc).replace(tzinfo=None).isoformat(),
                        "summary": summary,
                        "vulnerabilities": [],
                        "files_scanned": 0,
                        "total_files": 0,
                        "graph_data": None,
                    },
                    ["[ERROR] No scannable files matched the selected scope."],
                )
                return
            await self._update_scan(scan_id, {"total_files": len(files), "progress": 20})

            # Repository-level analysis (multi-file, interprocedural)
            pipeline = get_pipeline(PipelineConfig(enable_llm=enable_llm))
            trace_step("SemanticPipeline: analyze_repository()")
            scan_timeout = int(os.getenv("SCAN_TIMEOUT_SECONDS", "300"))

            parse_progress: Dict[str, Any] = {"parsed": 0, "total": len(files), "file": ""}

            def _on_parse_progress(parsed: int, total: int, file_path: str) -> None:
                parse_progress["parsed"] = parsed
                parse_progress["total"] = total
                parse_progress["file"] = file_path

            heartbeat_task = asyncio.create_task(self._report_parse_progress(scan_id, parse_progress))
            try:
                try:
                    repo_result = await asyncio.wait_for(
                        pipeline.analyze_repository(
                            repo_path=str(repo_root),
                            file_paths=[str(p.relative_to(repo_root)).replace("\\", "/") for p in files],
                            progress_callback=_on_parse_progress,
                        ),
                        timeout=scan_timeout,
                    )
                except asyncio.TimeoutError:
                    logger.warning(f"[scan:{scan_id}] analyze_repository timed out after {scan_timeout}s — completing with partial results")
                    from semantic_engine.pipeline import AnalysisResult
                    repo_result = AnalysisResult(
                        filename="repository", language="multi",
                        lines_of_code=0, analysis_time_seconds=float(scan_timeout),
                        graph_nodes=0, graph_edges=0, rules_executed=0,
                        slices_found=0, vulnerabilities_found=0,
                        vulnerabilities=[], graph_data=None,
                        warnings=["Scan timed out — partial results only"],
                        errors=[], success=False,
                        config_findings=[], dependency_findings=[], dependency_control_result=None,
                        capability_findings=[],
                    )
            finally:
                heartbeat_task.cancel()
                try:
                    await heartbeat_task
                except asyncio.CancelledError:
                    pass

            rel_paths = [str(p.relative_to(repo_root)).replace("\\", "/") for p in files]
            vulnerabilities: list[dict] = self._dedupe_vulnerabilities(
                repo_root, repo_result.vulnerabilities, rel_paths
            )
            # Normalize vulnerability file paths with suffix matching against repo files
            for vuln in vulnerabilities:
                location = vuln.get("location") or {}
                file_path = location.get("file")
                normalized = self._normalize_repo_path(repo_root, file_path, rel_paths)
                if normalized:
                    location["file"] = normalized
                    vuln["location"] = location
            static_vulnerabilities_found, by_severity = _summarize_static_findings(vulnerabilities)

            # Per-file progress bookkeeping for the live scan UI. ControlGate has no
            # graph-visualization page (that was Vulcan's CPG explorer, removed from
            # the frontend) and no ASVS control reads scan.graph_data, so the full
            # AST/CFG/DFG/CPG blob is not persisted here — for a real multi-service
            # repo it can exceed MongoDB's 16MB per-document limit and fail the scan
            # outright with no compliance benefit.
            file_map: dict[str, str] = {}
            file_order: list[str] = []

            for i, file_path in enumerate(files):
                rel_path = str(file_path.relative_to(repo_root)).replace("\\", "/")
                file_id = f"file-{i + 1}"
                file_map[file_id] = rel_path
                file_order.append(file_id)
                await self._update_scan(
                    scan_id,
                    {
                        "current_file": rel_path,
                        "files_scanned": i + 1,
                        "progress": 20 + int((i + 1) / max(len(files), 1) * 70),
                    },
                    [f"[INFO] Scanning {rel_path}..."],
                )

            # A microservice app's sibling services each live on their own
            # origin (crawler.py's same-origin rule means target_url alone
            # can never reach them) — every one gets swept within this SAME
            # hybrid scan (bridge correlation included, per target) and
            # merged into one report below, instead of needing a separate
            # scan per service. Order preserved, target_url first — dedup
            # via dict.fromkeys.
            all_targets = (
                list(dict.fromkeys([target_url, *(dynamic_additional_target_urls or [])]))
                if target_url else []
            )

            # ASVS dynamic-probe controls (V12.1.1, V12.2.1, V12.2.2, V3.4.1, V13.4.1, V13.4.6) —
            # opt-in: only runs when the user supplied a live deployment URL for this scan.
            dynamic_probe_findings: list[dict] = []
            for t in all_targets:
                try:
                    validate_public_http_url(t, allow_http=True)
                    probe_results = await asyncio.wait_for(
                        DynamicProbe().probe(t),
                        timeout=25.0,
                    )
                    dynamic_probe_findings.extend(asdict(f) for f in probe_results)
                except asyncio.TimeoutError:
                    logger.warning(f"[scan:{scan_id}] Dynamic probe timed out for {t}")
                except Exception as exc:
                    logger.warning(f"[scan:{scan_id}] Dynamic probe failed (non-blocking) for {t}: {exc}")

            # Folded in here, unconditionally on target_url rather than gated
            # on scan_type == "hybrid" below — dynamic_probe_findings gets
            # populated whenever a target_url was supplied at all, so a
            # failing live-probe check (e.g. weak HSTS, exposed .git) must
            # count here too, not only when the full DAST engine also ran.
            # Previously this whole category was invisible to by_severity/
            # vulnerabilities_found even though it showed up correctly in the
            # raw findings list.
            for finding_dict in dynamic_probe_findings:
                if finding_dict["verdict"] == "fail":
                    sev = finding_dict.get("severity", "medium")
                    by_severity[sev] = by_severity.get(sev, 0) + 1

            # scan_type="hybrid" — runs the full DAST engine (crawler, payload
            # checks, scenarios, race probes) alongside the static pipeline above,
            # against every target the passive probe loop above already swept.
            from app.domain.analysis.dast.verdict import FAILING_VERDICTS, VERDICT_RANK, Verdict

            dynamic_findings: list[dict] = []
            discovered_forms: list[dict] = []
            if scan_type == "hybrid" and all_targets:
                from app.domain.analysis.dast.bridge import build_dynamic_targets

                target_count = len(all_targets)
                progress_window = (99 - 90) / target_count

                # See _resolve_shared_multi_target_auth's docstring — avoids
                # every target re-triggering its own form_login, which can
                # trip a shared login endpoint's own rate limiter.
                eff_auth_mode, eff_bearer_token, eff_form_login, eff_oauth2, eff_api_key_header, eff_api_key_value = (
                    await self._resolve_shared_multi_target_auth(
                        dynamic_auth_mode, dynamic_bearer_token, dynamic_form_login,
                        dynamic_oauth2, dynamic_api_key_header, dynamic_api_key_value,
                    ) if target_count > 1 else
                    (dynamic_auth_mode, dynamic_bearer_token, dynamic_form_login,
                     dynamic_oauth2, dynamic_api_key_header, dynamic_api_key_value)
                )
                (
                    eff_second_auth_mode, eff_second_bearer_token, eff_second_form_login,
                    eff_second_oauth2, eff_second_api_key_header, eff_second_api_key_value,
                ) = (
                    await self._resolve_shared_multi_target_auth(
                        dynamic_second_actor_auth_mode, dynamic_second_actor_bearer_token,
                        dynamic_second_actor_form_login, dynamic_second_actor_oauth2,
                        dynamic_second_actor_api_key_header, dynamic_second_actor_api_key_value,
                    ) if target_count > 1 else
                    (dynamic_second_actor_auth_mode, dynamic_second_actor_bearer_token,
                     dynamic_second_actor_form_login, dynamic_second_actor_oauth2,
                     dynamic_second_actor_api_key_header, dynamic_second_actor_api_key_value)
                )

                for i, t in enumerate(all_targets):
                    if target_count > 1:
                        await self._append_logs(scan_id, [f"[DAST] Target {i + 1}/{target_count}: {t}"])

                    # bridge.py resolves the specific route a static finding
                    # flagged (for the rule_ids it knows a live-check
                    # counterpart for) so those exact findings get re-tested
                    # against their own URL below, not only whatever the
                    # crawler happens to stumble onto — recomputed per
                    # target since a route only resolves against the
                    # origin that actually serves it (order-service's
                    # /orders route means nothing bridged against
                    # product-service's origin).
                    bridge_targets = build_dynamic_targets(vulnerabilities, repo_root, t)

                    # Keyword-only — same reasoning as _run_dynamic_scan's call
                    # into _run_dynamic_checks above.
                    try:
                        target_findings, target_forms = await asyncio.wait_for(
                            self._run_dynamic_checks(
                                scan_id=scan_id, target_url=t,
                                dynamic_auth_mode=eff_auth_mode, dynamic_bearer_token=eff_bearer_token,
                                dynamic_form_login=eff_form_login, dynamic_oauth2=eff_oauth2,
                                dynamic_api_key_header=eff_api_key_header,
                                dynamic_api_key_value=eff_api_key_value,
                                dynamic_active_mode=dynamic_active_mode,
                                dynamic_second_actor_auth_mode=eff_second_auth_mode,
                                dynamic_second_actor_bearer_token=eff_second_bearer_token,
                                dynamic_second_actor_form_login=eff_second_form_login,
                                dynamic_second_actor_oauth2=eff_second_oauth2,
                                dynamic_second_actor_api_key_header=eff_second_api_key_header,
                                dynamic_second_actor_api_key_value=eff_second_api_key_value,
                                # See the matching comment in _run_dynamic_scan's
                                # loop — probes/scenarios carry their own
                                # absolute URL, so attaching them to every
                                # target would run each one N times instead
                                # of once. Primary target only.
                                dynamic_scenarios=dynamic_scenarios if i == 0 else None,
                                dynamic_race_probes=dynamic_race_probes if i == 0 else None,
                                dynamic_idor_probes=dynamic_idor_probes if i == 0 else None,
                                dynamic_mass_assignment_probes=dynamic_mass_assignment_probes if i == 0 else None,
                                dynamic_timing_probes=dynamic_timing_probes if i == 0 else None,
                                dynamic_signaling_fuzz_probes=dynamic_signaling_fuzz_probes if i == 0 else None,
                                dynamic_media_flood_probes=dynamic_media_flood_probes if i == 0 else None,
                                dynamic_malformed_packet_probes=dynamic_malformed_packet_probes if i == 0 else None,
                                dynamic_srtp_auth_probes=dynamic_srtp_auth_probes if i == 0 else None,
                                dynamic_crawl_max_pages=dynamic_crawl_max_pages,
                                dynamic_crawl_max_depth=dynamic_crawl_max_depth,
                                dynamic_state_crawl_max_forms=dynamic_state_crawl_max_forms,
                                dynamic_state_crawl_max_depth=dynamic_state_crawl_max_depth,
                                dynamic_rule_ids=dynamic_rule_ids,
                                dynamic_ssrf_collaborator_host=dynamic_ssrf_collaborator_host,
                                dynamic_ssrf_collaborator_port=dynamic_ssrf_collaborator_port,
                                bridge_targets=bridge_targets,
                                dynamic_openapi_spec_url=dynamic_openapi_spec_url,
                                dynamic_openapi_spec=dynamic_openapi_spec,
                                dynamic_use_headless_browser=dynamic_use_headless_browser,
                                repo_root=repo_root,
                                progress_start=int(90 + i * progress_window),
                                progress_end=int(90 + (i + 1) * progress_window),
                            ),
                            # Was 120.0 — too tight for the full active-mode rule set
                            # (13 live rules) against an app with double-digit
                            # injectable routes; verified against a real target
                            # during Track testing 2026-08-12 (2 timeouts back to
                            # back at 120s). 240s gives the full sweep room to
                            # finish instead of silently discarding every dynamic
                            # finding non-blocking on timeout (see except below).
                            # Applied per-target — each origin gets its own
                            # budget, same as before this loop existed.
                            timeout=240.0,
                        )
                        dynamic_findings.extend(target_findings)
                        discovered_forms.extend(target_forms)
                    except asyncio.TimeoutError:
                        logger.warning(f"[scan:{scan_id}] Hybrid dynamic checks timed out for {t}")
                        await self._append_logs(scan_id, [f"[DAST] Dynamic checks timed out for {t} — 0 result(s)"])
                    except Exception as exc:
                        # Same "never let one target's failure wipe out every
                        # other target's real results" reasoning as
                        # _run_dynamic_scan's per-target except — before this
                        # loop existed, one bad target here would just log a
                        # warning invisible anywhere a user could see it,
                        # same blank-reason bug fixed there.
                        reason = str(exc) or f"{type(exc).__name__} (no further detail from the exception)"
                        logger.warning(f"[scan:{scan_id}] Hybrid dynamic checks failed for {t} (non-blocking): {reason}")
                        await self._append_logs(
                            scan_id, [f"[DAST] Dynamic checks failed for {t} — 0 result(s). Reason: {reason}"]
                        )

                # Coarse correlation: annotate findings that share an ASVS control
                # between the two engines, even when neither is a bridge finding —
                # "both engines independently flagged the same control" is still a
                # real, useful triage signal (higher-confidence finding).
                static_controls = set()
                for v in vulnerabilities:
                    static_controls.update(v.get("asvs_controls") or [])
                for finding in dynamic_findings:
                    if finding.get("control_id") in static_controls:
                        finding["corroborates_static_finding"] = True

                dynamic_fail_controls = {
                    f["control_id"] for f in dynamic_findings if f["verdict"] in FAILING_VERDICTS
                }
                for v in vulnerabilities:
                    if dynamic_fail_controls & set(v.get("asvs_controls") or []):
                        v["dynamic_confirmed"] = True

                # Precise correlation (Phase 2.4): a bridge finding carries
                # the exact static finding id it was generated from directly
                # (DynamicFinding.bridge_static_finding_id, set on the
                # finding object itself by the bridge loop above — no
                # string encode/decode), so a FAIL/CONFIRMED here confirms
                # that specific static vulnerability was re-tested live, not
                # merely "some finding shares this control". Keeps the
                # strongest verdict per static id (CONFIRMED beats FAIL) so
                # report_service can tell "exploited" apart from "heuristic".
                bridge_verdict_by_id: dict[str, str] = {}
                for finding in dynamic_findings:
                    static_id = finding.get("bridge_static_finding_id")
                    if static_id and finding["verdict"] in FAILING_VERDICTS:
                        if VERDICT_RANK.get(finding["verdict"], 0) > VERDICT_RANK.get(
                            bridge_verdict_by_id.get(static_id), -1
                        ):
                            bridge_verdict_by_id[static_id] = finding["verdict"]
                for v in vulnerabilities:
                    bridge_verdict = bridge_verdict_by_id.get(v.get("id"))
                    if bridge_verdict:
                        v["dynamic_confirmed"] = True
                        v["bridge_confirmed"] = True
                        v["bridge_verdict"] = bridge_verdict

                # Reverse bridge (Phase 5.2): the other direction of the same
                # correlation. A bridge finding that came back a clean,
                # definitive PASS (not INCONCLUSIVE/NOT_TESTED/
                # NOT_CONFIGURED/SKIPPED_...) against the *exact* route a
                # static finding flagged is itself live evidence — the
                # dynamic engine actually reached that route and the class
                # of bug didn't reproduce. Downgrade, never drop: a PASS can
                # also just mean the check couldn't trigger it (wrong param
                # guess, a WAF, an auth wall), so this only lowers
                # confidence and tags the finding — it stays fully visible,
                # never silently disappears. Skips anything the FAIL/
                # CONFIRMED block above already promoted — a route can't be
                # simultaneously "reproduced" and "contradicted".
                bridge_pass_ids = {
                    finding["bridge_static_finding_id"] for finding in dynamic_findings
                    if finding.get("bridge_static_finding_id") and finding["verdict"] == Verdict.PASS.value
                }
                for v in vulnerabilities:
                    vuln_id = v.get("id")
                    if vuln_id in bridge_pass_ids and vuln_id not in bridge_verdict_by_id:
                        v["dynamic_contradicted"] = True
                        try:
                            original_confidence = float(v.get("confidence", 0.6))
                        except (TypeError, ValueError):
                            original_confidence = 0.6
                        v["confidence"] = round(original_confidence * DYNAMIC_CONTRADICTION_CONFIDENCE_FACTOR, 3)

                for finding in dynamic_findings:
                    if finding["verdict"] in FAILING_VERDICTS:
                        by_severity[finding["severity"]] = by_severity.get(finding["severity"], 0) + 1

            duration = time.time() - start_time
            summary = {
                "scan_id": scan_id,
                "status": "COMPLETED",
                "input_type": "REPOSITORY",
                "total_files": len(files),
                "files_scanned": len(files),
                "vulnerabilities_found": static_vulnerabilities_found + sum(
                    1 for f in dynamic_findings if f["verdict"] in FAILING_VERDICTS
                ) + sum(1 for f in dynamic_probe_findings if f["verdict"] == "fail"),
                "by_severity": by_severity,
                "duration_seconds": round(duration, 2),
                "created_at": datetime.now(timezone.utc).replace(tzinfo=None).isoformat(),
                "completed_at": datetime.now(timezone.utc).replace(tzinfo=None).isoformat(),
                "vulnerabilities": vulnerabilities,
                "scanned_files": list(file_map.values()),
                "config_findings": repo_result.config_findings,
                "dependency_findings": repo_result.dependency_findings,
                "dependency_control_result": repo_result.dependency_control_result,
                "capability_findings": repo_result.capability_findings,
                "dynamic_probe_findings": dynamic_probe_findings,
                "dynamic_findings": dynamic_findings,
                "discovered_forms": discovered_forms,
            }

            await self._update_scan(
                scan_id,
                {
                    "state": "COMPLETED",
                    "progress": 100,
                    "finished_at": datetime.now(timezone.utc).replace(tzinfo=None).isoformat(),
                    "summary": summary,
                    "vulnerabilities": vulnerabilities,
                    "graph_data": {"file_map": file_map, "file_order": file_order},
                },
                [f"[SUCCESS] Repository scan completed in {duration:.2f}s"],
            )

        except Exception as e:
            logger.error(f"Repository scan failed: {e}", exc_info=True)
            await self._update_scan(
                scan_id,
                {
                    "state": "FAILED",
                    "finished_at": datetime.now(timezone.utc).replace(tzinfo=None).isoformat(),
                    "summary": {"scan_id": scan_id, "status": "FAILED", "error": str(e)},
                },
                [f"[ERROR] Scan failed: {str(e)}"],
            )
        finally:
            if temp_root:
                shutil.rmtree(temp_root, ignore_errors=True)

    # Reads scan progress and state from MongoDB
    async def status(self, scan_id: str) -> ScanStatusRead:
        scan = await self.db.scans.find_one({"scan_id": scan_id})
        if not scan:
            return ScanStatusRead(
                scan_id=scan_id,
                user_id="",
                state="NOT_FOUND",
                progress=0,
                eta=None,
                started_at=None,
                finished_at=None,
                current_file=None,
                files_scanned=0,
                total_files=0,
            )

        return ScanStatusRead(
            scan_id=scan_id,
            user_id=str(scan.get("user_id")),
            state=scan.get("state", "UNKNOWN"),
            progress=scan.get("progress", 0),
            eta=None,
            started_at=scan.get("started_at"),
            finished_at=scan.get("finished_at"),
            current_file=scan.get("current_file"),
            files_scanned=scan.get("files_scanned", 0),
            total_files=scan.get("total_files", 0),
            current_dynamic_action=scan.get("current_dynamic_action"),
            dynamic_findings_count=scan.get("dynamic_findings_count", 0),
            target_url=scan.get("target_url"),
            scan_type=scan.get("scan_type"),
            created_at=scan.get("created_at"),
            updated_at=scan.get("updated_at"),
        )

    # Returns the last 100 log lines for a scan
    async def logs(self, scan_id: str) -> Dict[str, Any]:
        scan = await self.db.scans.find_one({"scan_id": scan_id}, {"logs": {"$slice": -100}})
        if not scan:
            return {"logs": []}
        return {"logs": scan.get("logs", [])}

    # Returns the completed scan summary
    async def summary(self, scan_id: str) -> Optional[ScanSummary]:
        scan = await self.db.scans.find_one({"scan_id": scan_id})
        if not scan:
            return None
        summary = scan.get("summary")
        if not summary:
            return None
        def _to_iso(value):
            return value.isoformat() if isinstance(value, datetime) else value
        merged = {
            "scan_id": scan_id,
            "user_id": str(scan.get("user_id")),
            "status": summary.get("status", scan.get("state", "UNKNOWN")),
            "input_type": summary.get("input_type", scan.get("input_type")),
            "total_files": summary.get("total_files", scan.get("total_files", 0)),
            "files_scanned": summary.get("files_scanned", scan.get("files_scanned", 0)),
            "vulnerabilities_found": summary.get(
                "vulnerabilities_found",
                len(summary.get("vulnerabilities", []) or []),
            ),
            "by_severity": summary.get("by_severity", {"critical": 0, "high": 0, "medium": 0, "low": 0}),
            "duration_seconds": summary.get("duration_seconds", 0.0),
            "created_at": _to_iso(summary.get("created_at", scan.get("created_at"))),
            "completed_at": _to_iso(summary.get("completed_at", scan.get("finished_at"))),
            "vulnerabilities": summary.get("vulnerabilities", []),
            "scanned_files": summary.get("scanned_files"),
            "config_findings": summary.get("config_findings"),
            "dependency_findings": summary.get("dependency_findings"),
            "dependency_control_result": summary.get("dependency_control_result"),
            "capability_findings": summary.get("capability_findings"),
            "dynamic_findings": summary.get("dynamic_findings"),
            "discovered_forms": summary.get("discovered_forms"),
        }
        return ScanSummary(**merged)

    # Sets scan state to CANCELLED in MongoDB
    async def cancel(self, scan_id: str) -> Dict[str, Any]:
        scan = await self.db.scans.find_one({"scan_id": scan_id})
        if not scan:
            return {"state": "NOT_FOUND"}
        await self._update_scan(
            scan_id,
            {"state": "CANCELLED", "finished_at": datetime.now(timezone.utc).replace(tzinfo=None).isoformat()},
            ["[INFO] Scan cancelled by user"],
        )
        return {"state": "CANCELLED"}

    # Lists scans visible to the user: their own, or every scan for an admin
    async def list_scans(self, user: dict) -> list[Dict[str, Any]]:
        if user.get("role") == UserRole.ADMIN.value:
            query = {}
        else:
            user_oid = to_object_id(user.get("id", ""))
            values = [str(user.get("id"))]
            if user_oid:
                values.append(user_oid)
            query = {"user_id": {"$in": values}}
        cursor = self.db.scans.find(query).sort("created_at", -1)
        scans = []
        async for scan in cursor:
            scans.append({
                "scan_id": scan.get("scan_id"),
                "user_id": str(scan.get("user_id")),
                "state": scan.get("state", "UNKNOWN"),
                "input_type": scan.get("input_type"),
                "vulnerabilities_found": scan.get("vulnerabilities_found", 0),
                "created_at": scan.get("created_at"),
                "finished_at": scan.get("finished_at"),
                "target_url": scan.get("target_url"),
                "scan_type": scan.get("scan_type"),
            })
        return scans

    # Deletes a scan document from MongoDB; returns False if it didn't exist
    async def delete(self, scan_id: str) -> bool:
        result = await self.db.scans.delete_one({"scan_id": scan_id})
        return result.deleted_count > 0

    # Checks that the user owns the scan or has admin role
    async def ensure_access(self, scan_id: str, user: dict) -> bool:
        scan = await self.db.scans.find_one({"scan_id": scan_id})
        if not scan:
            return False
        if user.get("role") == UserRole.ADMIN.value:
            return True
        return str(scan.get("user_id")) == user.get("id")
