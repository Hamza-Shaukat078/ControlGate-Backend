import asyncio
import re as _re
import tempfile
import os
import time
import uuid
from datetime import datetime
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
    ) -> tuple[str, str]:
        trace_step("Service: ScanService.start() (app/services/scan_service.py)")
        scan_id = f"scan-{uuid.uuid4().hex[:12]}"
        input_type = "DYNAMIC" if scan_type == "dynamic" else ("DIRECT_CODE" if code else "REPOSITORY")

        object_id = to_object_id(user_id)
        if not object_id:
            raise ValueError("Invalid user_id")

        now = datetime.utcnow()
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
            asyncio.create_task(self._run_dynamic_scan(
                scan_id, target_url,
                dynamic_auth_mode, dynamic_bearer_token, dynamic_form_login, dynamic_active_mode,
                dynamic_second_actor_auth_mode, dynamic_second_actor_bearer_token,
                dynamic_second_actor_form_login, dynamic_scenarios, dynamic_race_probes,
                dynamic_idor_probes,
            ))
        elif code:
            trace_step("Dispatch: create_task(_run_direct_code_scan)")
            asyncio.create_task(
                self._run_direct_code_scan(scan_id, code, language, filename, scan_mode)
            )
        else:
            trace_step("Dispatch: create_task(_run_repository_scan)")
            asyncio.create_task(
                self._run_repository_scan(
                    scan_id,
                    repo_id,
                    branch,
                    scan_mode,
                    repo_url,
                    repo_provider,
                    repo_token,
                    file_paths,
                    target_url,
                    scan_type,
                    dynamic_auth_mode,
                    dynamic_bearer_token,
                    dynamic_form_login,
                    dynamic_active_mode,
                    dynamic_second_actor_auth_mode,
                    dynamic_second_actor_bearer_token,
                    dynamic_second_actor_form_login,
                    dynamic_scenarios,
                    dynamic_race_probes,
                    dynamic_idor_probes,
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
                "$set": {"updated_at": datetime.utcnow()},
            },
        )

    # Updates scan fields and optionally appends log lines in a single atomic write
    async def _update_scan(self, scan_id: str, updates: Dict[str, Any], logs: Optional[list[str]] = None) -> None:
        update_doc: Dict[str, Any] = {"$set": {**updates, "updated_at": datetime.utcnow()}}
        if logs:
            update_doc["$push"] = {"logs": {"$each": logs}}
        await self.db.scans.update_one({"scan_id": scan_id}, update_doc)

    # Async worker that runs the pipeline on pasted code and writes results to MongoDB
    async def _run_direct_code_scan(
        self,
        scan_id: str,
        code: str,
        language: str,
        filename: Optional[str],
        scan_mode: str,
    ):
        trace_step("Worker: _run_direct_code_scan() (app/services/scan_service.py)")
        start_time = time.time()
        try:
            await self._update_scan(
                scan_id,
                {"state": "RUNNING", "started_at": datetime.utcnow().isoformat(), "progress": 10},
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
                pipeline = get_pipeline(PipelineConfig(enable_llm=True))
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
                by_severity = {"critical": 0, "high": 0, "medium": 0, "low": 0}
                for vuln in vulnerabilities:
                    severity = vuln.get("severity", "low")
                    by_severity[severity] = by_severity.get(severity, 0) + 1

                duration = time.time() - start_time
                summary = {
                    "scan_id": scan_id,
                    "status": "COMPLETED",
                    "input_type": "DIRECT_CODE",
                    "total_files": 1,
                    "files_scanned": 1,
                    "vulnerabilities_found": len(vulnerabilities),
                    "by_severity": by_severity,
                    "duration_seconds": round(duration, 2),
                    "created_at": datetime.utcnow().isoformat(),
                    "completed_at": datetime.utcnow().isoformat(),
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
                        "finished_at": datetime.utcnow().isoformat(),
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

                # Fire-and-forget oracle confirmation — never blocks scan completion
                try:
                    from app.services.confirmation_service import ConfirmationService
                    asyncio.create_task(
                        ConfirmationService(self.db).confirm_scan_findings(scan_id, vulnerabilities)
                    )
                except Exception as conf_err:
                    logger.debug("[scan:%s] confirmation task not started: %s", scan_id, conf_err)

            finally:
                if os.path.exists(tmp_path):
                    os.unlink(tmp_path)
        except Exception as e:
            logger.error(f"Direct code scan failed: {e}", exc_info=True)
            await self._update_scan(
                scan_id,
                {
                    "state": "FAILED",
                    "finished_at": datetime.utcnow().isoformat(),
                    "summary": {"scan_id": scan_id, "status": "FAILED", "error": str(e)},
                },
                [f"[ERROR] Scan failed: {str(e)}"],
            )

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
        bridge_targets: Optional[list] = None,
    ) -> tuple[list[dict], list[dict]]:
        from app.domain.analysis.dast.api_scenario import build_scenario_from_request
        from app.domain.analysis.dast.checks import run_payload_checks
        from app.domain.analysis.dast.config import ActorConfig, AuthMode, DynamicScanConfig, FormLoginConfig
        from app.domain.analysis.dast.crawler import crawl
        from app.domain.analysis.dast.findings import DynamicFinding
        from app.domain.analysis.dast.idor_probe import IdorProbeConfig, run_idor_probe
        from app.domain.analysis.dast.logout_discovery import (
            build_logout_invalidates_session_scenario,
            discover_logout_url,
        )
        from app.domain.analysis.dast.race_probe import RaceProbeConfig, run_race_probe
        from app.domain.analysis.dast.rule_loader import load_dynamic_queries
        from app.domain.analysis.dast.scenario_runner import run_scenario
        from app.domain.analysis.dast.session import DastSessionPair
        from app.domain.analysis.dast.verdict import Verdict
        from app.domain.analysis.dast.xss_probe import run_stored_xss_probe

        MAX_ADDITIONAL_CRAWL_URLS = 5
        MAX_FORMS_TO_PROBE = 5

        def _build_actor(auth_mode_str: str, bearer_token: Optional[str], form_login: Optional[dict]) -> ActorConfig:
            mode = AuthMode(auth_mode_str)
            built = ActorConfig(auth_mode=mode)
            if mode == AuthMode.BEARER:
                built.bearer_token = bearer_token
            elif mode == AuthMode.FORM_LOGIN and form_login:
                built.form_login = FormLoginConfig(**form_login)
            return built

        auth_mode = AuthMode(dynamic_auth_mode)
        actor = _build_actor(dynamic_auth_mode, dynamic_bearer_token, dynamic_form_login)
        second_actor = None
        if dynamic_second_actor_auth_mode != "none":
            second_actor = _build_actor(
                dynamic_second_actor_auth_mode, dynamic_second_actor_bearer_token,
                dynamic_second_actor_form_login,
            )

        config = DynamicScanConfig(
            target_url=target_url, actor=actor, second_actor=second_actor,
            active_mode=dynamic_active_mode,
        )

        findings = []
        discovered_forms: list[dict] = []
        discovered_form_objects: list = []
        try:
            async with DastSessionPair(config) as pair:
                check_urls = [target_url]
                try:
                    crawl_result = await asyncio.wait_for(
                        crawl(pair.primary, target_url), timeout=30.0,
                    )
                    discovered_forms = [asdict(f) for f in crawl_result.forms]
                    discovered_form_objects = crawl_result.forms
                    additional_urls = [u for u in crawl_result.urls if u != target_url]
                    check_urls = [target_url] + additional_urls[:MAX_ADDITIONAL_CRAWL_URLS]
                except asyncio.TimeoutError:
                    logger.warning(f"[scan:{scan_id}] Crawler timed out for {target_url}")
                except Exception as exc:
                    logger.warning(f"[scan:{scan_id}] Crawler failed (non-blocking): {exc}")

                findings = await asyncio.wait_for(
                    run_payload_checks(pair.primary, check_urls, active_mode=dynamic_active_mode),
                    timeout=60.0,
                )

                # Bridge targets (app/domain/analysis/dast/bridge.py): specific
                # routes a *static* finding flagged, re-tested live with the one
                # dynamic rule that matches that static rule_id — independent of
                # whatever the crawler happened to discover on its own.
                bridge_rules = load_dynamic_queries() if bridge_targets else {}
                for target in (bridge_targets or []):
                    rule = bridge_rules.get(target.dynamic_rule_id)
                    if rule is None:
                        continue
                    try:
                        bridge_results = await asyncio.wait_for(
                            run_payload_checks(
                                pair.primary, target.url, {target.dynamic_rule_id: rule},
                                active_mode=dynamic_active_mode,
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
                        finding.evidence = (
                            f"bridge:{target.static_finding_id}:{target.source_file}:{target.source_line}"
                        )
                    findings.extend(bridge_results)

                # Stored-XSS probe (Phase 4): submits each crawler-discovered
                # form with a marker payload, then checks for unescaped
                # reflection across check_urls. Bounded to the first
                # MAX_FORMS_TO_PROBE forms — each is a real (side-effecting,
                # active_mode-gated) submission, same budget reasoning as
                # MAX_ADDITIONAL_CRAWL_URLS above.
                for form in discovered_form_objects[:MAX_FORMS_TO_PROBE]:
                    try:
                        findings.append(
                            await asyncio.wait_for(
                                run_stored_xss_probe(
                                    pair.primary, form, check_urls, active_mode=dynamic_active_mode,
                                ),
                                timeout=20.0,
                            )
                        )
                    except Exception as exc:
                        logger.warning(
                            f"[scan:{scan_id}] Stored-XSS probe failed for form "
                            f"{form.action_url}: {exc}"
                        )

                if auth_mode != AuthMode.NONE:
                    logout_url = await discover_logout_url(pair.primary, target_url)
                    if logout_url:
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

                for scenario_data in (dynamic_scenarios or []):
                    try:
                        user_scenario = build_scenario_from_request(scenario_data)
                        findings.append(
                            await run_scenario(pair, user_scenario, active_mode=dynamic_active_mode)
                        )
                    except Exception as exc:
                        logger.warning(
                            f"[scan:{scan_id}] User-supplied scenario "
                            f"'{scenario_data.get('scenario_id', '?')}' failed to run: {exc}"
                        )

                for race_data in (dynamic_race_probes or []):
                    try:
                        race_config = RaceProbeConfig(**race_data)
                        findings.append(
                            await run_race_probe(pair, race_config, active_mode=dynamic_active_mode)
                        )
                    except Exception as exc:
                        logger.warning(
                            f"[scan:{scan_id}] Race probe "
                            f"'{race_data.get('scenario_id', '?')}' failed to run: {exc}"
                        )

                for idor_data in (dynamic_idor_probes or []):
                    try:
                        idor_config = IdorProbeConfig(**idor_data)
                        findings.append(
                            await run_idor_probe(pair, idor_config, active_mode=dynamic_active_mode)
                        )
                    except Exception as exc:
                        logger.warning(
                            f"[scan:{scan_id}] IDOR probe "
                            f"'{idor_data.get('scenario_id', '?')}' failed to run: {exc}"
                        )
        except asyncio.TimeoutError:
            logger.warning(f"[scan:{scan_id}] Dynamic payload checks timed out for {target_url}")
        except Exception as exc:
            logger.warning(f"[scan:{scan_id}] Dynamic payload checks failed (non-blocking): {exc}")

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
    ):
        trace_step("Worker: _run_dynamic_scan() (app/services/scan_service.py)")
        start_time = time.time()
        try:
            validate_public_http_url(target_url, allow_http=True)
            await self._update_scan(
                scan_id,
                {"state": "RUNNING", "started_at": datetime.utcnow().isoformat(), "progress": 10},
                [f"[INFO] Starting dynamic scan against {target_url}"],
            )

            dynamic_findings, discovered_forms = await self._run_dynamic_checks(
                scan_id, target_url, dynamic_auth_mode, dynamic_bearer_token, dynamic_form_login,
                dynamic_active_mode, dynamic_second_actor_auth_mode, dynamic_second_actor_bearer_token,
                dynamic_second_actor_form_login, dynamic_scenarios, dynamic_race_probes,
                dynamic_idor_probes,
            )

            by_severity = {"critical": 0, "high": 0, "medium": 0, "low": 0}
            fail_count = 0
            for finding_dict in dynamic_findings:
                if finding_dict["verdict"] == "fail":
                    fail_count += 1
                    by_severity[finding_dict["severity"]] = by_severity.get(finding_dict["severity"], 0) + 1

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
                "created_at": datetime.utcnow().isoformat(),
                "completed_at": datetime.utcnow().isoformat(),
                "vulnerabilities": [],
                "dynamic_findings": dynamic_findings,
                "discovered_forms": discovered_forms,
            }
            await self._update_scan(
                scan_id,
                {
                    "state": "COMPLETED",
                    "progress": 100,
                    "finished_at": datetime.utcnow().isoformat(),
                    "summary": summary,
                    "vulnerabilities": [],
                },
                [
                    f"[INFO] Dynamic checks run: {len(dynamic_findings)}, failed: {fail_count}",
                    f"[SUCCESS] Dynamic scan completed in {duration:.2f}s",
                ],
            )
        except Exception as e:
            logger.error(f"Dynamic scan failed: {e}", exc_info=True)
            await self._update_scan(
                scan_id,
                {
                    "state": "FAILED",
                    "finished_at": datetime.utcnow().isoformat(),
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
    ):
        trace_step("Worker: _run_repository_scan() (app/services/scan_service.py)")
        start_time = time.time()
        temp_root = None
        try:
            await self._update_scan(
                scan_id,
                {"state": "RUNNING", "started_at": datetime.utcnow().isoformat(), "progress": 5},
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
                    "created_at": datetime.utcnow().isoformat(),
                    "completed_at": datetime.utcnow().isoformat(),
                    "error": "No scannable files found for the selected scope.",
                }
                await self._update_scan(
                    scan_id,
                    {
                        "state": "FAILED",
                        "progress": 100,
                        "finished_at": datetime.utcnow().isoformat(),
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
            pipeline = get_pipeline(PipelineConfig(enable_llm=True))
            trace_step("SemanticPipeline: analyze_repository()")
            scan_timeout = int(os.getenv("SCAN_TIMEOUT_SECONDS", "300"))
            try:
                repo_result = await asyncio.wait_for(
                    pipeline.analyze_repository(
                        repo_path=str(repo_root),
                        file_paths=[str(p.relative_to(repo_root)).replace("\\", "/") for p in files],
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
            by_severity = {"critical": 0, "high": 0, "medium": 0, "low": 0}
            for vuln in vulnerabilities:
                severity = vuln.get("severity", "low")
                by_severity[severity] = by_severity.get(severity, 0) + 1

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

            # ASVS dynamic-probe controls (V12.1.1, V12.2.1, V12.2.2, V3.4.1, V13.4.1, V13.4.6) —
            # opt-in: only runs when the user supplied a live deployment URL for this scan.
            dynamic_probe_findings: list[dict] = []
            if target_url:
                try:
                    validate_public_http_url(target_url, allow_http=True)
                    probe_results = await asyncio.wait_for(
                        DynamicProbe().probe(target_url),
                        timeout=25.0,
                    )
                    dynamic_probe_findings = [asdict(f) for f in probe_results]
                except asyncio.TimeoutError:
                    logger.warning(f"[scan:{scan_id}] Dynamic probe timed out for {target_url}")
                except Exception as exc:
                    logger.warning(f"[scan:{scan_id}] Dynamic probe failed (non-blocking): {exc}")

            # scan_type="hybrid" — runs the full DAST engine (crawler, payload
            # checks, scenarios, race probes) alongside the static pipeline above,
            # against the same target_url the passive probe already uses.
            dynamic_findings: list[dict] = []
            discovered_forms: list[dict] = []
            if scan_type == "hybrid" and target_url:
                # bridge.py resolves the specific route a static finding flagged
                # (for the rule_ids it knows a live-check counterpart for) so
                # those exact findings get re-tested against their own URL below,
                # not only whatever the crawler happens to stumble onto.
                from app.domain.analysis.dast.bridge import build_dynamic_targets
                bridge_targets = build_dynamic_targets(vulnerabilities, repo_root, target_url)

                try:
                    dynamic_findings, discovered_forms = await asyncio.wait_for(
                        self._run_dynamic_checks(
                            scan_id, target_url, dynamic_auth_mode, dynamic_bearer_token,
                            dynamic_form_login, dynamic_active_mode, dynamic_second_actor_auth_mode,
                            dynamic_second_actor_bearer_token, dynamic_second_actor_form_login,
                            dynamic_scenarios, dynamic_race_probes, dynamic_idor_probes, bridge_targets,
                        ),
                        timeout=120.0,
                    )
                except asyncio.TimeoutError:
                    logger.warning(f"[scan:{scan_id}] Hybrid dynamic checks timed out for {target_url}")
                except Exception as exc:
                    logger.warning(f"[scan:{scan_id}] Hybrid dynamic checks failed (non-blocking): {exc}")

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
                    f["control_id"] for f in dynamic_findings if f["verdict"] == "fail"
                }
                for v in vulnerabilities:
                    if dynamic_fail_controls & set(v.get("asvs_controls") or []):
                        v["dynamic_confirmed"] = True

                # Precise correlation: a bridge finding's evidence carries the
                # exact static finding id it was generated from
                # (DastSession.request()'s "bridge:<id>:<file>:<line>" tag set
                # in _run_dynamic_checks), so a FAIL here confirms that specific
                # static vulnerability was re-tested live, not merely "some
                # finding shares this control".
                bridge_confirmed_ids = set()
                for finding in dynamic_findings:
                    evidence = finding.get("evidence") or ""
                    if finding["verdict"] == "fail" and evidence.startswith("bridge:"):
                        bridge_confirmed_ids.add(evidence.split(":", 3)[1])
                for v in vulnerabilities:
                    if v.get("id") in bridge_confirmed_ids:
                        v["dynamic_confirmed"] = True
                        v["bridge_confirmed"] = True

                for finding in dynamic_findings:
                    if finding["verdict"] == "fail":
                        by_severity[finding["severity"]] = by_severity.get(finding["severity"], 0) + 1

            duration = time.time() - start_time
            summary = {
                "scan_id": scan_id,
                "status": "COMPLETED",
                "input_type": "REPOSITORY",
                "total_files": len(files),
                "files_scanned": len(files),
                "vulnerabilities_found": len(vulnerabilities) + sum(
                    1 for f in dynamic_findings if f["verdict"] == "fail"
                ),
                "by_severity": by_severity,
                "duration_seconds": round(duration, 2),
                "created_at": datetime.utcnow().isoformat(),
                "completed_at": datetime.utcnow().isoformat(),
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
                    "finished_at": datetime.utcnow().isoformat(),
                    "summary": summary,
                    "vulnerabilities": vulnerabilities,
                    "graph_data": {"file_map": file_map, "file_order": file_order},
                },
                [f"[SUCCESS] Repository scan completed in {duration:.2f}s"],
            )

            # Fire-and-forget oracle confirmation — never blocks scan completion
            try:
                from app.services.confirmation_service import ConfirmationService
                asyncio.create_task(
                    ConfirmationService(self.db).confirm_scan_findings(scan_id, vulnerabilities)
                )
            except Exception as conf_err:
                logger.debug("[scan:%s] confirmation task not started: %s", scan_id, conf_err)
        except Exception as e:
            logger.error(f"Repository scan failed: {e}", exc_info=True)
            await self._update_scan(
                scan_id,
                {
                    "state": "FAILED",
                    "finished_at": datetime.utcnow().isoformat(),
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
            {"state": "CANCELLED", "finished_at": datetime.utcnow().isoformat()},
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
