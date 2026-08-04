"""
Semantic Analysis Pipeline - End-to-End Vulnerability Detection
Orchestrates: AST → CFG → DFG → Unified CPG → Query Execution → LLM Classification
Production-grade security scanning with guardrails and error handling.
"""
import asyncio
import os
import re
import time
import logging
from collections import defaultdict
from typing import List, Dict, Optional, Any
from dataclasses import dataclass, asdict, field, replace
from pathlib import Path

from app.schemas.graph import SemanticGraph
from app.domain.analysis.semantic_graph_builder import SemanticGraphBuilder
from app.domain.analysis.config_inspector import ConfigInspector
from app.domain.analysis.capability_checker import CapabilityChecker
from app.services.dependency_scanner import DependencyScanner

from semantic_engine.query_store.loader import get_query_store, QueryRule
from semantic_engine.query_executor.executor import QueryExecutor, CodeSlice
from semantic_engine.classifier.classifier import get_classifier, ClassifiedVulnerability
from app.core.trace import trace_step

logger = logging.getLogger(__name__)

# Dependency scan (V15.2.1) safeguards — network calls to OSV.dev per unique
# package, so both bounded: cap the package count and the total wall-clock time.
MAX_DEPENDENCY_PACKAGES = 150
DEPENDENCY_SCAN_TIMEOUT_SECONDS = 20

# NVD CVE enrichment — separately bounded from the OSV query above: NVD's
# rate limit forces sequential, paced requests (see nvd_client.py), so this
# is inherently slower per-item than OSV's concurrent query.
NVD_MAX_CVE_LOOKUPS = 10
NVD_ENRICHMENT_TIMEOUT_SECONDS = 75


# ── Shared "is this the same finding" logic ───────────────────────────────────
# Used by both _filter_discovery_slices (pre-classification, CodeSlice objects)
# and _dedupe_vulnerabilities (post-classification, ClassifiedVulnerability
# objects) — anything with .location ({"file", "start_line", "end_line"}) and
# .sink_label works. Previously each kept its own exact-tuple key
# (file, start_line, end_line, sink_label[, rule_name]), so a minor line-range
# or label discrepancy between two detectors of the *same* vulnerability (e.g.
# SQL_INJECTION's regex and PathDiscovery's taint graph both catching one
# cursor.execute(...) call, with slightly different snippet line ranges) let
# real duplicates survive as separate findings.

_SINK_CALL_RE = re.compile(r'([a-zA-Z_][\w.]*)\s*\(')


def _normalize_sink(label: Optional[str]) -> str:
    """
    Canonicalizes a sink_label so two detectors describing the same call
    converge on the same token — lowercased, self./this. stripped, trailing
    "()" stripped, and reduced to just the callee name when the label looks
    like a call (`Cursor.Execute(...)` and `cursor.execute` both -> "cursor.execute").
    """
    if not label:
        return ""
    label = label.strip().lower()
    match = _SINK_CALL_RE.search(label)
    normalized = match.group(1) if match else label.rstrip('();')
    return re.sub(r'^(?:self|this)\.', '', normalized)


def _same_finding(a, b) -> bool:
    """
    True if two findings are the same underlying vulnerability instance: same
    file, overlapping line range, same normalized sink. Deliberately does NOT
    compare rule_id/rule_name — two different rules genuinely converging on
    the same call (SQL_INJECTION's regex + PathDiscovery's graph both catching
    one cursor.execute(...), or a legitimate dual-signal pair like XSS +
    UNSAFE_DOM_RENDERING both firing on one `.innerHTML =` line) are the same
    finding for display purposes. The caller is responsible for merging rule
    metadata (see _dedupe_vulnerabilities) rather than discarding it — this
    function only answers "same or not".
    """
    a_loc, b_loc = a.location or {}, b.location or {}
    if a_loc.get("file") != b_loc.get("file"):
        return False
    a_start, a_end = a_loc.get("start_line", 0), a_loc.get("end_line", 0)
    b_start, b_end = b_loc.get("start_line", 0), b_loc.get("end_line", 0)
    if not (a_start <= b_end and b_start <= a_end):
        return False
    return _normalize_sink(a.sink_label) == _normalize_sink(b.sink_label)


def _cluster_by_same_finding(items: list) -> List[list]:
    """
    Groups items (CodeSlice or ClassifiedVulnerability) into clusters via
    union-find over _same_finding. Bucketed by file first since _same_finding
    always requires an exact file match, keeping the pairwise comparison
    O(n^2) per file instead of across the whole result set.
    """
    by_file: Dict[Optional[str], List[int]] = defaultdict(list)
    for idx, item in enumerate(items):
        by_file[(item.location or {}).get("file")].append(idx)

    parent = list(range(len(items)))

    def find(i: int) -> int:
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i

    def union(i: int, j: int) -> None:
        ri, rj = find(i), find(j)
        if ri != rj:
            parent[ri] = rj

    for indices in by_file.values():
        for a in range(len(indices)):
            for b in range(a + 1, len(indices)):
                i, j = indices[a], indices[b]
                if _same_finding(items[i], items[j]):
                    union(i, j)

    clusters: Dict[int, list] = defaultdict(list)
    for idx in range(len(items)):
        clusters[find(idx)].append(items[idx])
    return list(clusters.values())


@dataclass
class PipelineConfig:
    """Configuration for semantic analysis pipeline."""
    enable_llm: Optional[bool] = None  # None means: read from env
    max_graph_nodes: int = 200_000
    max_path_length: int = 50
    max_paths_per_rule: int = 100
    query_timeout: int = 30  # seconds per query
    llm_timeout: int = 15  # seconds per LLM call
    enable_cycle_detection: bool = True
    enable_path_discovery: bool = True
    path_score_threshold: float = 0.35
    max_candidate_paths: int = 200
    # How many distinct file boundaries a single PathDiscovery BFS path may
    # cross — see PathDiscovery.max_cross_file_hops. Bounds per-source search
    # cost independent of total repo size instead of the old hard cutoff at
    # 3000 graph nodes (which silently disabled discovery entirely past that).
    max_cross_file_hops: int = 2

    def __post_init__(self):
        """Load enable_llm from environment if not explicitly set."""
        if self.enable_llm is None:
            env_enable = os.getenv('ENABLE_LLM', 'true').lower()
            if env_enable in ['true', '1', 'yes']:
                self.enable_llm = True
            elif env_enable in ['false', '0', 'no']:
                self.enable_llm = False
            else:
                self.enable_llm = True


@dataclass
class AnalysisResult:
    """
    Complete analysis result with vulnerabilities and metadata.
    """
    # Input metadata
    filename: str
    language: str
    lines_of_code: int
    
    # Analysis metrics
    analysis_time_seconds: float
    graph_nodes: int
    graph_edges: int
    rules_executed: int
    slices_found: int
    vulnerabilities_found: int
    
    # Vulnerabilities (sorted by severity)
    vulnerabilities: List[Dict[str, Any]]
    
    # Warnings/errors
    warnings: List[str]
    errors: List[str]
    
    # Success status
    success: bool
    
    # Graph data for visualization (AST/CFG/DFG/CPG) - optional, has default
    graph_data: Optional[Dict[str, Any]] = None

    # ASVS config-inspection findings (.env/YAML/Dockerfile/nginx) - repo scans only
    config_findings: List[Dict[str, Any]] = field(default_factory=list)

    # ASVS dependency-scan findings (OSV.dev lookups) + V15.2.1 verdict - repo scans only
    dependency_findings: List[Dict[str, Any]] = field(default_factory=list)
    dependency_control_result: Optional[Dict[str, Any]] = None

    # ASVS "is X implemented (correctly)?" capability-check findings - repo scans only
    capability_findings: List[Dict[str, Any]] = field(default_factory=list)


class SemanticPipeline:
    """
    End-to-end semantic vulnerability analysis pipeline.
    Combines static analysis with LLM-powered classification.
    """
    
    def __init__(self, config: Optional[PipelineConfig] = None):
        """
        Initialize pipeline with configuration.
        
        Args:
            config: Pipeline configuration (uses defaults if None)
        """
        self.config = config or PipelineConfig()
        
        # Initialize components
        self.query_store = get_query_store()
        self.query_executor = QueryExecutor(
            max_path_length=self.config.max_path_length,
            max_paths_per_rule=self.config.max_paths_per_rule
        )
        self.classifier = get_classifier(enable_llm=self.config.enable_llm)
        self.config_inspector = ConfigInspector()
        self.capability_checker = CapabilityChecker()
        self.dependency_scanner = DependencyScanner()

        logger.info(f"SemanticPipeline initialized (LLM: {self.config.enable_llm})")
    
    async def analyze_code(
        self,
        filename: str,
        code: str,
        language: str = "python"
    ) -> AnalysisResult:
        trace_step("Pipeline: analyze_code() (semantic_engine/pipeline.py)")
        """
        Analyze code for security vulnerabilities.
        
        Args:
            filename: Name of file being analyzed
            code: Source code content
            language: Programming language ('python', 'javascript', etc.)
        
        Returns:
            AnalysisResult with detected vulnerabilities
        """
        start_time = time.time()
        warnings = []
        errors = []
        
        logger.info(f"Starting analysis: {filename} ({language})")
        
        try:
            # Step 1: Build semantic graph
            trace_step("Pipeline step: _build_graph()")
            graph = await self._build_graph(code, language)
            
            if graph is None:
                return self._create_error_result(
                    filename, language, code,
                    ["Failed to build semantic graph"],
                    ["Graph construction failed"]
                )
            
            # Check graph size limits
            if len(graph.nodes) > self.config.max_graph_nodes:
                error_msg = f"Graph too large: {len(graph.nodes)} nodes (limit: {self.config.max_graph_nodes})"
                logger.error(error_msg)
                return self._create_error_result(
                    filename, language, code,
                    warnings, [error_msg]
                )
            
            logger.info(f"Graph built: {len(graph.nodes)} nodes, {len(graph.edges)} edges")
            
            # Step 2: Broad path discovery (primary)
            all_slices = []
            if self.config.enable_path_discovery:
                trace_step("Pipeline step: _discover_paths()")
                discovery_slices = await self._discover_paths(graph, {filename: code})
                all_slices.extend(discovery_slices)
                logger.info(f"Path discovery: {len(discovery_slices)} candidate slices found")

            # Step 3: Execute security queries (augment discovery results)
            trace_step("Pipeline step: _execute_queries()")
            query_slices = await self._execute_queries(graph, code)
            if discovery_slices:
                discovery_slices = self._filter_discovery_slices(discovery_slices, query_slices)
            all_slices = (discovery_slices or []) + query_slices
            logger.info(f"Query execution: {len(query_slices)} slices found")
            
            # Step 4: Classify with LLM
            trace_step("Pipeline step: _classify_slices()")
            vulnerabilities = await self._classify_slices(all_slices)
            vulnerabilities = self._dedupe_vulnerabilities(vulnerabilities)
            logger.info(f"Classification: {len(vulnerabilities)} vulnerabilities confirmed")

            # Step 5: Build result
            formatted_vulns = [self._format_vulnerability(v) for v in vulnerabilities]

            analysis_time = time.time() - start_time
            graph_data    = self._serialize_graph(graph)

            result = AnalysisResult(
                filename=filename,
                language=language,
                lines_of_code=len(code.split('\n')),
                analysis_time_seconds=round(analysis_time, 2),
                graph_nodes=len(graph.nodes),
                graph_edges=len(graph.edges),
                rules_executed=len(self.query_store.get_all_queries()),
                slices_found=len(all_slices),
                vulnerabilities_found=len(vulnerabilities),
                vulnerabilities=formatted_vulns,
                graph_data=graph_data,
                warnings=warnings,
                errors=errors,
                success=True
            )
            
            logger.info(f"Analysis complete: {len(vulnerabilities)} vulnerabilities in {analysis_time:.2f}s")
            return result
        
        except Exception as e:
            logger.error(f"Analysis failed: {e}", exc_info=True)
            return self._create_error_result(
                filename, language, code,
                warnings, [str(e)]
            )
    
    async def _build_graph(self, code: str, language: str) -> Optional[SemanticGraph]:
        """
        Build unified semantic graph from source code.
        
        Args:
            code: Source code
            language: Programming language
        
        Returns:
            SemanticGraph or None on failure
        """
        try:
            _SUPPORTED = {'python', 'py', 'javascript', 'js', 'jsx', 'typescript', 'ts', 'tsx'}
            if language.lower() not in _SUPPORTED:
                logger.warning(f"Unsupported language: {language}, using Python parser")

            # Build semantic graph using existing components
            builder = SemanticGraphBuilder(language=language)
            graph = builder.build(code, filename="input")
            
            # Validate graph
            if not graph or not graph.nodes:
                logger.error("Empty graph generated")
                return None
            
            # Cycle detection (optional)
            if self.config.enable_cycle_detection:
                has_cycles = self._detect_cycles(graph)
                if has_cycles:
                    logger.debug("Cycles detected in graph (may affect path finding)")
            
            return graph
        
        except Exception as e:
            logger.error(f"Graph building failed: {e}")
            return None
    
    async def _execute_queries(
        self,
        graph: SemanticGraph,
        source_code: str,
        source_code_map: Optional[Dict[str, str]] = None
    ) -> List[CodeSlice]:
        """
        Execute all security queries against graph.
        Each query runs in a thread pool so the event loop stays responsive
        for health checks and job-status polling during long benchmark runs.
        """
        all_slices = []
        queries = self.query_store.get_all_queries()

        for query in queries:
            try:
                # Run the sync query executor in a thread so we don't block the
                # event loop. This is critical for the benchmark background task
                # which shares the loop with job-status poll requests.
                slices = await asyncio.wait_for(
                    asyncio.to_thread(
                        self.query_executor.execute_query,
                        graph, query, source_code, source_code_map,
                    ),
                    timeout=self.config.query_timeout,
                )
                all_slices.extend(slices)
            except asyncio.TimeoutError:
                logger.warning(f"Query {query.rule_id} timed out — skipped")
                continue
            except Exception as e:
                logger.error(f"Query {query.rule_id} failed: {e}")
                continue

        return all_slices

    # Runs PathDiscovery to find broad source→sink path candidates across the graph
    async def _discover_paths(
        self,
        graph: SemanticGraph,
        source_code_map: Dict[str, str]
    ) -> List[CodeSlice]:
        from semantic_engine.path_discovery import PathDiscovery
        discovery = PathDiscovery(
            max_depth=self.config.max_path_length,
            max_candidates=self.config.max_candidate_paths,
            score_threshold=self.config.path_score_threshold,
            max_cross_file_hops=self.config.max_cross_file_hops
        )
        # Run sync discovery in a thread — same reasoning as _execute_queries.
        return await asyncio.to_thread(
            discovery.discover, graph, source_code_map, self.query_store
        )

    async def analyze_repository(
        self,
        repo_path: str,
        file_paths: Optional[list[str]] = None
    ) -> AnalysisResult:
        trace_step("Pipeline: analyze_repository() (semantic_engine/pipeline.py)")
        """
        Analyze a repository with multi-file, interprocedural path discovery.
        """
        start_time = time.time()
        warnings = []
        errors = []
        try:
            from app.domain.analysis.multi_file_repo_graph import MultiFileRepositoryGraph
            trace_step("Repo graph: MultiFileRepositoryGraph.build()")
            allowed = set((p or "").replace("\\", "/") for p in (file_paths or []))
            repo_graph = MultiFileRepositoryGraph(
                repo_path,
                allowed_files=allowed if allowed else None,
            )
            # build() is pure sync — run in a thread to keep event loop live.
            result = await asyncio.to_thread(repo_graph.build)
            graph = result["global_cpg"]

            # Reload queries in case queries.json changed since startup
            self.query_store.reload()

            # Build source-code map in a thread — Path.read_text() for 40+ files
            # is blocking I/O that would stall the event loop if run inline.
            def _build_source_map() -> Dict[str, str]:
                smap: Dict[str, str] = {}
                repo_root_r = Path(repo_path).resolve()
                for mod in result["modules"]:
                    fp = mod.file_path
                    try:
                        rel = str(Path(fp).resolve().relative_to(repo_root_r)).replace("\\", "/")
                    except Exception:
                        rel = fp.replace("\\", "/")
                    if allowed and rel not in allowed:
                        continue
                    try:
                        code = Path(fp).read_text(encoding="utf-8", errors="ignore")
                        smap[fp] = code
                        smap[rel] = code
                        smap[str(Path(fp).resolve())] = code
                    except Exception:
                        continue
                return smap

            source_code_map: Dict[str, str] = await asyncio.to_thread(_build_source_map)

            # Add dependency manifests for A06 (Vulnerable & Outdated Components)
            self._add_dependency_files(repo_path, source_code_map, allowed)

            # De-duplicate source map for regex scanning.
            # Each file is stored under 3 keys (abs path, repo-rel, original path);
            # passing all 3 to _execute_regex_patterns would scan every file 3×,
            # tripling regex work and GIL-hold time.  Keep only one key per unique
            # content object so regex runs exactly once per file.
            _seen_ids: set = set()
            regex_source_map: Dict[str, str] = {}
            for _key, _code in source_code_map.items():
                _fid = id(_code)
                if _fid not in _seen_ids:
                    _seen_ids.add(_fid)
                    regex_source_map[_key] = _code

            # Broad path discovery
            all_slices = []
            if self.config.enable_path_discovery:
                trace_step("Pipeline step: _discover_paths() [repo]")
                discovery_slices = await self._discover_paths(graph, regex_source_map)
                logger.info(f"Path discovery: {len(discovery_slices)} candidate slices found")

            # Always augment with rule-based queries
            concat_source = "\n".join(regex_source_map.values()) if regex_source_map else ""
            trace_step("Pipeline step: _execute_queries() [repo]")
            query_slices = await self._execute_queries(graph, concat_source, regex_source_map)
            if discovery_slices:
                discovery_slices = self._filter_discovery_slices(discovery_slices, query_slices)
            all_slices = (discovery_slices or []) + query_slices
            logger.info(f"Query execution: {len(query_slices)} slices found")

            trace_step("Pipeline step: _classify_slices() [repo]")
            vulnerabilities = await self._classify_slices(all_slices)
            vulnerabilities = self._dedupe_vulnerabilities(vulnerabilities)

            formatted_vulns = [self._format_vulnerability(v) for v in vulnerabilities]

            # ASVS config-inspection controls (V3.2.1, V3.4.1, V4.1.1, V5.2.1, V5.3.1)
            config_map = await asyncio.to_thread(self._collect_config_files, repo_path)
            config_findings = [asdict(f) for f in self.config_inspector.inspect(config_map)] if config_map else []

            # ASVS "is X implemented (correctly)?" capability checks (V6.2.2, V6.2.3, V6.2.4,
            # V6.3.1, V6.4.1, V7.2.4, V7.4.1, V7.4.2, V14.3.1) — LLM-judged, never blocks the
            # scan if it fails.
            capability_findings: list[dict] = []
            try:
                capability_results = await self.capability_checker.check(regex_source_map)
                capability_findings = [asdict(f) for f in capability_results]
            except Exception as exc:
                logger.warning(f"Capability check failed (non-blocking): {exc}")

            # ASVS dependency-scan control (V15.2.1) — network calls to OSV.dev, so
            # wrapped in its own timeout: a slow/unreachable network degrades this
            # one control to not_tested rather than stalling the whole scan.
            dependency_findings: list[dict] = []
            dependency_control_result: Optional[dict] = None
            try:
                manifest_map = await asyncio.to_thread(self._collect_dependency_manifest_files, repo_path)
                if manifest_map:
                    refs = self.dependency_scanner.parse_manifests(manifest_map)
                    refs = refs[:MAX_DEPENDENCY_PACKAGES]
                    findings = await asyncio.wait_for(
                        self.dependency_scanner.query_osv(refs),
                        timeout=DEPENDENCY_SCAN_TIMEOUT_SECONDS,
                    )
                    if any(f.cve_ids for f in findings):
                        try:
                            await asyncio.wait_for(
                                self.dependency_scanner.enrich_with_nvd(findings, max_lookups=NVD_MAX_CVE_LOOKUPS),
                                timeout=NVD_ENRICHMENT_TIMEOUT_SECONDS,
                            )
                        except asyncio.TimeoutError:
                            logger.warning(
                                f"NVD CVE enrichment timed out after {NVD_ENRICHMENT_TIMEOUT_SECONDS}s — "
                                f"dependency findings keep their OSV-derived severity, unenriched"
                            )
                        except Exception as exc:
                            logger.warning(f"NVD CVE enrichment failed (non-blocking): {exc}")
                    dependency_findings = [asdict(f) for f in findings]
                    dependency_control_result = self.dependency_scanner.evaluate_v15_2_1(findings)
            except asyncio.TimeoutError:
                logger.warning(f"[V15.2.1] Dependency scan timed out after {DEPENDENCY_SCAN_TIMEOUT_SECONDS}s — control left not_tested")
            except Exception as exc:
                logger.warning(f"[V15.2.1] Dependency scan failed (non-blocking): {exc}")

            analysis_time = time.time() - start_time
            graph_data    = self._serialize_graph(graph)
            return AnalysisResult(
                filename="repository",
                language="multi",
                lines_of_code=sum(len(code.splitlines()) for code in source_code_map.values()),
                analysis_time_seconds=round(analysis_time, 2),
                graph_nodes=len(graph.nodes),
                graph_edges=len(graph.edges),
                rules_executed=len(self.query_store.get_all_queries()),
                slices_found=len(all_slices),
                vulnerabilities_found=len(vulnerabilities),
                vulnerabilities=formatted_vulns,
                graph_data=graph_data,
                warnings=warnings,
                errors=errors,
                success=True,
                config_findings=config_findings,
                dependency_findings=dependency_findings,
                dependency_control_result=dependency_control_result,
                capability_findings=capability_findings,
            )
        except Exception as e:
            logger.error(f"Repository analysis failed: {e}", exc_info=True)
            return self._create_error_result(
                "repository", "multi", "", warnings, [str(e)]
            )

    def _add_dependency_files(
        self,
        repo_path: str,
        source_code_map: Dict[str, str],
        allowed: set
    ) -> None:
        """Add dependency manifests/locks to source map for regex-based rules."""
        repo_root = Path(repo_path)
        file_names = {
            "requirements.txt",
            "requirements-dev.txt",
            "pipfile",
            "pipfile.lock",
            "pyproject.toml",
            "poetry.lock",
            "setup.cfg",
            ".npmrc",
            "package.json",
            "package-lock.json",
            "npm-shrinkwrap.json",
            "yarn.lock",
            "pnpm-lock.yaml"
        }
        exclude_dirs = {"node_modules", "venv", ".venv", ".git", "__pycache__", "dist", "build"}

        for path in repo_root.rglob("*"):
            if not path.is_file():
                continue
            if path.name.lower() not in file_names:
                continue
            if any(part in exclude_dirs for part in path.parts):
                continue

            rel_path = str(path.relative_to(repo_root)).replace("\\", "/")
            # Config/manifest files are always included for A06 rules —
            # do NOT filter them by the source-file allowed set.
            try:
                code = path.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue

            abs_path = str(path)
            source_code_map.setdefault(abs_path, code)
            source_code_map.setdefault(rel_path, code)

    def _collect_config_files(self, repo_path: str) -> Dict[str, str]:
        """Collect .env/YAML/Dockerfile/nginx-style files for ConfigInspector (ASVS config_inspection controls)."""
        repo_root = Path(repo_path)
        exclude_dirs = {"node_modules", "venv", ".venv", ".git", "__pycache__", "dist", "build"}
        config_map: Dict[str, str] = {}

        def _is_candidate(path: Path) -> bool:
            name = path.name.lower()
            if name == ".env" or name.startswith(".env."):
                return True
            if name == "dockerfile" or name.startswith("dockerfile."):
                return True
            if name.endswith((".yml", ".yaml", ".conf")):
                return True
            if "nginx" in name:
                return True
            return False

        for path in repo_root.rglob("*"):
            if not path.is_file() or not _is_candidate(path):
                continue
            if any(part in exclude_dirs for part in path.parts):
                continue
            try:
                rel_path = str(path.relative_to(repo_root)).replace("\\", "/")
                config_map[rel_path] = path.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue

        return config_map

    def _collect_dependency_manifest_files(self, repo_path: str) -> Dict[str, str]:
        """Collect dependency manifests/lockfiles for DependencyScanner (ASVS V15.2.1)."""
        repo_root = Path(repo_path)
        exclude_dirs = {"node_modules", "venv", ".venv", ".git", "__pycache__", "dist", "build"}
        manifest_names = {
            "requirements.txt", "requirements-dev.txt", "pyproject.toml",
            "pipfile.lock", "package.json", "package-lock.json",
        }
        manifest_map: Dict[str, str] = {}

        for path in repo_root.rglob("*"):
            if not path.is_file() or path.name.lower() not in manifest_names:
                continue
            if any(part in exclude_dirs for part in path.parts):
                continue
            try:
                rel_path = str(path.relative_to(repo_root)).replace("\\", "/")
                manifest_map[rel_path] = path.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue

        return manifest_map

    def build_graph_data(
        self,
        code: str,
        language: str = "python",
        filename: str = "input"
    ) -> Optional[Dict[str, Any]]:
        """Build and serialize graph data without running queries/LLM."""
        try:
            builder = SemanticGraphBuilder(language=language)
            graph = builder.build(code, filename=filename)
            return self._serialize_graph(graph)
        except Exception:
            return None
    
    async def _classify_slices(
        self, slices: List[CodeSlice]
    ) -> List[ClassifiedVulnerability]:
        """
        Classify code slices using LLM.
        
        Args:
            slices: List of code slices
        
        Returns:
            List of classified vulnerabilities (filtered for true positives)
        """
        return await self.classifier.classify_slices(slices)

    def _filter_discovery_slices(
        self,
        discovery_slices: List[CodeSlice],
        query_slices: List[CodeSlice]
    ) -> List[CodeSlice]:
        """
        Drop a discovery slice already covered by a rule-based slice from the
        SAME rule — true re-detection, not worth spending LLM budget on twice.
        Uses _same_finding (overlapping range + normalized sink) rather than
        an exact location/label match, since a discovery slice's snippet
        window rarely lines up byte-for-byte with the regex slice's.

        Deliberately scoped to same-rule_id only: a discovery slice attributed
        (via PathDiscovery._attribute_rule) to a DIFFERENT rule than a nearby
        query slice is a genuinely distinct signal at this pre-classification
        stage, so it's kept here. If it turns out to describe the same
        underlying finding as that other rule's slice, _dedupe_vulnerabilities
        merges them properly after classification, unioning both rules' ASVS
        mappings onto one result instead of one silently vanishing before it
        ever got the chance.
        """
        query_slices_by_rule: Dict[str, List[CodeSlice]] = defaultdict(list)
        for s in query_slices:
            query_slices_by_rule[s.rule_id].append(s)

        filtered = []
        for s in discovery_slices:
            same_rule_query_slices = query_slices_by_rule.get(s.rule_id, [])
            if any(_same_finding(s, q) for q in same_rule_query_slices):
                continue
            filtered.append(s)
        return filtered

    def _dedupe_vulnerabilities(
        self,
        vulnerabilities: List[ClassifiedVulnerability]
    ) -> List[ClassifiedVulnerability]:
        """
        Collapse findings that _same_finding considers the same underlying
        vulnerability instance into one, keeping the most "sure" one as the
        display primary — but unioning the rest of the cluster's rule_ids
        onto it via contributing_rule_ids instead of just discarding them.

        _same_finding ignores rule identity by design, so this also merges
        genuine dual-signal pairs (e.g. XSS + UNSAFE_DOM_RENDERING both firing
        on one `.innerHTML =` line) into a single displayed finding rather
        than two near-identical entries. That's safe specifically because of
        the union: _format_vulnerability reads asvs_controls from
        [rule_id] + contributing_rule_ids, so both rules' ASVS controls still
        get a verdict — nothing is silently dropped by folding two rules'
        findings together.
        """
        if not vulnerabilities:
            return vulnerabilities

        severity_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

        def rank(v: ClassifiedVulnerability) -> tuple:
            sev = severity_rank.get((v.final_severity or "").lower(), 0)
            conf = v.final_confidence or 0.0
            llm_value = getattr(v.llm_classification, "value", v.llm_classification)
            if llm_value == "VULNERABLE":
                strength = 2
            elif llm_value == "LIKELY_VULNERABLE":
                strength = 1
            else:
                strength = 0
            has_snippet = 1 if (v.code_snippet or "").strip() else 0
            path_len = len(v.path_nodes or [])
            return (strength, has_snippet, conf, sev, -path_len)

        merged: List[ClassifiedVulnerability] = []
        for cluster in _cluster_by_same_finding(vulnerabilities):
            primary = max(cluster, key=rank)
            other_rule_ids = {v.rule_id for v in cluster} - {primary.rule_id}
            if other_rule_ids:
                primary = replace(
                    primary,
                    contributing_rule_ids=sorted(
                        set(primary.contributing_rule_ids) | other_rule_ids
                    ),
                )
            merged.append(primary)

        return merged
    
    def _detect_cycles(self, graph: SemanticGraph) -> bool:
        """
        Detect cycles in graph using DFS.
        
        Args:
            graph: Semantic graph
        
        Returns:
            True if cycles detected
        """
        # Build adjacency list
        adj = {}
        for edge in graph.edges:
            if edge.from_node not in adj:
                adj[edge.from_node] = []
            adj[edge.from_node].append(edge.to_node)
        
        # DFS cycle detection
        visited = set()
        rec_stack = set()
        
        def has_cycle(node):
            visited.add(node)
            rec_stack.add(node)
            
            for neighbor in adj.get(node, []):
                if neighbor not in visited:
                    if has_cycle(neighbor):
                        return True
                elif neighbor in rec_stack:
                    return True
            
            rec_stack.remove(node)
            return False
        
        for node in graph.nodes:
            if node.id not in visited:
                if has_cycle(node.id):
                    return True
        
        return False
    
    def _serialize_graph(self, graph) -> Dict[str, Any]:
        """
        Serialize semantic graph to JSON-serializable format.
        
        Args:
            graph: SemanticGraph object
        
        Returns:
            Dictionary with nodes and edges
        """
        nodes = []
        for node in graph.nodes:
            metadata = node.metadata if node.metadata else {}
            nodes.append({
                "id": node.id,
                "label": node.name or str(node.type),
                "type": str(node.type),
                "node_type": getattr(metadata, 'graph_type', 'AST') if hasattr(metadata, 'graph_type') else 'AST',
                "properties": {
                    "file": node.file,
                    "line": node.line,
                    "column": node.column,
                    "value": str(node.value) if node.value is not None else None
                }
            })
        
        edges = []
        for edge in graph.edges:
            edge_metadata = edge.metadata if edge.metadata else {}
            edges.append({
                "source": edge.from_node,
                "target": edge.to_node,
                "type": str(edge.type),
                "edge_type": edge_metadata.get('graph_type', 'CHILD') if isinstance(edge_metadata, dict) else 'CHILD',
                "label": str(edge.type),
                "properties": edge_metadata if isinstance(edge_metadata, dict) else {}
            })
        
        return {
            "nodes": nodes,
            "edges": edges
        }
    
    @staticmethod
    def _compute_cvss_score(severity: str, exploitability: float) -> float:
        """
        Approximate CVSS v3.1 Base Score from severity band + exploitability.
        Maps: critical 9.0-10.0, high 7.0-8.9, medium 4.0-6.9, low 0.1-3.9
        """
        bands = {
            "critical": (9.0, 10.0),
            "high":     (7.0,  8.9),
            "medium":   (4.0,  6.9),
            "low":      (0.1,  3.9),
        }
        lo, hi = bands.get((severity or "").lower(), (4.0, 6.9))
        score = lo + (hi - lo) * max(0.0, min(1.0, exploitability))
        return round(score, 1)

    def _format_vulnerability(self, vuln: ClassifiedVulnerability) -> Dict[str, Any]:
        """
        Format vulnerability for API response.

        Args:
            vuln: Classified vulnerability

        Returns:
            Dictionary representation
        """
        cvss_score = self._compute_cvss_score(vuln.final_severity, vuln.llm_exploitability)

        # _dedupe_vulnerabilities may have merged this finding with one or more
        # other rules' findings for the same underlying vulnerability instance
        # (see _same_finding) — contributing_rule_ids holds the rest of that
        # cluster. Union every contributing rule's asvs_controls onto this one
        # result instead of only reading the primary rule_id's mapping, so
        # folding e.g. XSS + UNSAFE_DOM_RENDERING into one displayed finding
        # doesn't silently drop UNSAFE_DOM_RENDERING's V3.2.2 mapping.
        all_rule_ids = [vuln.rule_id] + list(vuln.contributing_rule_ids)
        rules = [r for r in (self.query_store.get_query(rid) for rid in all_rule_ids) if r]
        primary_rule = rules[0] if rules else None

        asvs_controls: List[str] = []
        for r in rules:
            for control_id in r.asvs_controls:
                if control_id not in asvs_controls:
                    asvs_controls.append(control_id)

        return {
            "id": vuln.slice_id,
            "type": vuln.rule_name,
            "severity": vuln.final_severity,
            "confidence": round(vuln.final_confidence, 2),
            "cvss_score": cvss_score,
            "owasp": vuln.owasp,
            "cwe": vuln.cwe,
            "asvs_controls": asvs_controls,
            "asvs_finding_polarity": primary_rule.finding_polarity if primary_rule else "vulnerable",
            # Other rules folded into this one by _dedupe_vulnerabilities, for
            # anything that wants to show the full picture rather than just the
            # primary rule_id/rule_name above.
            "contributing_rules": [
                {"rule_id": r.rule_id, "name": r.name} for r in rules[1:]
            ],
            # True only when NO rule at all — primary or merged-in — resolved
            # to a real catalog entry. A path-discovery finding whose source
            # and sink didn't both match a single existing rule (see
            # PathDiscovery._attribute_rule) has no owasp/cwe/asvs mapping to
            # fall back on — it's a genuinely novel flow, not a bug. Flag it
            # explicitly so the UI surfaces it as "needs manual triage" instead
            # of letting it quietly disappear from any view that groups/
            # filters by owasp, cwe, or ASVS control. (Checking `not rules`
            # rather than `rule_id == "PATH_DISCOVERY"` matters here: if a real
            # rule's finding got merged into a PATH_DISCOVERY-tagged primary,
            # that real rule's ASVS controls are still present via `rules`, so
            # this must NOT be flagged as needing triage.)
            "needs_manual_triage": not rules,

            "location": {
                "file": vuln.location.get("file", "unknown"),
                "start_line": vuln.location.get("start_line", 0),
                "end_line": vuln.location.get("end_line", 0)
            },

            "evidence": {
                "source": vuln.source_label,
                "sink": vuln.sink_label,
                "pattern": vuln.pattern_type,
                "code_snippet": vuln.code_snippet,
                "data_flow_path": vuln.path_nodes
            },

            "analysis": {
                "static_detection": {
                    "severity": vuln.static_severity,
                    "confidence": vuln.static_confidence,
                    "reason": vuln.static_reason
                },
                "llm_classification": {
                    "classification": vuln.llm_classification.value,
                    "severity": vuln.llm_severity,
                    "exploitability": round(vuln.llm_exploitability, 2),
                    "confidence": round(vuln.llm_confidence, 2),
                    "explanation": vuln.llm_explanation,
                    "remediation": vuln.llm_remediation
                }
            }
        }
    
    def _create_error_result(
        self,
        filename: str,
        language: str,
        code: str,
        warnings: List[str],
        errors: List[str]
    ) -> AnalysisResult:
        """Create error result when analysis fails."""
        return AnalysisResult(
            filename=filename,
            language=language,
            lines_of_code=len(code.split('\n')),
            analysis_time_seconds=0.0,
            graph_nodes=0,
            graph_edges=0,
            rules_executed=0,
            slices_found=0,
            vulnerabilities_found=0,
            vulnerabilities=[],
            warnings=warnings,
            errors=errors,
            success=False
        )


# Global pipeline instance
_pipeline_instance: Optional[SemanticPipeline] = None


def get_pipeline(config: Optional[PipelineConfig] = None) -> SemanticPipeline:
    """
    Get global pipeline instance (singleton).
    
    Args:
        config: Pipeline configuration (only used on first call)
    
    Returns:
        SemanticPipeline instance
    """
    global _pipeline_instance
    
    if _pipeline_instance is None:
        _pipeline_instance = SemanticPipeline(config)
    elif config is not None:
        if _pipeline_instance.config.enable_llm != config.enable_llm:
            _pipeline_instance = SemanticPipeline(config)
    
    return _pipeline_instance
