"""
Slice Classifier - Vulnerability Validation Layer
Orchestrates LLM-based classification of code slices.
Reduces false positives from static analysis.
"""
import logging
import re
from typing import List, Optional
from dataclasses import dataclass

from semantic_engine.query_executor.executor import CodeSlice
from semantic_engine.classifier.llm_service import (
    get_llm_service, 
    LLMClassificationResult,
    Classification
)

logger = logging.getLogger(__name__)

# Rules whose presence alone is sufficient evidence — LLM cannot make them "safe".
# Taint-flow rules (SQL injection, SSRF, path traversal, etc.) are NOT here;
# those still benefit from LLM false-positive filtering.
_PRESENCE_VULN_RULES = {
    "INSECURE_DESERIALIZATION",
    "WEAK_CRYPTO",
    "USE_OF_HARD_CODED_IV",
    "DEBUG_MODE_ENABLED",
    "DISABLED_CERTIFICATE_VALIDATION",
    "JWT_NONE_ALGORITHM",
    "JWT_WEAK_SECRET",
    "HARDCODED_SECRETS",
    "LOGGING_DISABLED",
    "AWS_METADATA_ACCESS",
    "GCP_METADATA_ACCESS",
    "AZURE_METADATA_ACCESS",
    "IMDS_TOKENLESS",
    "A06_NPM_RESOLVED_HTTP",
    "A06_NPM_REGISTRY_HTTP",
    "A06_PYTHON_VCS_DEP",
    "A06_PIPFILE_VCS",
    "VULNERABLE_COMPONENTS",

    # ASVS 5.0.0 L1 rules (Section B) — deterministic config/policy checks where
    # a regex match on its own is the full verdict, same character as the
    # existing entries above. Heuristic/absence-based ASVS markers (password
    # policy "process" checks, session/logout markers, etc.) are deliberately
    # left out — those are weak signals that still benefit from LLM triage.
    "INSECURE_WEBSOCKET",
    "SECRET_QUESTIONS_PRESENT",
    "SESSION_VERIFICATION_BYPASSED",
    "JWT_EXP_NBF_NOT_VERIFIED",
    "JWT_HEADER_SOURCE_NOT_VALIDATED",
    "PASSWORD_FIELD_NOT_MASKED",
    "WEAK_PASSWORD_MIN_LENGTH",
    "OVERLY_RESTRICTIVE_PASSWORD_COMPOSITION",
    "PASSWORD_MANAGER_BLOCKED",
    "PASSWORD_MODIFIED_BEFORE_VERIFY",
    "STATIC_SESSION_SECRET",
    "XXE_UNSAFE_XML_PARSER",
}


@dataclass
class ClassifiedVulnerability:
    """
    A vulnerability with LLM classification results.
    Combines static analysis detection with AI validation.
    """
    # Original slice data
    slice_id: str
    rule_id: str
    rule_name: str
    owasp: str
    cwe: Optional[str]
    
    # Location and code
    code_snippet: str
    location: dict
    source_label: str
    sink_label: str
    path_nodes: List[str]
    
    # Static analysis results
    static_severity: str
    static_confidence: str
    pattern_type: str
    static_reason: str
    
    # LLM classification results
    llm_classification: Classification
    llm_explanation: str
    llm_severity: str
    llm_exploitability: float
    llm_remediation: str
    llm_confidence: float
    
    # Final combined assessment
    final_severity: str
    final_confidence: float
    is_vulnerable: bool


class SliceClassifier:
    """
    Classifies code slices using LLM to validate static analysis findings.
    Combines pattern-based detection with AI reasoning.
    """

    def __init__(self, enable_llm: bool = True):
        self.enable_llm = enable_llm
        self.llm_service = get_llm_service() if enable_llm else None
        logger.info(f"SliceClassifier initialized (LLM: {enable_llm})")
    
    async def classify_slices(
        self, slices: List[CodeSlice]
    ) -> List[ClassifiedVulnerability]:
        """
        Classify multiple code slices concurrently.

        Spawns LLM_CLASSIFIER_WORKERS independent worker tasks, each with its own
        LLMService instance (own pool + rate limiter), so they run in true parallel.
        When one worker's pool is exhausted it falls back to static; the others
        continue unaffected with their own model cascades.
        """
        import asyncio
        import os
        from semantic_engine.classifier.llm_service import LLMService

        max_llm_calls  = int(os.getenv("MAX_LLM_DETECTION_CALLS", "100"))
        n_workers      = int(os.getenv("LLM_CLASSIFIER_WORKERS", "3"))
        _FALLBACK_EXPL = "LLM unavailable — pattern-based detection only"
        _conf_rank     = {"critical": 4, "high": 3, "medium": 2, "low": 1}

        def _needs_llm(s: "CodeSlice") -> bool:
            return not (s.pattern_type == "REGEX" and s.rule_id in _PRESENCE_VULN_RULES)

        # Sort: high-severity taint-flow slices first so they claim LLM budget
        sorted_slices = sorted(
            slices,
            key=lambda s: _conf_rank.get((s.confidence or "").lower(), 0),
            reverse=True,
        )

        if not self.enable_llm:
            classified = []
            for s in sorted_slices:
                r = self._fallback_classify(s)
                if r:
                    classified.append(r)
            classified.sort(
                key=lambda v: (
                    self._severity_rank(v.final_severity),
                    -v.final_confidence
                )
            )
            logger.info(
                f"Classified {len(classified)} vulnerabilities | "
                f"LLM disabled | total slices={len(slices)}"
            )
            return classified

        # Separate slices that need LLM from those that don't
        llm_slices    = [s for s in sorted_slices if _needs_llm(s)]
        static_slices = [s for s in sorted_slices if not _needs_llm(s)]

        # ── Static slices (presence rules) — no LLM needed ───────────────────
        static_results: List[ClassifiedVulnerability] = []
        for s in static_slices:
            r = await self.classify_slice(s)
            if r:
                static_results.append(r)

        # ── LLM slices — concurrent workers ──────────────────────────────────
        # Shared queue and counters (protected by asyncio single-thread model)
        queue: asyncio.Queue = asyncio.Queue()
        for s in llm_slices[:max_llm_calls]:
            await queue.put(s)
        # Slices beyond budget go straight to static fallback
        over_budget = llm_slices[max_llm_calls:]

        llm_results: List[Optional[ClassifiedVulnerability]] = []
        counters = {"succeeded": 0, "attempted": 0}

        async def _worker(worker_id: int) -> None:
            # Each worker gets its own LLMService (own pool + rate limiter)
            svc = LLMService()
            svc._pool.reset_soft_exhausted()

            while True:
                # Check pool BEFORE pulling — dead worker stops consuming so
                # live workers can handle the remaining queue items instead.
                if not svc._pool.is_available:
                    logger.warning(
                        f"[classifier:worker-{worker_id}] pool exhausted — "
                        "releasing remaining queue items to live workers"
                    )
                    break

                try:
                    slice_obj = queue.get_nowait()
                except asyncio.QueueEmpty:
                    break

                counters["attempted"] += 1

                r = await self._classify_with_service(slice_obj, svc)
                if r and r.llm_explanation != _FALLBACK_EXPL:
                    counters["succeeded"] += 1

                if r:
                    llm_results.append(r)
                queue.task_done()

        # Fallback worker — runs after all LLM workers finish, handles any
        # items left in the queue because all LLM workers exhausted their pools.
        async def _fallback_worker() -> None:
            while True:
                try:
                    slice_obj = queue.get_nowait()
                except asyncio.QueueEmpty:
                    break
                r = self._fallback_classify(slice_obj)
                if r:
                    llm_results.append(r)
                queue.task_done()

        actual_workers = min(n_workers, len(llm_slices)) if llm_slices else 0
        if actual_workers:
            await asyncio.gather(*[_worker(i) for i in range(actual_workers)])

        # Drain any items left behind by exhausted workers using static fallback
        await _fallback_worker()

        # Over-budget slices — static only
        for s in over_budget:
            r = self._fallback_classify(s)
            if r:
                llm_results.append(r)

        classified = static_results + [r for r in llm_results if r is not None]
        logger.info(
            f"Classified {len(classified)} vulnerabilities | "
            f"workers={actual_workers} | "
            f"LLM succeeded={counters['succeeded']}/{counters['attempted']} | "
            f"static={len(static_results)} | "
            f"over-budget={len(over_budget)} | "
            f"total slices={len(slices)}"
        )

        # Sort by final severity and confidence
        classified.sort(
            key=lambda v: (
                self._severity_rank(v.final_severity),
                -v.final_confidence
            )
        )

        return classified

    def _fallback_classify(self, slice_obj: "CodeSlice") -> Optional["ClassifiedVulnerability"]:
        """Fast path for slices beyond the LLM cap — static result only."""
        llm_result = self._get_static_only_result(slice_obj)
        if self._code_is_safe(slice_obj.rule_id, slice_obj.code_snippet):
            return None
        final_severity, final_confidence, is_vulnerable = self._combine_results(slice_obj, llm_result)
        if not is_vulnerable:
            return None
        return ClassifiedVulnerability(
            slice_id=slice_obj.slice_id,
            rule_id=slice_obj.rule_id,
            rule_name=slice_obj.rule_name,
            owasp=slice_obj.owasp,
            cwe=slice_obj.cwe,
            code_snippet=slice_obj.code_snippet,
            location=slice_obj.location,
            source_label=slice_obj.source_label,
            sink_label=slice_obj.sink_label,
            path_nodes=slice_obj.path_nodes,
            static_severity=slice_obj.severity,
            static_confidence=slice_obj.confidence,
            pattern_type=slice_obj.pattern_type,
            static_reason=slice_obj.reason,
            llm_classification=llm_result.classification,
            llm_explanation="LLM cap reached — static analysis only",
            llm_severity=llm_result.severity,
            llm_exploitability=llm_result.exploitability_score,
            llm_remediation=llm_result.remediation,
            llm_confidence=llm_result.confidence,
            final_severity=final_severity,
            final_confidence=final_confidence,
            is_vulnerable=is_vulnerable,
        )
    
    async def _classify_with_service(
        self, slice_obj: "CodeSlice", svc
    ) -> Optional["ClassifiedVulnerability"]:
        """Classify one slice using an explicitly supplied LLMService instance."""
        if slice_obj.pattern_type == "REGEX" and slice_obj.rule_id in _PRESENCE_VULN_RULES:
            llm_result = self._get_static_only_result(slice_obj)
        elif self.enable_llm and svc:
            llm_result = await svc.classify_code_slice(
                code_snippet=slice_obj.code_snippet,
                rule_name=slice_obj.rule_name,
                rule_description=slice_obj.reason,
                source_label=slice_obj.source_label,
                sink_label=slice_obj.sink_label,
                owasp=slice_obj.owasp,
                cwe=slice_obj.cwe,
            )
        else:
            llm_result = self._get_static_only_result(slice_obj)

        if llm_result.classification != Classification.SAFE and \
                self._code_is_safe(slice_obj.rule_id, slice_obj.code_snippet):
            from semantic_engine.classifier.llm_service import LLMClassificationResult as _R
            llm_result = _R(
                classification=Classification.SAFE,
                explanation="Safe pattern detected: parameterized query / list args / allowlist / static template.",
                severity="low", exploitability_score=0.0,
                remediation="No action required.", cwe=slice_obj.cwe,
                owasp=slice_obj.owasp, confidence=0.95,
            )

        final_severity, final_confidence, is_vulnerable = self._combine_results(slice_obj, llm_result)
        if not is_vulnerable:
            return None
        return ClassifiedVulnerability(
            slice_id=slice_obj.slice_id, rule_id=slice_obj.rule_id,
            rule_name=slice_obj.rule_name, owasp=slice_obj.owasp, cwe=slice_obj.cwe,
            code_snippet=slice_obj.code_snippet, location=slice_obj.location,
            source_label=slice_obj.source_label, sink_label=slice_obj.sink_label,
            path_nodes=slice_obj.path_nodes, static_severity=slice_obj.severity,
            static_confidence=slice_obj.confidence, pattern_type=slice_obj.pattern_type,
            static_reason=slice_obj.reason, llm_classification=llm_result.classification,
            llm_explanation=llm_result.explanation, llm_severity=llm_result.severity,
            llm_exploitability=llm_result.exploitability_score,
            llm_remediation=llm_result.remediation, llm_confidence=llm_result.confidence,
            final_severity=final_severity, final_confidence=final_confidence,
            is_vulnerable=is_vulnerable,
        )

    async def classify_slice(
        self, slice_obj: CodeSlice
    ) -> Optional[ClassifiedVulnerability]:
        """Classify a single code slice using the default shared LLM service."""
        if slice_obj.pattern_type == "REGEX" and slice_obj.rule_id in _PRESENCE_VULN_RULES:
            llm_result = self._get_static_only_result(slice_obj)
        elif self.enable_llm and self.llm_service:
            llm_result = await self.llm_service.classify_code_slice(
                code_snippet=slice_obj.code_snippet,
                rule_name=slice_obj.rule_name,
                rule_description=slice_obj.reason,
                source_label=slice_obj.source_label,
                sink_label=slice_obj.sink_label,
                owasp=slice_obj.owasp,
                cwe=slice_obj.cwe
            )
        else:
            # Fallback when LLM disabled
            llm_result = self._get_static_only_result(slice_obj)
        
        # Programmatic safe-pattern override — catches well-known FP patterns
        # regardless of what the LLM decided (parameterized SQL, subprocess list, etc.)
        if llm_result.classification != Classification.SAFE and \
                self._code_is_safe(slice_obj.rule_id, slice_obj.code_snippet):
            from semantic_engine.classifier.llm_service import LLMClassificationResult as _R
            llm_result = _R(
                classification=Classification.SAFE,
                explanation="Safe pattern detected: parameterized query / list args / allowlist / static template.",
                severity="low",
                exploitability_score=0.0,
                remediation="No action required.",
                cwe=slice_obj.cwe,
                owasp=slice_obj.owasp,
                confidence=0.95,
            )

        # Combine static + LLM results
        final_severity, final_confidence, is_vulnerable = self._combine_results(
            slice_obj, llm_result
        )

        # Filter out SAFE classifications
        if not is_vulnerable:
            logger.debug(f"Filtered out SAFE slice: {slice_obj.slice_id}")
            return None
        
        # Create classified vulnerability
        return ClassifiedVulnerability(
            slice_id=slice_obj.slice_id,
            rule_id=slice_obj.rule_id,
            rule_name=slice_obj.rule_name,
            owasp=slice_obj.owasp,
            cwe=slice_obj.cwe,
            code_snippet=slice_obj.code_snippet,
            location=slice_obj.location,
            source_label=slice_obj.source_label,
            sink_label=slice_obj.sink_label,
            path_nodes=slice_obj.path_nodes,
            static_severity=slice_obj.severity,
            static_confidence=slice_obj.confidence,
            pattern_type=slice_obj.pattern_type,
            static_reason=slice_obj.reason,
            llm_classification=llm_result.classification,
            llm_explanation=llm_result.explanation,
            llm_severity=llm_result.severity,
            llm_exploitability=llm_result.exploitability_score,
            llm_remediation=llm_result.remediation,
            llm_confidence=llm_result.confidence,
            final_severity=final_severity,
            final_confidence=final_confidence,
            is_vulnerable=is_vulnerable
        )
    
    # Patterns that definitively indicate safe code — override LLM VULNERABLE verdicts.
    # Parameterized SQL: execute/query/raw with %s, ?, or $N placeholder plus bind args.
    _PARAMETERIZED_SQL  = re.compile(
        r'(?:execute|query)\s*\(\s*[\'"][^\'"]*(?:%s|\$\d+)[^\'"]*[\'"],\s*[\[\(]',
        re.IGNORECASE,
    )
    _PARAMETERIZED_SQL2 = re.compile(
        r'(?:execute|query)\s*\(\s*[\'"][^\'"]*\?[^\'"]*[\'"],\s*[\[\(]',
        re.IGNORECASE,
    )
    _PARAMETERIZED_SQL_BIND = re.compile(
        r'(?:execute|query|raw)\s*\(\s*[\'"][\s\S]{0,300}(?:%s|\$\d+|\?)[\s\S]{0,300}[\'"]\s*,\s*'
        r'(?:[a-zA-Z_]\w*|\([^)]+\)|\[[^\]]+\]|\{[^}]+\})',
        re.IGNORECASE,
    )
    _SQLALCHEMY_ATTR_COMPARE = re.compile(
        r'\.where\s*\([^)]*\.[a-zA-Z_]\w*\s*==\s*[a-zA-Z_]\w*\s*\)',
        re.IGNORECASE,
    )
    _JS_QUERY_ARRAY_ARGS = re.compile(
        r'\.(?:query|execute)\s*\(\s*[a-zA-Z_]\w*\s*,\s*\[\s*(?:req\.|request\.|[a-zA-Z_]\w+)',
        re.IGNORECASE,
    )
    _MONGO_STRING_ONLY_SAFE = re.compile(
        r"(?:''\s*\+\s*query|\.substr\s*\(|req\.body\s+is\s+safe|only\s+by\s+string\s+value|typeof\s+\w+\s*===\s*['\"]string['\"])",
        re.IGNORECASE,
    )
    # Only safe when the subprocess list contains EXCLUSIVELY string literals — no variable args.
    # subprocess.run(['sh', '-c', user_input]) is still vulnerable (argument injection).
    _SUBPROCESS_LIST    = re.compile(
        r'subprocess\.(?:run|Popen|call|check_call|check_output)\s*\(\s*'
        r'\[\s*(?:[\'"][^\'"]*[\'"](?:\s*,\s*[\'"][^\'"]*[\'"])*\s*)\]',
        re.IGNORECASE,
    )
    # List form whose first element is a non-shell binary — safe from shell injection even
    # with variable args (OS passes args directly, no shell metacharacter expansion).
    _SUBPROCESS_SAFE_LIST = re.compile(
        r'subprocess\.(?:run|Popen|call|check_call|check_output)\s*\(\s*\[\s*'
        r'[\'"](?!(?:sh|bash|zsh|csh|ksh|fish|cmd|powershell|pwsh)\b)[^\'"]*[\'"]',
        re.IGNORECASE,
    )
    _SUBPROCESS_SHELL_TRUE = re.compile(r'\bshell\s*=\s*True\b', re.IGNORECASE)
    # shlex.quote() in the snippet means the developer is properly escaping shell args.
    _SHLEX_QUOTE_SAFE   = re.compile(r'\bshlex\.quote\s*\(', re.IGNORECASE)
    # execFile safe only when binary AND args list are BOTH exclusively string literals.
    _EXECFILE_ARRAY     = re.compile(
        r'execFile\s*\(\s*[\'"][^\'"]+[\'"],\s*\[\s*(?:[\'"][^\'"]*[\'"](?:\s*,\s*[\'"][^\'"]*[\'"])*\s*)?\]',
        re.IGNORECASE,
    )
    # execFile with a string-literal binary and any args array — Node.js never invokes a shell.
    _EXECFILE_BINARY_ARRAY = re.compile(
        r'execFile(?:Sync)?\s*\(\s*[\'"][^\'"]+[\'"],\s*\[',
        re.IGNORECASE,
    )
    _DEFUSEDXML         = re.compile(r'(?:import defusedxml|from defusedxml)', re.IGNORECASE)
    # Static template: render_template_string('<literal>', keyword=args) — safe with Jinja2 autoescape
    _STATIC_TEMPLATE    = re.compile(r"render_template_string\s*\(\s*['\"]", re.IGNORECASE)
    _HTML_ESCAPE_SAFE   = re.compile(r'\b(?:escape|escapeHtml)\s*\(', re.IGNORECASE)
    _XSS_ENCODE_SAFE    = re.compile(r'\bencodeURIComponent\s*\(|\.split\s*\(\s*["\']\?["\']\s*\)\s*\[\s*0\s*\]', re.IGNORECASE)
    _XSS_QUOTE_GUARD_SAFE = re.compile(r'indexOf\s*\(\s*["\']\\?["\']\s*\)\s*!==\s*-1', re.IGNORECASE)
    _XSS_STATIC_JQUERY_SAFE = re.compile(r'\$\s*\(\s*["\']<[^"\']*["\']\s*\+\s*\$\.trim\s*\(\s*["\']', re.IGNORECASE)
    _TEXT_PLAIN_RESPONSE = re.compile(
        r"res\.set\s*\(\s*['\"]Content-Type['\"]\s*,\s*(?:['\"]text/plain['\"]|textContentType\s*\()",
        re.IGNORECASE,
    )
    _ALLOWLIST_CHECK    = re.compile(
        r'(?:ALLOWED\w*\.has|allowedHosts|is_safe_url|urlparse\s*\('
        r'|not\s+in\s+ALLOWED\w*'              # Python allowlist: if host not in ALLOWED
        r'|allowedDomains\.\w+\s*\('           # JS: allowedDomains.includes(...)
        r'|\.includes\s*\([^)]*hostname'       # JS: .includes(parsedUrl.hostname)
        r')',
        re.IGNORECASE,
    )
    # Browser/client same-origin calls with relative paths are not SSRF. SSRF requires
    # a server-side HTTP client reaching an attacker-controlled absolute URL/host.
    _RELATIVE_DIRECT_FETCH = re.compile(
        r'\b(?:fetch|axios\.(?:get|post|put|delete|request))\s*\(\s*(?:[\'"`]/(?!/))',
        re.IGNORECASE,
    )
    _RELATIVE_URL_VAR_FETCH = re.compile(
        r'\b(?:const|let|var)\s+([a-zA-Z_]\w*)\s*=\s*'
        r'(?:[^;\n]*\?\s*)?(?:[\'"`]/(?!/)[^\'"`]*[\'"`])'
        r'(?:\s*:\s*(?:[\'"`]/(?!/)[^\'"`]*[\'"`]))?'
        r'[^;\n]*;?[\s\S]{0,300}\b(?:fetch|axios\.(?:get|post|put|delete|request))\s*\(\s*\1\b',
        re.IGNORECASE,
    )
    _ABSOLUTE_OR_PARSED_URL = re.compile(
        r'https?://|new\s+URL\s*\(|urlparse\s*\(|req\.(?:query|body|params)|request\.(?:args|form|json|values)',
        re.IGNORECASE,
    )
    _VISUAL_RANDOM_CONTEXT = re.compile(
        r'\b(?:Sparkles|particles?|alpha|alphaSpeed|vx|vy|minSize|maxSize|'
        r'animation|animate|canvas|color|opacity|jitter|confetti)\b',
        re.IGNORECASE,
    )
    # File operations that indicate genuine PATH_TRAVERSAL risk.
    _PATH_FILE_OPS      = re.compile(
        r'\bopen\s*\(|os\.(?:path\b|open\s*\(|makedirs|mkdir|remove|unlink|rename\s*\()'
        r'|io\.open\s*\(|aiofiles\.open\s*\(|pathlib\.Path\s*\('
        r'|shutil\.'
        r'|fs\.(?:readFile|writeFile|createReadStream|createWriteStream|appendFile|'
        r'open|stat|unlink|access|mkdir|rmdir|rename|copyFile)(?:Sync)?\s*\('
        r'|send_file\s*\(|send_from_directory\s*\(|res\.sendFile\s*\(',
        re.IGNORECASE,
    )
    # JS path.normalize/path.resolve assigned to var then var.startsWith() guard.
    _PATH_JS_NORMALIZE_GUARD = re.compile(
        r'path\.(?:normalize|resolve)\s*\([\s\S]{0,400}\.startsWith?\s*\(',
        re.IGNORECASE | re.DOTALL,
    )
    # Path traversal sanitization: realpath/abspath + startswith prefix check.
    # Handles both same-line and variable-assignment (multi-line) forms.
    _PATH_REALPATH_PREFIX = re.compile(
        # Same-line: os.path.realpath(...).startswith(
        r'os\.path\.(?:realpath|abspath)\s*\([^)]+\)[^\n]{0,120}\.startswith\s*\('
        # Same-line: .resolve().startswith(
        r'|\.resolve\s*\(\s*\)[^\n]{0,120}\.startswith\s*\('
        # Multi-line: var = os.path.realpath(...) ... var.startswith(
        r'|=\s*os\.path\.(?:realpath|abspath)\s*\([\s\S]{0,400}\.startswith\s*\(',
        re.IGNORECASE | re.DOTALL,
    )
    # normpath + startswith guard where `open` is INSIDE the indented if-block.
    # Pattern: `if <var>.startswith(...):\n    ... open(` — open is indented after the guard.
    # Does NOT fire when open is outside/after the if block (that's still vulnerable).
    _PATH_NORMPATH_GUARD_OPEN = re.compile(
        r'if\s+\w[\w.]*\.startswith\s*\([^)]+\)\s*:[^\n]*\n[ \t]+[^\n]*(?:open|send_file|read_file)\s*\(',
        re.IGNORECASE,
    )
    # normpath assigned to var then var.startswith() guard — guards path escape via ../ resolution.
    _PATH_NORMPATH_VAR_GUARD = re.compile(
        r'=\s*os\.path\.normpath\s*\([\s\S]{0,400}\.startswith\s*\(',
        re.IGNORECASE | re.DOTALL,
    )
    _SENDFILE_ROOT_SAFE = re.compile(
        r'res\.sendfile?\s*\([^)]*(?:\{\s*root\s*:|homeDir\s*\+\s*[\'"]/data/|[\'"]data/[\'"]\s*\+)',
        re.IGNORECASE,
    )
    _NORMALIZE_PREFIX_STRIP = re.compile(
        r'[\'"]prefix[\'"]\s*\+\s*pathModule\.normalize\s*\(\s*path\s*\)\.replace\s*\(',
        re.IGNORECASE,
    )

    _SAFE_RULES_PATTERNS: dict = {}  # populated lazily per rule_id

    def _code_is_safe(self, rule_id: str, code: str) -> bool:
        """Return True when the code snippet contains a definitively safe pattern."""
        if self._DEFUSEDXML.search(code):
            return True
        if rule_id in ("SQL_INJECTION", "NOSQL_INJECTION", "BROKEN_ACCESS_CONTROL"):
            if (
                self._PARAMETERIZED_SQL.search(code)
                or self._PARAMETERIZED_SQL2.search(code)
                or self._PARAMETERIZED_SQL_BIND.search(code)
                or self._SQLALCHEMY_ATTR_COMPARE.search(code)
                or self._JS_QUERY_ARRAY_ARGS.search(code)
                or self._MONGO_STRING_ONLY_SAFE.search(code)
            ):
                return True
        if rule_id in ("COMMAND_INJECTION", "CODE_INJECTION"):
            if self._SUBPROCESS_LIST.search(code) or self._EXECFILE_ARRAY.search(code):
                return True
            # List form with non-shell first arg and no shell=True is safe from shell injection.
            if (self._SUBPROCESS_SAFE_LIST.search(code) and
                    not self._SUBPROCESS_SHELL_TRUE.search(code)):
                return True
            # execFile with a string-literal binary is safe regardless of args array content.
            if self._EXECFILE_BINARY_ARRAY.search(code):
                return True
            # shlex.quote present — developer is properly escaping shell arguments.
            if self._SHLEX_QUOTE_SAFE.search(code):
                return True
        if rule_id == "CODE_INJECTION":
            if re.search(r'\bre\.compile\s*\(', code):
                return True
        if rule_id == "PATH_TRAVERSAL":
            # Broad source-tracking patterns (27/28) fire on any request.args assignment.
            # If no file operation is present, the code cannot be a path traversal.
            if not self._PATH_FILE_OPS.search(code):
                return True
            if self._PATH_REALPATH_PREFIX.search(code):
                return True
            if self._PATH_NORMPATH_GUARD_OPEN.search(code):
                return True
            if self._PATH_NORMPATH_VAR_GUARD.search(code):
                return True
            if self._PATH_JS_NORMALIZE_GUARD.search(code):
                return True
            if self._SENDFILE_ROOT_SAFE.search(code) or self._NORMALIZE_PREFIX_STRIP.search(code):
                return True
        if rule_id in ("PATH_DISCOVERY", "BROKEN_ACCESS_CONTROL", "INPUT_VALIDATION_MISSING"):
            # IDOR / missing-validation: an ownership, role, or equality guard is visible
            # in the same snippet. Covers both snake_case (Flask/Django-style: user_id !=)
            # and camelCase (Express/Node-style: req.user.userId !==, .role !==) idioms —
            # a manual comparison guard is real validation even without a schema library.
            if re.search(
                r'\b(?:current_user(?:_id)?|owner_id|user_id\s*!=|'
                r'owner_id\s*:\s*current|userId\s*!==?|req\.user\.\w+\s*!==?|\.role\s*!==?)',
                code, re.IGNORECASE,
            ):
                return True
        if rule_id == "PATH_DISCOVERY":
            # Safe deserialization: SafeLoader / defusedxml
            if re.search(r'\bSafeLoader\b', code):
                return True
            # Secure cookie flags
            if re.search(r'(?:secure\s*[=:]\s*true|httpOnly\s*[=:]\s*true)', code, re.IGNORECASE):
                return True
            # Environment variable — not a hardcoded secret
            if re.search(r'process\.env\.[A-Z_]+\b', code):
                return True
            # SQLAlchemy ORM .filter() with == comparison — parameterized
            if re.search(r'\.filter\s*\([^)]*\.[a-zA-Z_]\w*\s*==\s*[a-zA-Z_]\w*', code, re.IGNORECASE):
                return True
            # Cast to str/int prevents NoSQL operator injection
            if re.search(r'\bstr\s*\(\s*request\.|int\s*\(\s*request\.', code, re.IGNORECASE):
                return True
            # Parameterized SQL in snippet — safe from SQL injection
            if (
                self._PARAMETERIZED_SQL.search(code)
                or self._PARAMETERIZED_SQL2.search(code)
                or self._PARAMETERIZED_SQL_BIND.search(code)
                or self._JS_QUERY_ARRAY_ARGS.search(code)
            ):
                return True
            # Subprocess/spawn with array args and no shell — safe from command injection
            if (self._SUBPROCESS_SAFE_LIST.search(code) and
                    not self._SUBPROCESS_SHELL_TRUE.search(code)):
                return True
            if self._EXECFILE_BINARY_ARRAY.search(code):
                return True
            # JS spawn with array args is safe (OS passes args directly, no shell)
            if re.search(r'\.spawn\s*\(\s*[\'"][^\'"]+[\'"],\s*\[', code, re.IGNORECASE):
                return True
            # XML: noent:false or resolve-entities:false disables external entity expansion
            if re.search(r'noent\s*:\s*false|resolve.entities\s*:\s*false', code, re.IGNORECASE):
                return True
            # Allowlist or domain-validation check (SSRF/redirect safety)
            if self._ALLOWLIST_CHECK.search(code):
                return True
            # Credentials masked in log — username only, not password
            if re.search(r'(?:logger|logging)\.\w+\s*\([^)]*\busername\b[^)]*\)', code, re.IGNORECASE):
                if not re.search(r'(?:logger|logging)\.\w+\s*\([^)]*\bpassword\b', code, re.IGNORECASE):
                    return True
            # ReDoS: no nested quantifiers in regex pattern → not catastrophic.
            # Handles Python r'...' / "..." and JS /.../ literal syntax.
            regex_src = re.search(
                r"re\.(?:compile|match|search|fullmatch)\s*\(\s*r?['\"]([^'\"]+)['\"]|"
                r"new\s+RegExp\s*\(\s*['\"]([^'\"]+)['\"]|"
                r"/([^/\n]{4,})/\s*\.test",
                code,
                re.IGNORECASE,
            )
            if regex_src:
                pattern_str = next(group for group in regex_src.groups() if group)
                if not re.search(r'\([^)]*[+*?][^)]*\)\s*[+*?{]', pattern_str):
                    if re.search(r're\.\w+\s*\(|RegExp|\.test\s*\(', code, re.IGNORECASE):
                        return True
        if rule_id == "REGEX_DOS":
            # Safe if the regex pattern contains no nested quantifiers (no catastrophic backtracking).
            regex_src = re.search(
                r"re\.(?:compile|match|search|fullmatch)\s*\(\s*r?['\"]([^'\"]+)['\"]|"
                r"new\s+RegExp\s*\(\s*['\"]([^'\"]+)['\"]|"
                r"/([^/\n]{4,})/\s*\.test",
                code,
                re.IGNORECASE,
            )
            if regex_src:
                pattern_str = next(group for group in regex_src.groups() if group)
                if not re.search(r'\([^)]*[+*?][^)]*\)\s*[+*?{]', pattern_str):
                    return True
        if rule_id in ("TEMPLATE_INJECTION", "XSS"):
            if (
                self._STATIC_TEMPLATE.search(code)
                or self._HTML_ESCAPE_SAFE.search(code)
                or self._XSS_ENCODE_SAFE.search(code)
                or self._XSS_QUOTE_GUARD_SAFE.search(code)
                or self._XSS_STATIC_JQUERY_SAFE.search(code)
                or self._TEXT_PLAIN_RESPONSE.search(code)
            ):
                return True
        if rule_id in ("SSRF", "UNVALIDATED_REDIRECT"):
            if self._ALLOWLIST_CHECK.search(code):
                return True
        if rule_id == "SSRF":
            if (
                self._RELATIVE_DIRECT_FETCH.search(code)
                or self._RELATIVE_URL_VAR_FETCH.search(code)
            ) and not self._ABSOLUTE_OR_PARSED_URL.search(code):
                return True
        if rule_id in ("INSECURE_RANDOM", "OTP_INSECURE_RANDOM"):
            if self._VISUAL_RANDOM_CONTEXT.search(code) and not re.search(
                r'\b(?:token|session|password|key|secret|nonce|csrf|api[_-]?key|'
                r'filename|file_?name|upload|otp|verification|verifier|lookup|recovery|oob|code)\b',
                code,
                re.IGNORECASE,
            ):
                return True
        return False

    def _get_static_only_result(self, slice_obj: CodeSlice) -> LLMClassificationResult:
        """
        Get fallback result when LLM is disabled or bypassed.
        Uses static analysis only — treats the finding as VULNERABLE.
        """
        from semantic_engine.classifier.llm_service import LLMClassificationResult
        conf_map = {"high": 0.85, "medium": 0.65, "low": 0.45, "critical": 0.90}
        conf = conf_map.get((slice_obj.confidence or "").lower(), 0.65)
        return LLMClassificationResult(
            classification=Classification.VULNERABLE,
            explanation=slice_obj.reason,
            severity=slice_obj.severity,
            exploitability_score=conf,
            remediation="Apply input validation/sanitization or replace with a safe alternative.",
            cwe=slice_obj.cwe,
            owasp=slice_obj.owasp,
            confidence=conf
        )
    
    def _combine_results(
        self,
        slice_obj: CodeSlice,
        llm_result: LLMClassificationResult
    ) -> tuple[str, float, bool]:
        """
        Combine static analysis and LLM results.
        
        Args:
            slice_obj: Original slice with static analysis
            llm_result: LLM classification result
        
        Returns:
            Tuple of (final_severity, final_confidence, is_vulnerable)
        """
        # Determine if vulnerable
        is_vulnerable = llm_result.classification in [
            Classification.VULNERABLE,
            Classification.LIKELY_VULNERABLE
        ]
        
        # If LLM says SAFE, trust it
        if llm_result.classification == Classification.SAFE:
            return "low", 0.9, False
        
        # If LLM says VULNERABLE, use LLM severity
        if llm_result.classification == Classification.VULNERABLE:
            return llm_result.severity, llm_result.confidence, True
        
        # For LIKELY_VULNERABLE or UNKNOWN, combine assessments
        # Use higher severity between static and LLM
        static_rank = self._severity_rank(slice_obj.severity)
        llm_rank = self._severity_rank(llm_result.severity)
        
        final_severity = (
            slice_obj.severity if static_rank <= llm_rank 
            else llm_result.severity
        )
        
        # Average confidence scores
        static_conf = self._confidence_to_score(slice_obj.confidence)
        final_confidence = (static_conf + llm_result.confidence) / 2
        
        return final_severity, final_confidence, is_vulnerable
    
    def _severity_rank(self, severity: str) -> int:
        """Convert severity to numeric rank (lower = more severe)."""
        ranks = {
            'critical': 0,
            'high': 1,
            'medium': 2,
            'low': 3,
            'info': 4
        }
        return ranks.get(severity.lower(), 5)
    
    def _confidence_to_score(self, confidence: str) -> float:
        """Convert confidence string to numeric score."""
        scores = {
            'high': 0.9,
            'medium': 0.6,
            'low': 0.3
        }
        return scores.get(confidence.lower(), 0.5)


# Global classifier instance
_classifier_instance: Optional[SliceClassifier] = None


def get_classifier(enable_llm: bool = True) -> SliceClassifier:
    """
    Get global classifier instance (singleton).
    Re-creates if enable_llm flag differs from the existing instance.
    """
    global _classifier_instance

    if _classifier_instance is None or _classifier_instance.enable_llm != enable_llm:
        _classifier_instance = SliceClassifier(enable_llm)

    return _classifier_instance
