"""Static -> dynamic bridge (Phase 2 of the static+dynamic plan).

Static taint findings (semantic_engine.classifier.ClassifiedVulnerability,
formatted via SemanticPipeline._format_vulnerability) point at a file+line,
never at a live URL — no route information exists anywhere on that dataclass
or in its formatted dict. Today the dynamic engine can therefore only ever
test what the crawler happens to discover on its own (crawler.py, max_depth
2 / max_pages 10) or what the caller manually lists in target_url — it has
no way to specifically go re-test the exact route a static finding flagged.

build_dynamic_targets() closes that gap for the handful of static rules that
have a matching live check (queries/dynamic_queries.json): it walks upward
from each flagged line looking for the nearest Flask/FastAPI decorator or
Express route-registration call, and — only when that resolves cleanly —
turns "this file/line is tainted" into "run this specific dynamic check
against this specific URL".

Best-effort and intentionally narrow:
  - Only the rule_ids in STATIC_TO_DYNAMIC_RULE_MAP participate; most of the
    202 static rules have no live-check counterpart yet and are silently
    skipped here, not guessed at.
  - Route resolution is regex/heuristic, same weight class as crawler.py and
    logout_discovery.py, not a real Flask/Express AST walk. A finding whose
    route can't be confidently resolved is skipped rather than mapped to a
    wrong URL — a wrong bridge target is worse than no bridge target.
  - REFLECTED_XSS_LIVE/SQL_INJECTION_LIVE (checks.py) deliberately only test
    query params a URL already carries — no fixed candidate-param-name list
    the way OPEN_REDIRECT_LIVE has, so a bare route URL isn't enough for
    these two. For rule_ids mapped to them, the tainted param name is
    regex-extracted from the static finding's source_label (e.g.
    request.args.get('q')) and appended to the bridge URL; if it can't be
    extracted, the finding is skipped rather than producing a target that
    could only ever return NOT_TESTED.
"""
import logging
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional
from urllib.parse import urlencode, urljoin

logger = logging.getLogger(__name__)

# Only rules with a real live-check counterpart today (queries/dynamic_queries.json).
# Extend this alongside new dynamic payload checks as they're added.
STATIC_TO_DYNAMIC_RULE_MAP: Dict[str, str] = {
    "UNVALIDATED_REDIRECT": "OPEN_REDIRECT_LIVE",
    "PATH_TRAVERSAL": "DOUBLE_DECODE_BYPASS",
    "HTTP_REQUEST_SMUGGLING": "REQUEST_SMUGGLING",
    "XSS": "REFLECTED_XSS_LIVE",
    "SQL_INJECTION": "SQL_INJECTION_LIVE",
    # SSRF_LIVE isn't a checks.py payload check (it needs a CollaboratorServer,
    # not just a session+rule) — scan_service.py's bridge loop special-cases
    # this dynamic_rule_id rather than routing it through run_payload_checks
    # like the others above.
    "SSRF": "SSRF_LIVE",
}

# Dynamic rule_ids that only test query params a URL already carries — see
# module docstring. A bridge target for one of these needs a param name.
_PARAM_DEPENDENT_DYNAMIC_RULES = {"REFLECTED_XSS_LIVE", "SQL_INJECTION_LIVE", "SSRF_LIVE"}

# Common "read a query/GET param" idioms across the languages universal_parser
# targets — same best-effort spirit as the route regexes below, not a real
# expression-level taint tracker (that's the static engine's job; this only
# needs the param *name*, which is almost always a literal string argument).
_PARAM_NAME_PATTERNS = [
    re.compile(r"""request\.args\.get\(\s*['"](\w+)['"]"""),          # Flask
    re.compile(r"""request\.args\[\s*['"](\w+)['"]\s*\]"""),          # Flask
    re.compile(r"""request\.GET\.get\(\s*['"](\w+)['"]"""),           # Django
    re.compile(r"""request\.GET\[\s*['"](\w+)['"]\s*\]"""),           # Django
    re.compile(r"""req\.query\.(\w+)\b"""),                           # Express
    re.compile(r"""req\.query\[\s*['"](\w+)['"]\s*\]"""),             # Express
    re.compile(r"""req\.params\.(\w+)\b"""),                          # Express (path/query params)
]

_PYTHON_EXTENSIONS = {".py"}
_JS_EXTENSIONS = {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}

# Flask: @app.route("/x"), @bp.route('/x', methods=["POST"])
# FastAPI: @app.get("/x"), @router.post('/x')
_PYTHON_DECORATOR_RE = re.compile(
    r"""^\s*@\s*[\w.]+\.
        (?:route|get|post|put|delete|patch)
        \(\s*['"](?P<path>[^'"]+)['"]""",
    re.VERBOSE,
)
_PYTHON_METHODS_RE = re.compile(r"""methods\s*=\s*\[\s*['"](?P<method>\w+)['"]""")
_PYTHON_VERB_RE = re.compile(r"""@\s*[\w.]+\.(?P<verb>get|post|put|delete|patch)\(""")

# Express: app.get('/x', ...), router.post("/x", ...)
_JS_ROUTE_RE = re.compile(
    r"""[\w.]+\.(?P<verb>get|post|put|delete|patch|all)\(\s*['"](?P<path>[^'"]+)['"]""",
)

_MAX_LOOKUP_WINDOW = 60


@dataclass
class RouteMatch:
    method: str
    path: str


@dataclass
class BridgeTarget:
    """One dynamic check to run because a static finding flagged this exact route."""
    static_finding_id: str
    static_rule_id: str
    dynamic_rule_id: str
    asvs_controls: List[str]
    url: str
    method: str
    source_file: str
    source_line: int


def _detect_language(file_path: str) -> Optional[str]:
    suffix = Path(file_path).suffix.lower()
    if suffix in _PYTHON_EXTENSIONS:
        return "python"
    if suffix in _JS_EXTENSIONS:
        return "javascript"
    return None


def _find_python_route(lines: List[str], line_no: int) -> Optional[RouteMatch]:
    # 0-indexed list, line_no is 1-indexed and may be inside the handler body —
    # walk upward past the def line to any decorator stack directly above it.
    idx = min(line_no - 1, len(lines) - 1)
    def_idx = None
    for i in range(idx, -1, -1):
        if re.match(r"^\s*(?:async\s+)?def\s+\w+\s*\(", lines[i]):
            def_idx = i
            break
    if def_idx is None:
        return None

    i = def_idx - 1
    while i >= 0 and (lines[i].strip().startswith("@") or not lines[i].strip()):
        match = _PYTHON_DECORATOR_RE.match(lines[i])
        if match:
            verb_match = _PYTHON_VERB_RE.search(lines[i])
            methods_match = _PYTHON_METHODS_RE.search(lines[i])
            if methods_match:
                method = methods_match.group("method").upper()
            elif verb_match and verb_match.group("verb") != "route":
                method = verb_match.group("verb").upper()
            else:
                method = "GET"
            return RouteMatch(method=method, path=match.group("path"))
        i -= 1
    return None


def _find_js_route(lines: List[str], line_no: int) -> Optional[RouteMatch]:
    start = min(line_no - 1, len(lines) - 1)
    lower_bound = max(0, start - _MAX_LOOKUP_WINDOW)
    for i in range(start, lower_bound - 1, -1):
        match = _JS_ROUTE_RE.search(lines[i])
        if match:
            verb = match.group("verb")
            method = "GET" if verb == "all" else verb.upper()
            return RouteMatch(method=method, path=match.group("path"))
    return None


def find_enclosing_route(source_lines: List[str], line_no: int, language: Optional[str]) -> Optional[RouteMatch]:
    if language == "python":
        return _find_python_route(source_lines, line_no)
    if language == "javascript":
        return _find_js_route(source_lines, line_no)
    return None


def _extract_param_name(source_label: str) -> Optional[str]:
    for pattern in _PARAM_NAME_PATTERNS:
        match = pattern.search(source_label)
        if match:
            return match.group(1)
    return None


def build_dynamic_targets(
    vulnerabilities: List[dict],
    repo_root: Path,
    base_url: str,
) -> List[BridgeTarget]:
    """vulnerabilities: formatted dicts as produced by
    SemanticPipeline._format_vulnerability (needs ["type" or rule_id-bearing
    field], "asvs_controls", "location", and "evidence.source" for the two
    param-dependent rules). Only findings whose primary rule_id is in
    STATIC_TO_DYNAMIC_RULE_MAP and whose route (and, where needed, param
    name) resolves are returned.
    """
    targets: List[BridgeTarget] = []
    for vuln in vulnerabilities:
        rule_id = vuln.get("rule_id") or vuln.get("type")
        if rule_id not in STATIC_TO_DYNAMIC_RULE_MAP:
            continue

        location = vuln.get("location") or {}
        file_path = location.get("file")
        line_no = location.get("start_line")
        if not file_path or not line_no:
            continue

        language = _detect_language(file_path)
        if language is None:
            continue

        full_path = repo_root / file_path
        try:
            source_lines = full_path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            logger.debug(f"Bridge could not read {full_path} to resolve a route")
            continue

        route = find_enclosing_route(source_lines, line_no, language)
        if route is None:
            continue

        dynamic_rule_id = STATIC_TO_DYNAMIC_RULE_MAP[rule_id]
        url = urljoin(base_url.rstrip("/") + "/", route.path.lstrip("/"))

        if dynamic_rule_id in _PARAM_DEPENDENT_DYNAMIC_RULES:
            source_label = (vuln.get("evidence") or {}).get("source", "")
            param_name = _extract_param_name(source_label)
            if param_name is None:
                # No fixed candidate-param list for these two (see module
                # docstring) — a bare route URL would only ever come back
                # NOT_TESTED, so skip rather than produce a useless target.
                continue
            url = f"{url}?{urlencode({param_name: '1'})}"

        targets.append(BridgeTarget(
            static_finding_id=vuln.get("id", ""),
            static_rule_id=rule_id,
            dynamic_rule_id=dynamic_rule_id,
            asvs_controls=vuln.get("asvs_controls", []),
            url=url,
            method=route.method,
            source_file=file_path,
            source_line=line_no,
        ))
    return targets
