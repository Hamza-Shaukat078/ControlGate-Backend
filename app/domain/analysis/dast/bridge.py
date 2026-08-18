"""Static -> dynamic bridge (Phase 2 of the static+dynamic plan), plus
whole-repo automatic route discovery (discover_routes_from_source, below).

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

from app.domain.analysis.dast.openapi_discovery import DiscoveredEndpoint

logger = logging.getLogger(__name__)

# Only rules with a real live-check counterpart today (queries/dynamic_queries.json
# for the run_payload_checks-dispatched ones; a few fixed-rule_id checks that
# need something more than a session+rule — a CollaboratorServer, a live
# browser — are special-cased in scan_service.py's bridge loop instead, noted
# per-entry below). Extend this alongside new dynamic checks as they're added
# (Phase 3) — as of Phase 2.3 this covers every dynamic check that already
# existed, not just the original six; STORED_XSS_PROBE is the one deliberate
# exception (it walks a crawler-discovered DiscoveredForm, not a bare
# URL+method, so it doesn't fit BridgeTarget's shape without its own
# dispatch rework — left for whenever that's worth doing on its own).
STATIC_TO_DYNAMIC_RULE_MAP: Dict[str, str] = {
    "UNVALIDATED_REDIRECT": "OPEN_REDIRECT_LIVE",
    "PATH_TRAVERSAL": "DOUBLE_DECODE_BYPASS",
    "HTTP_REQUEST_SMUGGLING": "REQUEST_SMUGGLING",
    "XSS": "REFLECTED_XSS_LIVE",
    "SQL_INJECTION": "SQL_INJECTION_LIVE",
    "MISSING_CSRF_PROTECTION": "CSRF_TOKEN_NOT_VALIDATED",
    "BROKEN_ACCESS_CONTROL": "UNAUTHENTICATED_ACCESS_ALLOWED",
    # SSRF_LIVE isn't a checks.py payload check (it needs a CollaboratorServer,
    # not just a session+rule) — scan_service.py's bridge loop special-cases
    # this dynamic_rule_id rather than routing it through run_payload_checks
    # like the others above.
    "SSRF": "SSRF_LIVE",
    # DOM_XSS_LIVE isn't a checks.py payload check either (it needs a live
    # Playwright BrowserContext, not just a session+rule) — also
    # special-cased in scan_service.py's bridge loop, gated on
    # dynamic_use_headless_browser the same way the non-bridge DOM-XSS
    # sweep already is.
    "UNSAFE_DOM_RENDERING": "DOM_XSS_LIVE",
    # Phase 3 — new dynamic checks filling out the catalog, all dispatched
    # through the ordinary run_payload_checks path like the checks above.
    "COMMAND_INJECTION": "COMMAND_INJECTION_LIVE",
    "CODE_INJECTION": "SSTI_LIVE",
    "XXE_UNSAFE_XML_PARSER": "XXE_LIVE",
    "NOSQL_INJECTION": "NOSQL_INJECTION_LIVE",
    "CORS_MISCONFIGURATION": "CORS_MISCONFIG_LIVE",
    # JWT_WEAKNESS_LIVE forges variants of the scan's own bearer JWT rather
    # than testing anything about this specific route (see jwt_probe.py) —
    # also special-cased in scan_service.py's bridge loop, gated on the
    # scan actually using auth_mode=bearer, same as the non-bridge sweep.
    # No standalone "JWT_WEAKNESS" static rule exists yet (that would be a
    # new semantic_engine/queries.json AST rule, a different subsystem
    # entirely) — JWT_NONE_ALGORITHM is the closest existing static rule
    # this dynamic check can actually confirm/deny.
    "JWT_NONE_ALGORITHM": "JWT_WEAKNESS_LIVE",
}

# Dynamic rule_ids that only test query params a URL already carries — see
# module docstring. A bridge target for one of these needs a param name.
_PARAM_DEPENDENT_DYNAMIC_RULES = {
    "REFLECTED_XSS_LIVE", "SQL_INJECTION_LIVE", "SSRF_LIVE",
    "COMMAND_INJECTION_LIVE", "SSTI_LIVE", "NOSQL_INJECTION_LIVE",
}

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
# The (?P<obj>...) group (the "bp" in "@bp.route(...)") is unused by
# find_enclosing_route()'s single-finding lookup but is what
# discover_routes_from_source() needs to resolve a Flask Blueprint's
# url_prefix — see _discover_blueprint_prefixes() below.
_PYTHON_DECORATOR_RE = re.compile(
    r"""^\s*@\s*(?P<obj>[\w.]+)\.
        (?:route|get|post|put|delete|patch)
        \(\s*['"](?P<path>[^'"]+)['"]""",
    re.VERBOSE,
)
_PYTHON_METHODS_RE = re.compile(r"""methods\s*=\s*\[\s*['"](?P<method>\w+)['"]""")
_PYTHON_VERB_RE = re.compile(r"""@\s*[\w.]+\.(?P<verb>get|post|put|delete|patch)\(""")

# Flask Blueprint registration: app.register_blueprint(users_bp, url_prefix="/api/users")
_BLUEPRINT_REGISTER_RE = re.compile(
    r"""register_blueprint\(\s*(?P<var>\w+)\s*,\s*url_prefix\s*=\s*['"](?P<prefix>[^'"]*)['"]""",
)

# Express: app.get('/x', ...), router.post("/x", ...), apiRouter.get(...).
# Receiver is deliberately restricted to `app` or an identifier ending in
# "router" (any case/prefix: router, apiRouter, orderRouter, ...) rather
# than the old bare `[\w.]+` — that matched ANY `<identifier>.get("string")`
# call in the file, which in practice fired on totally unrelated JS/TS
# idioms that happen to share the verb name: params.get("id"),
# formData.get("file"), req.headers.get("x-forwarded-for"),
# url.searchParams.get("category"). Each of those got misread as an Express
# route registration for path "id"/"file"/"x-forwarded-for"/"category" —
# pure noise fed into the dynamic sweep. Every real Express route/router
# call site in this codebase's own fixtures uses `app` or `router` as the
# receiver, so this loses no real coverage.
_JS_ROUTE_RE = re.compile(
    r"""\b(?:app|\w*[Rr]outer)\.(?P<verb>get|post|put|delete|patch|all)\(\s*['"](?P<path>[^'"]+)['"]""",
)

# Express mount registration: app.use('/orders', orderRoutes) — the JS
# equivalent of Flask's register_blueprint(var, url_prefix=...) above, just
# positional instead of a keyword arg. Deliberately not matching a bare
# `app.use(middlewareFn)` (no path string) — that's not a router mount.
_JS_APP_USE_RE = re.compile(
    r"""\.use\(\s*['"](?P<prefix>/[^'"]*)['"]\s*,\s*(?P<var>[\w$]+)\s*\)""",
)
# ES module: import orderRoutes from './routes/order.routes.js'
_JS_IMPORT_RE = re.compile(
    r"""^\s*import\s+(?P<var>[\w$]+)\s+from\s+['"](?P<path>\.[^'"]+)['"]""",
    re.MULTILINE,
)
# CommonJS: const orderRoutes = require('./routes/order.routes')
_JS_REQUIRE_RE = re.compile(
    r"""(?:const|let|var)\s+(?P<var>[\w$]+)\s*=\s*require\(\s*['"](?P<path>\.[^'"]+)['"]\s*\)""",
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


_PYTHON_DEF_RE = re.compile(r"^\s*(?:async\s+)?def\s+(?P<name>\w+)\s*\(")

# Bound on how many call sites of a helper function get route-resolution
# attempted — same "best-effort, bound the cost" posture as
# MAX_ADDITIONAL_CRAWL_URLS/MAX_OPENAPI_URLS in scan_service.py. A helper
# called from 200 places in a huge repo isn't going to yield a single
# unambiguous route anyway (see the ambiguity check below), so there's no
# value in walking all 200 — just cost.
_MAX_CALLER_SITES = 25


def _find_enclosing_function_name(lines: List[str], line_no: int) -> Optional[str]:
    """Nearest `def name(...)` at or above line_no, regardless of whether
    it's route-decorated — the cross-file fallback below needs the plain
    function name to search the rest of the repo for its call sites."""
    idx = min(line_no - 1, len(lines) - 1)
    for i in range(idx, -1, -1):
        match = _PYTHON_DEF_RE.match(lines[i])
        if match:
            return match.group("name")
    return None


def _find_callers_of_function(candidate_files: List[Path], func_name: str) -> List[tuple]:
    """Regex search across the repo for call sites of func_name(...),
    skipping its own def line. Same weight class as the rest of this
    module — a plain text match, not an import-aware call-graph walk, so a
    same-named function in an unrelated module could produce a spurious
    "call site". That's fine: build_dynamic_targets only trusts the result
    when every resolved caller route agrees, so a spurious match either
    resolves to nothing (skipped) or, in the rare worst case, adds a second
    disagreeing route and makes the whole lookup bail out as ambiguous —
    never a wrong bridge target."""
    call_re = re.compile(r"\b" + re.escape(func_name) + r"\s*\(")
    def_marker = f"def {func_name}("
    results: List[tuple] = []
    for file_path in candidate_files:
        if _detect_language(str(file_path)) != "python":
            continue
        try:
            lines = file_path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        for i, line in enumerate(lines):
            if def_marker in line:
                continue
            if call_re.search(line):
                results.append((file_path, i + 1))
                if len(results) >= _MAX_CALLER_SITES:
                    return results
    return results


def _detect_language(file_path: str) -> Optional[str]:
    suffix = Path(file_path).suffix.lower()
    if suffix in _PYTHON_EXTENSIONS:
        return "python"
    if suffix in _JS_EXTENSIONS:
        return "javascript"
    return None


def _find_python_route(
    lines: List[str], line_no: int, blueprint_prefixes: Optional[Dict[str, str]] = None,
) -> Optional[RouteMatch]:
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

    blueprint_prefixes = blueprint_prefixes or {}
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
            # Same blueprint url_prefix join as _routes_in_python_source —
            # "@transactions_bp.route('/transfer')" only actually resolves
            # to /transfer at the app root if transactions_bp was never
            # registered with a prefix. In practice (this repo included)
            # it almost always was, in a different file
            # (app.register_blueprint(transactions_bp, url_prefix=
            # "/api/transactions")) — skipping this join is what made
            # every bridge target from a blueprint-routed file 404 before
            # this fix: a bare "/transfer" instead of the real
            # "/api/transactions/transfer".
            prefix = blueprint_prefixes.get(match.group("obj"), "")
            path = (
                prefix.rstrip("/") + "/" + match.group("path").lstrip("/") if prefix
                else match.group("path")
            )
            return RouteMatch(method=method, path=path)
        i -= 1
    return None


def _find_js_route(lines: List[str], line_no: int, prefix: str = "") -> Optional[RouteMatch]:
    start = min(line_no - 1, len(lines) - 1)
    lower_bound = max(0, start - _MAX_LOOKUP_WINDOW)
    for i in range(start, lower_bound - 1, -1):
        match = _JS_ROUTE_RE.search(lines[i])
        if match:
            verb = match.group("verb")
            method = "GET" if verb == "all" else verb.upper()
            path = match.group("path")
            # Same join _find_python_route does for a Blueprint's
            # url_prefix — a modular Express router's routes only actually
            # resolve at prefix + path once mounted (app.use('/orders',
            # orderRoutes)), almost always in a different file (server.js)
            # than the route itself — see _discover_js_mount_prefixes.
            if prefix:
                path = prefix.rstrip("/") + "/" + path.lstrip("/")
            return RouteMatch(method=method, path=path)
    return None


def find_enclosing_route(
    source_lines: List[str], line_no: int, language: Optional[str],
    blueprint_prefixes: Optional[Dict[str, str]] = None,
    js_mount_prefixes: Optional[Dict[str, str]] = None,
    file_path: Optional[Path] = None,
) -> Optional[RouteMatch]:
    if language == "python":
        return _find_python_route(source_lines, line_no, blueprint_prefixes)
    if language == "javascript":
        prefix = ""
        if js_mount_prefixes and file_path is not None:
            prefix = js_mount_prefixes.get(str(file_path.resolve()), "")
        return _find_js_route(source_lines, line_no, prefix)
    return None


def _extract_param_name(source_label: str) -> Optional[str]:
    for pattern in _PARAM_NAME_PATTERNS:
        match = pattern.search(source_label)
        if match:
            return match.group(1)
    return None


# Bare identifier (e.g. "query_str", "q", "sql") — the shape the classifier's
# abbreviated source label actually takes when it *does* trace back to a
# request.args.get(...)-style read a few lines away (see
# _extract_param_name_from_lines' docstring). Anything else — a call
# expression like "some_custom_input_source()", a dotted attribute chain, an
# f-string — isn't a variable name at all, so nearby-line search has nothing
# principled to match it against; running it anyway just grabs whatever
# request.args.get(...) happens to sit in the window, unrelated to what the
# classifier actually flagged. Gating on this shape keeps the fallback's
# intended case working while restoring the "skip rather than guess wrong"
# rule for source labels that were never a query-param variable to begin
# with.
_BARE_IDENTIFIER_RE = re.compile(r"^[A-Za-z_]\w*$")


# How many lines above/below the anchor line to search for a real
# request.args.get(...)-shaped expression when the taint label alone
# doesn't carry one — wide enough to reach a route function's first few
# statements (where the value is normally pulled off the request) from
# either the sink itself or a cross-file call site, narrow enough to stay
# a same-function-body search rather than drifting into unrelated code.
_PARAM_SEARCH_WINDOW = 15


def _extract_param_name_from_lines(lines: List[str], line_no: int, window: int = _PARAM_SEARCH_WINDOW) -> Optional[str]:
    """Same patterns as _extract_param_name, applied to actual source lines
    around line_no instead of the classifier's (often abbreviated) taint
    label. Searches upward first — request.args.get(...) almost always
    precedes its use, whether that's the sink itself or a route function's
    call into a helper a few lines later."""
    start = min(line_no - 1, len(lines) - 1)
    lower = max(0, start - window)
    upper = min(len(lines), start + window + 1)
    for i in list(range(start, lower - 1, -1)) + list(range(start + 1, upper)):
        name = _extract_param_name(lines[i])
        if name:
            return name
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
    # Same whole-repo prefix pass discover_routes_from_source uses below —
    # a blueprint's real path depends on where it was registered
    # (app.register_blueprint(..., url_prefix=...)), almost always a
    # different file than the route decorator itself. Computed once up
    # front rather than per-finding: it's a cheap regex scan, but there's
    # no reason to repeat it for every vulnerability in the loop.
    try:
        candidate_files = [p for p in repo_root.rglob("*") if p.is_file()]
    except OSError:
        candidate_files = []
    blueprint_prefixes = _discover_blueprint_prefixes(candidate_files)
    js_mount_prefixes = _discover_js_mount_prefixes(candidate_files)

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

        # Tracks the caller location that won cross-file route resolution
        # (None for the ordinary same-file case) — the param-name fallback
        # below needs it: the taint source's own label ("query_str", "sql")
        # is just the parameter name *inside* the helper, not the original
        # request.args.get('q')-shaped expression, which usually only
        # appears at the call site in the route function itself.
        cross_file_caller: Optional[tuple] = None

        route = find_enclosing_route(
            source_lines, line_no, language, blueprint_prefixes,
            js_mount_prefixes=js_mount_prefixes, file_path=full_path,
        )
        if route is None and language == "python":
            # Cross-file fallback: the flagged line has no route decorator
            # directly above it because it's inside a plain helper function
            # (e.g. database.py's find_user_by_username, called from a
            # route in api/users.py) — same-file resolution alone missed
            # every finding of this shape before this fallback existed,
            # which for this exact repo meant *no* SQL_INJECTION finding
            # could ever bridge (every sink lives in database.py, not in
            # the route file). One hop: find the enclosing function's
            # name, search the whole repo for its call sites, and try
            # route resolution at each of *those* locations instead. Only
            # trusted when every call site that resolves agrees on the
            # same (method, path) — same "skip rather than guess wrong"
            # principle as the rest of this module; a helper called from
            # several distinct routes has no single correct bridge target.
            func_name = _find_enclosing_function_name(source_lines, line_no)
            if func_name:
                resolved: Dict[tuple, tuple] = {}
                for caller_file, caller_line in _find_callers_of_function(candidate_files, func_name):
                    try:
                        caller_lines = caller_file.read_text(encoding="utf-8", errors="replace").splitlines()
                    except OSError:
                        continue
                    caller_route = find_enclosing_route(caller_lines, caller_line, "python", blueprint_prefixes)
                    if caller_route:
                        resolved[(caller_route.method, caller_route.path)] = (caller_route, caller_lines, caller_line)
                if len(resolved) == 1:
                    route, caller_lines, caller_line = next(iter(resolved.values()))
                    cross_file_caller = (caller_lines, caller_line)
        if route is None:
            continue

        dynamic_rule_id = STATIC_TO_DYNAMIC_RULE_MAP[rule_id]
        url = urljoin(base_url.rstrip("/") + "/", route.path.lstrip("/"))

        if dynamic_rule_id in _PARAM_DEPENDENT_DYNAMIC_RULES:
            source_label = (vuln.get("evidence") or {}).get("source", "")
            # The classifier's source label is often just the tainted
            # variable's bare name at the sink ("query_str", "sql") rather
            # than the original request.args.get('q')-shaped expression —
            # _extract_param_name only matches the latter. Three attempts,
            # cheapest/most-direct first: the label itself; nearby lines in
            # the same file (the expression may be a few lines above the
            # sink even when the label was abbreviated); nearby lines
            # around the route call site in a *different* file, when cross-
            # file resolution is how this target was found at all — that's
            # exactly where request.args.get(...) actually lives for a
            # sink like search_users(query_str) two files away from its
            # own HTTP entry point.
            param_name = _extract_param_name(source_label)
            if param_name is None and _BARE_IDENTIFIER_RE.match(source_label.strip()):
                param_name = _extract_param_name_from_lines(source_lines, line_no) or (
                    cross_file_caller and _extract_param_name_from_lines(*cross_file_caller)
                )
            if param_name is None:
                # No fixed candidate-param list for these two (see module
                # docstring) — a bare route URL would only ever come back
                # NOT_TESTED, so skip rather than produce a useless target.
                continue
            url = f"{url}?{urlencode({param_name: '1'})}"
        elif dynamic_rule_id == "DOUBLE_DECODE_BYPASS":
            # Unlike the hard-required rules above, a param here is a
            # bonus, not a prerequisite: _check_double_decode_bypass tests
            # a query-param *value* when the URL carries one (the common
            # /download?file=x shape) but still falls back to its original
            # path-suffix strategy when it doesn't — so a target with no
            # resolvable param is still worth sending, just via that
            # fallback, unlike the checks above where a paramless target
            # would only ever come back NOT_TESTED.
            source_label = (vuln.get("evidence") or {}).get("source", "")
            param_name = _extract_param_name(source_label)
            if param_name is None and _BARE_IDENTIFIER_RE.match(source_label.strip()):
                param_name = _extract_param_name_from_lines(source_lines, line_no) or (
                    cross_file_caller and _extract_param_name_from_lines(*cross_file_caller)
                )
            if param_name:
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


# ── Whole-repo automatic route discovery ────────────────────────────────────
#
# build_dynamic_targets() above only ever resolves a route when it's anchored
# to a specific flagged finding's line. That leaves a real gap: an API-only
# target (no crawlable HTML, no published OpenAPI spec — vuln-bank-app is
# exactly this shape) gives the dynamic engine no way to discover *any* of
# its real endpoints, flagged or not — every payload check ends up testing
# only target_url itself. But a hybrid scan has already cloned the repo for
# static analysis, so the actual route definitions are sitting right there.
# discover_routes_from_source() reuses the identical decorator/registration
# regexes above, just run across every source file instead of anchored to
# one line — turning "the source code defines these routes" directly into
# "these are real testable URLs", no spec and no crawl required.

_PATH_PARAM_PLACEHOLDER = "1"
# Flask: <id>, <int:id>, <string:name>
_FLASK_PATH_PARAM_RE = re.compile(r"<(?:[a-zA-Z_]+:)?([a-zA-Z_]\w*)>")
# FastAPI: {id}
_BRACE_PATH_PARAM_RE = re.compile(r"\{([a-zA-Z_]\w*)\}")
# Express: :id
_EXPRESS_PATH_PARAM_RE = re.compile(r":([a-zA-Z_]\w*)")


def _substitute_path_params(path: str) -> str:
    """Same placeholder strategy as openapi_discovery.py's path-param
    resolution — "1" is a syntactically valid path segment for virtually
    every REST route, even if it 404s functionally on this specific app."""
    path = _FLASK_PATH_PARAM_RE.sub(_PATH_PARAM_PLACEHOLDER, path)
    path = _BRACE_PATH_PARAM_RE.sub(_PATH_PARAM_PLACEHOLDER, path)
    path = _EXPRESS_PATH_PARAM_RE.sub(_PATH_PARAM_PLACEHOLDER, path)
    return path


def _routes_in_python_source(lines: List[str], blueprint_prefixes: Optional[Dict[str, str]] = None) -> List[RouteMatch]:
    blueprint_prefixes = blueprint_prefixes or {}
    routes = []
    for line in lines:
        match = _PYTHON_DECORATOR_RE.match(line)
        if not match:
            continue
        verb_match = _PYTHON_VERB_RE.search(line)
        methods_match = _PYTHON_METHODS_RE.search(line)
        if methods_match:
            method = methods_match.group("method").upper()
        elif verb_match and verb_match.group("verb") != "route":
            method = verb_match.group("verb").upper()
        else:
            method = "GET"
        # "users_bp" in "@users_bp.route(...)" — if that name was registered
        # with a url_prefix elsewhere in the repo (app.register_blueprint),
        # the route only actually exists at prefix + path; "@app.route(...)"
        # or a blueprint with no registered prefix leaves the path as-is.
        prefix = blueprint_prefixes.get(match.group("obj"), "")
        path = prefix.rstrip("/") + "/" + match.group("path").lstrip("/") if prefix else match.group("path")
        routes.append(RouteMatch(method=method, path=path))
    return routes


def _discover_blueprint_prefixes(candidate_files: List[Path]) -> Dict[str, str]:
    """First pass over the repo: {blueprint_variable_name: url_prefix} from
    every app.register_blueprint(var, url_prefix="...") call, wherever in
    the repo it happens to live (almost always a different file than the
    one that defines the routes themselves — hence the separate pass over
    the whole repo rather than a single-file lookup)."""
    prefixes: Dict[str, str] = {}
    for file_path in candidate_files:
        if _detect_language(str(file_path)) != "python":
            continue
        try:
            text = file_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for match in _BLUEPRINT_REGISTER_RE.finditer(text):
            prefixes[match.group("var")] = match.group("prefix")
    return prefixes


def _routes_in_js_source(lines: List[str], prefix: str = "") -> List[RouteMatch]:
    routes = []
    for line in lines:
        match = _JS_ROUTE_RE.search(line)
        if not match:
            continue
        verb = match.group("verb")
        method = "GET" if verb == "all" else verb.upper()
        path = match.group("path")
        if prefix:
            path = prefix.rstrip("/") + "/" + path.lstrip("/")
        routes.append(RouteMatch(method=method, path=path))
    return routes


# Tried in order against the resolved base path: as-is (the import already
# named a real file), each common extension appended, then each as a
# directory's index file (import './routes' resolving to routes/index.js).
_JS_EXTENSION_SUFFIXES = (".js", ".ts", ".mjs", ".cjs")
_JS_INDEX_FILENAMES = ("index.js", "index.ts")


def _resolve_js_relative_import(importing_file: Path, relative_path: str) -> Optional[Path]:
    base = (importing_file.parent / relative_path).resolve()
    if base.is_file():
        return base
    for suffix in _JS_EXTENSION_SUFFIXES:
        candidate = base.with_name(base.name + suffix)
        if candidate.is_file():
            return candidate
    for index_name in _JS_INDEX_FILENAMES:
        candidate = base / index_name
        if candidate.is_file():
            return candidate
    return None


def _discover_js_mount_prefixes(candidate_files: List[Path]) -> Dict[str, str]:
    """First pass over the repo: {resolved_route_file_path: url_prefix} from
    every app.use('/prefix', routerVar) call, resolved back to whichever
    file routerVar's import/require points at. Keyed by file path rather
    than variable name (unlike _discover_blueprint_prefixes) — Express
    router files conventionally all name their export "router", so a
    variable-name key would collide across every route file in a multi-
    router app; the mount call and the import/require that resolves its
    variable are almost always in the same file (server.js), so this stays
    a single-file lookup per mount, no cross-file call-site search needed."""
    prefixes: Dict[str, str] = {}
    for file_path in candidate_files:
        if _detect_language(str(file_path)) != "javascript":
            continue
        try:
            text = file_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue

        imports: Dict[str, str] = {}
        for match in _JS_IMPORT_RE.finditer(text):
            imports[match.group("var")] = match.group("path")
        for match in _JS_REQUIRE_RE.finditer(text):
            imports[match.group("var")] = match.group("path")
        if not imports:
            continue

        for match in _JS_APP_USE_RE.finditer(text):
            var = match.group("var")
            relative_path = imports.get(var)
            if not relative_path:
                continue
            resolved = _resolve_js_relative_import(file_path, relative_path)
            if resolved is not None:
                prefixes[str(resolved.resolve())] = match.group("prefix")
    return prefixes


# Next.js App Router: the URL is derived from folder structure under any
# directory literally named "app" (src/app/ or a top-level app/ — the
# framework's own convention, default/recommended routing style for every
# Next.js 13+ project), not from a route decorator/registration call
# anywhere in the file. Neither _routes_in_python_source nor
# _routes_in_js_source can see these at all — there's no call site to
# regex-match — so an App Router target previously contributed zero
# source-discovered endpoints. That's a real coverage gap, not just noise:
# it includes anything the crawler has no public link to reach (e.g. an
# admin area intentionally not linked from the public nav) — a hybrid scan
# would run its live payload checks against the public pages only and
# report a clean dynamic sweep despite never having touched the one area
# that actually needs access-control testing.
_NEXTJS_PAGE_FILENAMES = {"page.tsx", "page.jsx", "page.ts", "page.js"}
_NEXTJS_ROUTE_HANDLER_FILENAMES = {"route.ts", "route.js"}
_NEXTJS_SKIP_DIR_NAMES = {"node_modules", ".next", ".git"}

# export async function GET(req) {...}  /  export const POST = async (req) => {...}
_NEXTJS_HANDLER_VERB_RE = re.compile(
    r"""^\s*export\s+(?:async\s+)?(?:function\s+(?P<fn_verb>GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\b"""
    r"""|const\s+(?P<const_verb>GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s*[:=])""",
    re.MULTILINE,
)


def _nextjs_url_segments(dir_parts: tuple) -> List[str]:
    """Converts the folder-path segments between an "app" root and a
    page.tsx/route.ts file into URL path segments, per the App Router's own
    naming conventions: (group) route groups and @slot parallel routes are
    organizational only and never appear in the URL; [param], [...param],
    and [[...param]] all collapse to the same "1" placeholder
    _substitute_path_params already uses for Flask/Express/FastAPI."""
    segments: List[str] = []
    for part in dir_parts:
        if part.startswith("(") and part.endswith(")"):
            continue
        if part.startswith("@"):
            continue
        if part.startswith("[") and part.endswith("]"):
            segments.append(_PATH_PARAM_PLACEHOLDER)
            continue
        segments.append(part)
    return segments


def _routes_in_nextjs_app_router(repo_root: Path) -> List[RouteMatch]:
    routes: List[RouteMatch] = []
    try:
        app_dirs = [
            p for p in repo_root.rglob("app")
            if p.is_dir() and not any(part in _NEXTJS_SKIP_DIR_NAMES for part in p.parts)
        ]
    except OSError:
        return routes

    route_filenames = _NEXTJS_PAGE_FILENAMES | _NEXTJS_ROUTE_HANDLER_FILENAMES
    for app_dir in app_dirs:
        for filename in route_filenames:
            for file_path in app_dir.rglob(filename):
                if any(part in _NEXTJS_SKIP_DIR_NAMES for part in file_path.parts):
                    continue
                rel_dir_parts = file_path.relative_to(app_dir).parent.parts
                segments = _nextjs_url_segments(rel_dir_parts)
                path = "/" + "/".join(segments) if segments else "/"

                if filename in _NEXTJS_PAGE_FILENAMES:
                    routes.append(RouteMatch(method="GET", path=path))
                    continue

                try:
                    text = file_path.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    continue
                verbs = {
                    m.group("fn_verb") or m.group("const_verb")
                    for m in _NEXTJS_HANDLER_VERB_RE.finditer(text)
                }
                for verb in verbs:
                    routes.append(RouteMatch(method=verb, path=path))
    return routes


def discover_routes_from_source(
    repo_root: Path, base_url: str, max_routes: Optional[int] = None,
) -> List[DiscoveredEndpoint]:
    """Walks every Python/JS/TS file under repo_root looking for a route
    decorator or registration call on each line, resolves path params to a
    placeholder, and turns each one into a concrete URL against base_url.
    Also separately walks any Next.js App Router "app" directory tree
    (page.tsx/route.ts file-based routing — see _routes_in_nextjs_app_router)
    since that has no call site for the decorator/registration regexes to
    match at all.

    Best-effort/regex-based, same weight class and same "skip rather than
    guess" posture as the rest of this module and openapi_discovery.py — a
    line that doesn't cleanly match one of the known route shapes is simply
    not a route as far as this is concerned, never a wrong guess.

    max_routes: None (the default) means unlimited — deliberately, unlike
    the crawler/OpenAPI-discovery caps: those bound *live requests already
    in flight against a real target*, where an unbounded count is a real
    self-DoS risk. This function only reads files already on local disk —
    no network cost to walking every route the repo defines. The caller
    (scan_service.py) is what decides how many of the returned endpoints
    actually get swept with live payload checks; pass an int here only if
    the discovery pass itself needs bounding on a huge monorepo.
    """
    endpoints: List[DiscoveredEndpoint] = []
    try:
        # A fresh git clone (the normal case — scan_service.py clones into a
        # throwaway temp dir per scan) never has node_modules/.next checked
        # out, so this filter is a no-op there. It matters when repo_root is
        # a real working checkout instead (vendored deps committed, or a
        # local-directory scan target): node_modules alone routinely holds
        # tens of thousands of files, none of which are ever a real app
        # route, and reading every one of them here turns a sub-second walk
        # into a multi-minute one for zero benefit.
        candidate_files = [
            p for p in repo_root.rglob("*")
            if p.is_file() and not any(part in _NEXTJS_SKIP_DIR_NAMES for part in p.parts)
        ]
    except OSError as exc:
        logger.debug(f"discover_routes_from_source could not walk {repo_root}: {exc}")
        return endpoints

    # Pass 1 (whole repo, cheap — just a regex scan): resolve Flask
    # Blueprint url_prefixes and Express router mount prefixes before
    # extracting any routes, since a route's real path depends on where it
    # was registered/mounted — almost always a different file (app.py /
    # server.js) than the route decorator/handler itself.
    blueprint_prefixes = _discover_blueprint_prefixes(candidate_files)
    js_mount_prefixes = _discover_js_mount_prefixes(candidate_files)

    for file_path in candidate_files:
        if max_routes is not None and len(endpoints) >= max_routes:
            break
        language = _detect_language(str(file_path))
        if language is None:
            continue
        try:
            lines = file_path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue

        routes = (
            _routes_in_python_source(lines, blueprint_prefixes) if language == "python"
            else _routes_in_js_source(lines, js_mount_prefixes.get(str(file_path.resolve()), ""))
        )
        for route in routes:
            path = _substitute_path_params(route.path)
            url = urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))
            endpoints.append(DiscoveredEndpoint(method=route.method, url=url))
            if max_routes is not None and len(endpoints) >= max_routes:
                break

    # Separate pass: Next.js App Router has no decorator/registration call
    # site for the loop above to match, so it's discovered by walking the
    # "app" directory's own file-based routing structure instead.
    seen = {(e.method, e.url) for e in endpoints}
    for route in _routes_in_nextjs_app_router(repo_root):
        if max_routes is not None and len(endpoints) >= max_routes:
            break
        url = urljoin(base_url.rstrip("/") + "/", route.path.lstrip("/"))
        if (route.method, url) in seen:
            continue
        seen.add((route.method, url))
        endpoints.append(DiscoveredEndpoint(method=route.method, url=url))

    return endpoints
