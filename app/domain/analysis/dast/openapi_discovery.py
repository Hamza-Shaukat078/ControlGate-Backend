"""Track C3 — OpenAPI/Swagger spec-driven target discovery.

The regex crawler (crawler.py) only ever follows <a href>/<form> tags in
server-rendered HTML. An API-first target — a backend with no HTML pages at
all, just JSON endpoints — is almost invisible to it: the scan only ever
tests target_url itself and whatever links happen to be reachable from it.

This module accepts an OpenAPI/Swagger spec (fetched from a URL through the
existing DastSession, or supplied directly as raw JSON/YAML text) and turns
every operation it describes into a concrete testable URL. Those URLs feed
into the exact same check_urls list the crawler already populates
(scan_service._run_dynamic_checks) — no new check-execution path, just a
second source of URLs for the checks that already exist.

Scope, deliberately limited: request bodies are NOT resolved into test
parameters. Every existing live check (REFLECTED_XSS_LIVE, SQL_INJECTION_LIVE,
SSRF_LIVE, OPEN_REDIRECT_LIVE, ...) only ever inspects *query* parameters on
a URL — there is no JSON-body injection path anywhere downstream yet. A spec
describing only POST endpoints whose inputs live entirely in the request
body will still be discovered (its URL lands in check_urls) but won't be
meaningfully tested by anything downstream until that capability exists.
This is a documented limitation of this pass, not an oversight.
"""
import json
import logging
import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit

import yaml

from app.domain.analysis.dast.session import DastSession

logger = logging.getLogger(__name__)

# Substituted into an unresolved path param ({id}, {userId}, ...) when the
# spec's own parameter definition doesn't supply a better value (example,
# default, or enum) — "1" is accepted as a syntactically valid path segment
# by virtually every REST API (numeric IDs, slugs, UUID-shaped routes all
# tolerate a plain scalar there even if it 404s functionally).
PATH_PARAM_PLACEHOLDER = "1"

_HTTP_METHODS = {"get", "post", "put", "patch", "delete", "head", "options"}
_PATH_PARAM_PATTERN = re.compile(r"\{([^{}]+)\}")

# Schema types that structurally can't be represented by a single scalar
# placeholder dropped into a path segment — an operation whose required path
# param resolves to one of these, with no example/default/enum to fall back
# on, is skipped rather than guessed at.
_UNRESOLVABLE_SCALAR_TYPES = {"array", "object"}


@dataclass
class DiscoveredEndpoint:
    method: str
    url: str


async def fetch_openapi_spec(session: DastSession, url: str) -> Dict[str, Any]:
    """GETs `url` through the caller's existing DastSession, so a spec fetch
    goes through the exact same SSRF/public-host guard as every other
    request this engine makes (DastSession.request validates on every call,
    not just at session construction) — a spec URL is just as
    attacker-steerable as any other user-supplied URL and gets no special
    trust.

    Parses the response body as JSON first, falling back to YAML on
    failure. A .yaml/.yml URL extension isn't a reliable enough signal to
    pick a parser up front — plenty of spec hosts serve YAML from an
    extensionless or even .json-suffixed path — and yaml.safe_load parses
    valid JSON without complaint anyway, so trying JSON first and falling
    back costs nothing and covers both cases correctly.
    """
    resp = await session.request("GET", url)
    resp.raise_for_status()
    return parse_spec_text(resp.text)


def parse_spec_text(text: str) -> Dict[str, Any]:
    """Public so callers with spec text already in hand (e.g. the inline
    dynamic_openapi_spec scan option) can reuse the same JSON-then-YAML
    parsing fetch_openapi_spec applies to a fetched body — one parsing
    policy for both entry points."""
    try:
        parsed = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        try:
            parsed = yaml.safe_load(text)
        except yaml.YAMLError as exc:
            raise ValueError(f"OpenAPI spec is neither valid JSON nor valid YAML: {exc}") from exc
    if not isinstance(parsed, dict):
        raise ValueError("OpenAPI spec did not parse to a JSON/YAML object")
    return parsed


def _param_value(param: Optional[Dict[str, Any]]) -> Optional[str]:
    """Prefer an explicit example/default/enum from the spec over the
    generic placeholder. OpenAPI 3 commonly puts these under 'schema'
    (schema.example, schema.default, schema.enum), Swagger 2 puts them
    directly on the parameter object — check both spots."""
    if not param:
        return None
    if param.get("example") is not None:
        return str(param["example"])
    schema = param.get("schema")
    if isinstance(schema, dict):
        if schema.get("example") is not None:
            return str(schema["example"])
        if schema.get("default") is not None:
            return str(schema["default"])
        enum = schema.get("enum")
        if isinstance(enum, list) and enum:
            return str(enum[0])
    if param.get("default") is not None:
        return str(param["default"])
    enum = param.get("enum")
    if isinstance(enum, list) and enum:
        return str(enum[0])
    return None


def _param_schema_type(param: Dict[str, Any]) -> Optional[str]:
    schema = param.get("schema") if isinstance(param.get("schema"), dict) else param
    return schema.get("type")


def _resolve_path(path_template: str, params: List[Dict[str, Any]]) -> Optional[str]:
    """Substitutes every {placeholder} in path_template. Returns None
    (operation gets skipped by the caller) when a placeholder has no
    example/default/enum AND its declared schema type is array/object —
    there's no sane single-scalar guess for those. Everything else
    (declared scalar types, or an undeclared/unknown type) falls back to
    PATH_PARAM_PLACEHOLDER."""
    param_by_name = {
        p.get("name"): p for p in params if isinstance(p, dict) and p.get("in") == "path"
    }
    resolved = path_template
    for name in _PATH_PARAM_PATTERN.findall(path_template):
        param = param_by_name.get(name)
        value = _param_value(param)
        if value is None:
            if param is not None and _param_schema_type(param) in _UNRESOLVABLE_SCALAR_TYPES:
                return None
            value = PATH_PARAM_PLACEHOLDER
        resolved = resolved.replace("{" + name + "}", value)
    return resolved


def _build_query_string(params: List[Dict[str, Any]]) -> List[tuple]:
    pairs = []
    for param in params:
        if not isinstance(param, dict) or param.get("in") != "query":
            continue
        name = param.get("name")
        if not name:
            continue
        value = _param_value(param)
        pairs.append((name, value if value is not None else PATH_PARAM_PLACEHOLDER))
    return pairs


def _join_url(base_url: str, resolved_path: str, query_pairs: List[tuple]) -> str:
    joined = urljoin(base_url if base_url.endswith("/") else base_url + "/", resolved_path.lstrip("/"))
    if not query_pairs:
        return joined
    parts = urlsplit(joined)
    existing = parse_qsl(parts.query, keep_blank_values=True)
    merged_query = urlencode(existing + query_pairs)
    return urlunsplit((parts.scheme, parts.netloc, parts.path, merged_query, parts.fragment))


def parse_openapi_spec(spec: Dict[str, Any], base_url: str) -> List[DiscoveredEndpoint]:
    """Walks spec['paths'] (the OpenAPI 2/3 shape both use: a dict of
    path-template -> {method: operation}), resolving each operation to one
    concrete DiscoveredEndpoint against base_url.

    Never raises on a malformed/unexpected shape — an empty or garbage
    'paths' value (missing, not a dict, an operation that isn't a dict,
    ...) is skipped field-by-field and simply contributes nothing, so a bad
    spec degrades to an empty list rather than blowing up the caller (which
    already wraps this in a try/except, but the contract holds either way).
    """
    endpoints: List[DiscoveredEndpoint] = []
    if not isinstance(spec, dict):
        return endpoints
    paths = spec.get("paths")
    if not isinstance(paths, dict):
        return endpoints

    for path_template, path_item in paths.items():
        if not isinstance(path_template, str) or not isinstance(path_item, dict):
            continue
        shared_params = path_item.get("parameters")
        shared_params = shared_params if isinstance(shared_params, list) else []

        for method, operation in path_item.items():
            if method.lower() not in _HTTP_METHODS or not isinstance(operation, dict):
                continue
            try:
                op_params = operation.get("parameters")
                op_params = op_params if isinstance(op_params, list) else []
                all_params = shared_params + op_params

                resolved_path = _resolve_path(path_template, all_params)
                if resolved_path is None:
                    logger.debug(
                        f"openapi_discovery: skipping unresolvable operation {method.upper()} {path_template}"
                    )
                    continue

                query_pairs = _build_query_string(all_params)
                url = _join_url(base_url, resolved_path, query_pairs)
                endpoints.append(DiscoveredEndpoint(method=method.upper(), url=url))
            except Exception as exc:
                # One malformed operation entry must never take the whole
                # spec down with it — same "degrade, don't abort" posture
                # as every other optional discovery step in this engine.
                logger.debug(f"openapi_discovery: skipping malformed operation {method} {path_template}: {exc}")
                continue

    return endpoints
