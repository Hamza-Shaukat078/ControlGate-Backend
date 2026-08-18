from pathlib import Path

from app.domain.analysis.dast.bridge import (
    _discover_js_mount_prefixes,
    _extract_param_name,
    build_dynamic_targets,
    discover_routes_from_source,
    find_enclosing_route,
)
from app.domain.analysis.dast.openapi_discovery import DiscoveredEndpoint


FLASK_SOURCE = """\
from flask import Flask, request, redirect

app = Flask(__name__)


@app.route("/go", methods=["POST"])
def go():
    target = request.args.get("next")
    return redirect(target)
"""

FLASK_SEARCH_SOURCE = """\
from flask import Flask, request

app = Flask(__name__)


@app.route("/search")
def search():
    q = request.args.get("q")
    return render_results(q)
"""

FLASK_PRODUCTS_SOURCE = """\
from flask import Flask, request

app = Flask(__name__)


@app.route("/products")
def products():
    product_id = request.args.get("id")
    return run_query(product_id)
"""

FLASK_PROXY_SOURCE = """\
from flask import Flask, request
import requests

app = Flask(__name__)


@app.route("/proxy")
def proxy():
    target = request.args.get("url")
    return requests.get(target).text
"""

FASTAPI_SOURCE = """\
from fastapi import APIRouter

router = APIRouter()


@router.get("/files")
async def read_file(path: str):
    with open(path) as f:
        return f.read()
"""

EXPRESS_SOURCE = """\
const app = require('express')();

app.get('/redirect', (req, res) => {
    const next = req.query.next;
    res.redirect(next);
});
"""


def _make_vuln(rule_id, file_path, start_line, controls=None, finding_id="v1", source=""):
    return {
        "id": finding_id,
        "rule_id": rule_id,
        "asvs_controls": controls or ["V3.7.2"],
        "location": {"file": file_path, "start_line": start_line, "end_line": start_line},
        "evidence": {"source": source},
    }


class TestFindEnclosingRoute:
    def test_flask_route_with_methods(self):
        lines = FLASK_SOURCE.splitlines()
        route = find_enclosing_route(lines, 9, "python")  # body line inside go()
        assert route is not None
        assert route.path == "/go"
        assert route.method == "POST"

    def test_fastapi_verb_decorator(self):
        lines = FASTAPI_SOURCE.splitlines()
        route = find_enclosing_route(lines, 8, "python")
        assert route is not None
        assert route.path == "/files"
        assert route.method == "GET"

    def test_express_route_call(self):
        lines = EXPRESS_SOURCE.splitlines()
        route = find_enclosing_route(lines, 4, "javascript")
        assert route is not None
        assert route.path == "/redirect"
        assert route.method == "GET"

    def test_no_enclosing_def_returns_none(self):
        lines = ["x = 1", "y = 2"]
        assert find_enclosing_route(lines, 1, "python") is None

    def test_unknown_language_returns_none(self):
        assert find_enclosing_route(["whatever"], 1, None) is None


class TestBuildDynamicTargets:
    def test_maps_unvalidated_redirect_to_open_redirect_live(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(FLASK_SOURCE, encoding="utf-8")
        vulns = [_make_vuln("UNVALIDATED_REDIRECT", "app.py", 9)]

        targets = build_dynamic_targets(vulns, tmp_path, "https://target.example")

        assert len(targets) == 1
        t = targets[0]
        assert t.dynamic_rule_id == "OPEN_REDIRECT_LIVE"
        assert t.static_rule_id == "UNVALIDATED_REDIRECT"
        assert t.url == "https://target.example/go"
        assert t.method == "POST"
        assert t.asvs_controls == ["V3.7.2"]

    def test_maps_path_traversal_to_double_decode_bypass(self, tmp_path: Path):
        (tmp_path / "files.py").write_text(FASTAPI_SOURCE, encoding="utf-8")
        vulns = [_make_vuln("PATH_TRAVERSAL", "files.py", 8, controls=["V1.1.1"])]

        targets = build_dynamic_targets(vulns, tmp_path, "https://target.example")

        assert len(targets) == 1
        assert targets[0].dynamic_rule_id == "DOUBLE_DECODE_BYPASS"
        assert targets[0].url == "https://target.example/files"

    def test_unmapped_rule_is_skipped(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(FLASK_SOURCE, encoding="utf-8")
        # WEAK_CRYPTO has no live-check counterpart (nothing about the HTTP
        # surface can confirm/deny a weak crypto primitive) — deliberately
        # not in STATIC_TO_DYNAMIC_RULE_MAP and never expected to be.
        vulns = [_make_vuln("WEAK_CRYPTO", "app.py", 9)]

        assert build_dynamic_targets(vulns, tmp_path, "https://target.example") == []

    def test_maps_xss_to_reflected_xss_live(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(FLASK_SEARCH_SOURCE, encoding="utf-8")
        vulns = [_make_vuln("XSS", "app.py", 8, controls=["V1.2.1"], source="request.args.get('q')")]

        targets = build_dynamic_targets(vulns, tmp_path, "https://target.example")

        assert len(targets) == 1
        t = targets[0]
        assert t.dynamic_rule_id == "REFLECTED_XSS_LIVE"
        assert t.url == "https://target.example/search?q=1"

    def test_maps_sql_injection_to_sql_injection_live(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(FLASK_PRODUCTS_SOURCE, encoding="utf-8")
        vulns = [_make_vuln("SQL_INJECTION", "app.py", 8, controls=["V1.2.4"], source="request.args.get('id')")]

        targets = build_dynamic_targets(vulns, tmp_path, "https://target.example")

        assert len(targets) == 1
        t = targets[0]
        assert t.dynamic_rule_id == "SQL_INJECTION_LIVE"
        assert t.url == "https://target.example/products?id=1"

    def test_maps_ssrf_to_ssrf_live(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(FLASK_PROXY_SOURCE, encoding="utf-8")
        vulns = [_make_vuln("SSRF", "app.py", 9, controls=["V5.3.2"], source="request.args.get('url')")]

        targets = build_dynamic_targets(vulns, tmp_path, "https://target.example")

        assert len(targets) == 1
        t = targets[0]
        assert t.dynamic_rule_id == "SSRF_LIVE"
        assert t.static_rule_id == "SSRF"
        assert t.url == "https://target.example/proxy?url=1"

    def test_maps_command_injection_to_command_injection_live(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(FLASK_PRODUCTS_SOURCE, encoding="utf-8")
        vulns = [_make_vuln("COMMAND_INJECTION", "app.py", 8, controls=["V1.2.5"], source="request.args.get('id')")]

        targets = build_dynamic_targets(vulns, tmp_path, "https://target.example")

        assert len(targets) == 1
        t = targets[0]
        assert t.dynamic_rule_id == "COMMAND_INJECTION_LIVE"
        assert t.url == "https://target.example/products?id=1"

    def test_maps_code_injection_to_ssti_live(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(FLASK_SEARCH_SOURCE, encoding="utf-8")
        vulns = [_make_vuln("CODE_INJECTION", "app.py", 8, controls=["V1.3.2"], source="request.args.get('q')")]

        targets = build_dynamic_targets(vulns, tmp_path, "https://target.example")

        assert len(targets) == 1
        t = targets[0]
        assert t.dynamic_rule_id == "SSTI_LIVE"
        assert t.url == "https://target.example/search?q=1"

    def test_maps_xxe_unsafe_xml_parser_to_xxe_live(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(FLASK_SOURCE, encoding="utf-8")
        vulns = [_make_vuln("XXE_UNSAFE_XML_PARSER", "app.py", 9, controls=["V1.5.1"])]

        targets = build_dynamic_targets(vulns, tmp_path, "https://target.example")

        assert len(targets) == 1
        assert targets[0].dynamic_rule_id == "XXE_LIVE"

    def test_maps_nosql_injection_to_nosql_injection_live(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(FLASK_PRODUCTS_SOURCE, encoding="utf-8")
        vulns = [_make_vuln("NOSQL_INJECTION", "app.py", 8, controls=["V1.2.4"], source="request.args.get('id')")]

        targets = build_dynamic_targets(vulns, tmp_path, "https://target.example")

        assert len(targets) == 1
        t = targets[0]
        assert t.dynamic_rule_id == "NOSQL_INJECTION_LIVE"
        assert t.url == "https://target.example/products?id=1"

    def test_maps_cors_misconfiguration_to_cors_misconfig_live(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(FLASK_SOURCE, encoding="utf-8")
        vulns = [_make_vuln("CORS_MISCONFIGURATION", "app.py", 9, controls=["V3.4.2"])]

        targets = build_dynamic_targets(vulns, tmp_path, "https://target.example")

        assert len(targets) == 1
        assert targets[0].dynamic_rule_id == "CORS_MISCONFIG_LIVE"

    def test_maps_jwt_none_algorithm_to_jwt_weakness_live(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(FLASK_SOURCE, encoding="utf-8")
        vulns = [_make_vuln("JWT_NONE_ALGORITHM", "app.py", 9, controls=["V3.5.3"])]

        targets = build_dynamic_targets(vulns, tmp_path, "https://target.example")

        assert len(targets) == 1
        assert targets[0].dynamic_rule_id == "JWT_WEAKNESS_LIVE"

    def test_maps_missing_csrf_protection_to_csrf_token_not_validated(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(FLASK_SOURCE, encoding="utf-8")
        vulns = [_make_vuln("MISSING_CSRF_PROTECTION", "app.py", 9, controls=["V3.5.1"])]

        targets = build_dynamic_targets(vulns, tmp_path, "https://target.example")

        assert len(targets) == 1
        t = targets[0]
        assert t.dynamic_rule_id == "CSRF_TOKEN_NOT_VALIDATED"
        assert t.url == "https://target.example/go"

    def test_maps_broken_access_control_to_unauthenticated_access_allowed(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(FLASK_SOURCE, encoding="utf-8")
        vulns = [_make_vuln("BROKEN_ACCESS_CONTROL", "app.py", 9, controls=["V8.2.1"])]

        targets = build_dynamic_targets(vulns, tmp_path, "https://target.example")

        assert len(targets) == 1
        t = targets[0]
        assert t.dynamic_rule_id == "UNAUTHENTICATED_ACCESS_ALLOWED"
        assert t.url == "https://target.example/go"

    def test_maps_unsafe_dom_rendering_to_dom_xss_live(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(FLASK_SEARCH_SOURCE, encoding="utf-8")
        vulns = [_make_vuln("UNSAFE_DOM_RENDERING", "app.py", 8, controls=["V1.2.1"])]

        targets = build_dynamic_targets(vulns, tmp_path, "https://target.example")

        assert len(targets) == 1
        t = targets[0]
        assert t.dynamic_rule_id == "DOM_XSS_LIVE"
        assert t.url == "https://target.example/search"

    def test_param_dependent_rule_skipped_without_extractable_param(self, tmp_path: Path):
        # Route resolves fine, but the source label doesn't match any known
        # "read a query param" idiom — a bare route URL would only ever
        # come back NOT_TESTED for REFLECTED_XSS_LIVE, so no target at all.
        (tmp_path / "app.py").write_text(FLASK_SEARCH_SOURCE, encoding="utf-8")
        vulns = [_make_vuln("XSS", "app.py", 8, source="some_custom_input_source()")]

        assert build_dynamic_targets(vulns, tmp_path, "https://target.example") == []

    def test_unresolvable_route_is_skipped(self, tmp_path: Path):
        (tmp_path / "plain.py").write_text("x = 1\ny = 2\n", encoding="utf-8")
        vulns = [_make_vuln("UNVALIDATED_REDIRECT", "plain.py", 2)]

        assert build_dynamic_targets(vulns, tmp_path, "https://target.example") == []

    def test_missing_file_is_skipped_not_raised(self, tmp_path: Path):
        vulns = [_make_vuln("UNVALIDATED_REDIRECT", "does_not_exist.py", 3)]

        assert build_dynamic_targets(vulns, tmp_path, "https://target.example") == []

    def test_unsupported_extension_is_skipped(self, tmp_path: Path):
        (tmp_path / "route.rb").write_text("get '/x' do\nend\n", encoding="utf-8")
        vulns = [_make_vuln("UNVALIDATED_REDIRECT", "route.rb", 1)]

        assert build_dynamic_targets(vulns, tmp_path, "https://target.example") == []

    def test_missing_location_is_skipped(self, tmp_path: Path):
        vulns = [{"id": "v1", "rule_id": "UNVALIDATED_REDIRECT", "asvs_controls": [], "location": {}}]

        assert build_dynamic_targets(vulns, tmp_path, "https://target.example") == []


class TestExtractParamName:
    def test_flask_args_get(self):
        assert _extract_param_name("request.args.get('q')") == "q"

    def test_flask_args_getitem(self):
        assert _extract_param_name('request.args["search"]') == "search"

    def test_django_get_get(self):
        assert _extract_param_name("request.GET.get('term')") == "term"

    def test_express_query_dot_access(self):
        assert _extract_param_name("req.query.keyword") == "keyword"

    def test_express_query_getitem(self):
        assert _extract_param_name("req.query['id']") == "id"

    def test_express_params_dot_access(self):
        assert _extract_param_name("req.params.id") == "id"

    def test_unrecognized_source_returns_none(self):
        assert _extract_param_name("some_custom_input_source()") is None


class TestDiscoverRoutesFromSource:
    """Whole-repo automatic route discovery — the gap this closes: an
    API-only target (no crawlable HTML, no published OpenAPI spec) gives
    the dynamic engine no way to discover its real endpoints on its own.
    A hybrid scan has already cloned the repo for static analysis, so this
    extracts routes straight from the source instead."""

    def test_flask_route_discovered_with_path_param_substituted(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(
            "from flask import Flask\n"
            "app = Flask(__name__)\n\n"
            "@app.route('/orders/<int:order_id>', methods=['DELETE'])\n"
            "def delete_order(order_id):\n"
            "    ...\n",
            encoding="utf-8",
        )
        endpoints = discover_routes_from_source(tmp_path, "https://target.example")
        assert len(endpoints) == 1
        assert endpoints[0].method == "DELETE"
        assert endpoints[0].url == "https://target.example/orders/1"

    def test_fastapi_brace_path_param_substituted(self, tmp_path: Path):
        (tmp_path / "files.py").write_text(FASTAPI_SOURCE, encoding="utf-8")
        endpoints = discover_routes_from_source(tmp_path, "https://target.example")
        assert endpoints == [DiscoveredEndpoint(method="GET", url="https://target.example/files")]

    def test_express_colon_path_param_substituted(self, tmp_path: Path):
        (tmp_path / "server.js").write_text(
            "const app = require('express')();\n"
            "app.get('/api/users/:userId', (req, res) => {\n"
            "    res.json(getUser(req.params.userId));\n"
            "});\n",
            encoding="utf-8",
        )
        endpoints = discover_routes_from_source(tmp_path, "https://target.example")
        assert endpoints == [DiscoveredEndpoint(method="GET", url="https://target.example/api/users/1")]

    def test_multiple_routes_across_multiple_files_all_discovered(self, tmp_path: Path):
        (tmp_path / "a.py").write_text(FLASK_SOURCE, encoding="utf-8")
        (tmp_path / "b.py").write_text(FLASK_SEARCH_SOURCE, encoding="utf-8")
        endpoints = discover_routes_from_source(tmp_path, "https://target.example")
        urls = {e.url for e in endpoints}
        assert "https://target.example/go" in urls
        assert "https://target.example/search" in urls

    def test_get_and_post_on_same_path_both_discovered(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(
            "from flask import Flask\n"
            "app = Flask(__name__)\n\n"
            "@app.route('/items', methods=['GET'])\n"
            "def list_items():\n    ...\n\n"
            "@app.route('/items', methods=['POST'])\n"
            "def create_item():\n    ...\n",
            encoding="utf-8",
        )
        endpoints = discover_routes_from_source(tmp_path, "https://target.example")
        methods = {e.method for e in endpoints}
        assert methods == {"GET", "POST"}

    def test_non_route_code_produces_no_endpoints(self, tmp_path: Path):
        (tmp_path / "plain.py").write_text("x = 1\ndef f(): return x + 1\n", encoding="utf-8")
        assert discover_routes_from_source(tmp_path, "https://target.example") == []

    def test_undecodable_file_is_skipped_not_raised(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(FLASK_SOURCE, encoding="utf-8")
        # errors="replace" handles genuinely non-UTF-8 bytes without raising;
        # the rest of the repo must still be scanned regardless.
        (tmp_path / "binary.py").write_bytes(b"\xff\xfe\x00\x01garbage")
        endpoints = discover_routes_from_source(tmp_path, "https://target.example")
        assert any(e.url.endswith("/go") for e in endpoints)

    def test_capped_when_max_routes_explicitly_given(self, tmp_path: Path):
        lines = []
        for i in range(30):
            lines.append(f"@app.route('/r{i}')")
            lines.append(f"def r{i}():\n    ...\n")
        (tmp_path / "app.py").write_text(
            "from flask import Flask\napp = Flask(__name__)\n\n" + "\n".join(lines), encoding="utf-8",
        )
        endpoints = discover_routes_from_source(tmp_path, "https://target.example", max_routes=10)
        assert len(endpoints) == 10

    def test_no_cap_by_default_beyond_thirty_routes(self, tmp_path: Path):
        # Regression: unlike the crawler/OpenAPI-discovery caps (which bound
        # live requests already in flight), discovery itself is local-disk-
        # only and must not silently truncate — explicit user request to
        # remove the default cap here after it dropped 2 of 17 real routes
        # on a live scan (vuln-bank-app, MAX_SOURCE_ROUTES=15 at the time).
        lines = []
        for i in range(30):
            lines.append(f"@app.route('/r{i}')")
            lines.append(f"def r{i}():\n    ...\n")
        (tmp_path / "app.py").write_text(
            "from flask import Flask\napp = Flask(__name__)\n\n" + "\n".join(lines), encoding="utf-8",
        )
        endpoints = discover_routes_from_source(tmp_path, "https://target.example")
        assert len(endpoints) == 30

    def test_nonexistent_repo_root_returns_empty_not_raises(self, tmp_path: Path):
        assert discover_routes_from_source(tmp_path / "does-not-exist", "https://target.example") == []


class TestBlueprintPrefixResolution:
    """A Flask Blueprint's routes are decorated with @users_bp.route(...) in
    one file, but the actual live path also depends on
    app.register_blueprint(users_bp, url_prefix="/api/users") — almost
    always written in a *different* file (the app entrypoint). Without
    resolving this, discovered URLs are wrong (missing the prefix) even
    though the route path itself was extracted correctly — this was found
    empirically running against a real Flask app during this track's own
    verification, not a hypothetical case."""

    def test_blueprint_route_gets_prefix_from_a_different_file(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(
            "from flask import Flask\n"
            "from api.users import users_bp\n"
            "app = Flask(__name__)\n"
            "app.register_blueprint(users_bp, url_prefix=\"/api/users\")\n",
            encoding="utf-8",
        )
        (tmp_path / "api").mkdir()
        (tmp_path / "api" / "users.py").write_text(
            "from flask import Blueprint\n"
            "users_bp = Blueprint(\"users\", __name__)\n\n"
            "@users_bp.route(\"/profile/<int:user_id>\", methods=[\"GET\"])\n"
            "def profile(user_id):\n    ...\n",
            encoding="utf-8",
        )
        endpoints = discover_routes_from_source(tmp_path, "https://target.example")
        assert endpoints == [DiscoveredEndpoint(method="GET", url="https://target.example/api/users/profile/1")]

    def test_route_on_bare_app_object_is_not_prefixed(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(
            "from flask import Flask\n"
            "app = Flask(__name__)\n\n"
            "@app.route(\"/health\")\n"
            "def health():\n    ...\n",
            encoding="utf-8",
        )
        endpoints = discover_routes_from_source(tmp_path, "https://target.example")
        assert endpoints == [DiscoveredEndpoint(method="GET", url="https://target.example/health")]

    def test_blueprint_registered_without_url_prefix_is_not_prefixed(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(
            "from flask import Flask\n"
            "from api.misc import misc_bp\n"
            "app = Flask(__name__)\n"
            "app.register_blueprint(misc_bp)\n",
            encoding="utf-8",
        )
        (tmp_path / "misc.py").write_text(
            "from flask import Blueprint\n"
            "misc_bp = Blueprint(\"misc\", __name__)\n\n"
            "@misc_bp.route(\"/ping\")\n"
            "def ping():\n    ...\n",
            encoding="utf-8",
        )
        endpoints = discover_routes_from_source(tmp_path, "https://target.example")
        assert endpoints == [DiscoveredEndpoint(method="GET", url="https://target.example/ping")]

    def test_multiple_blueprints_each_get_their_own_prefix(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(
            "from flask import Flask\n"
            "app = Flask(__name__)\n"
            "app.register_blueprint(users_bp, url_prefix=\"/api/users\")\n"
            "app.register_blueprint(admin_bp, url_prefix=\"/api/admin\")\n",
            encoding="utf-8",
        )
        (tmp_path / "users.py").write_text(
            "users_bp = Blueprint(\"users\", __name__)\n\n"
            "@users_bp.route(\"/list\")\n"
            "def list_users():\n    ...\n",
            encoding="utf-8",
        )
        (tmp_path / "admin.py").write_text(
            "admin_bp = Blueprint(\"admin\", __name__)\n\n"
            "@admin_bp.route(\"/list\")\n"
            "def admin_list():\n    ...\n",
            encoding="utf-8",
        )
        endpoints = discover_routes_from_source(tmp_path, "https://target.example")
        urls = {e.url for e in endpoints}
        assert "https://target.example/api/users/list" in urls
        assert "https://target.example/api/admin/list" in urls

    def test_express_router_gets_prefix_from_es_module_import_in_server_js(self, tmp_path: Path):
        """The exact shape this was built against — a modular Express
        router (routes defined at the router's own root/':id') mounted at a
        prefix in server.js via an ES module import, not in the same file
        as the route decorators themselves."""
        (tmp_path / "server.js").write_text(
            "import express from 'express';\n"
            "import orderRoutes from './routes/order.routes.js';\n"
            "const app = express();\n"
            "app.use('/orders', orderRoutes);\n",
            encoding="utf-8",
        )
        (tmp_path / "routes").mkdir()
        (tmp_path / "routes" / "order.routes.js").write_text(
            "import express from 'express';\n"
            "const router = express.Router();\n"
            "router.get('/', getUserOrders);\n"
            "router.get('/:id', getOrderById);\n"
            "export default router;\n",
            encoding="utf-8",
        )
        endpoints = discover_routes_from_source(tmp_path, "http://localhost:3003")
        urls = {e.url for e in endpoints}
        assert "http://localhost:3003/orders/" in urls
        assert "http://localhost:3003/orders/1" in urls  # :id substituted, same as Flask's <int:id>

    def test_express_router_gets_prefix_from_commonjs_require(self, tmp_path: Path):
        (tmp_path / "server.js").write_text(
            "const express = require('express');\n"
            "const productRoutes = require('./routes/product.routes');\n"
            "const app = express();\n"
            "app.use('/products', productRoutes);\n",
            encoding="utf-8",
        )
        (tmp_path / "routes").mkdir()
        (tmp_path / "routes" / "product.routes.js").write_text(
            "const router = require('express').Router();\n"
            "router.get('/', getAllProducts);\n"
            "module.exports = router;\n",
            encoding="utf-8",
        )
        endpoints = discover_routes_from_source(tmp_path, "http://localhost:3002")
        assert endpoints == [DiscoveredEndpoint(method="GET", url="http://localhost:3002/products/")]

    def test_express_router_never_mounted_is_not_prefixed(self, tmp_path: Path):
        """No app.use(...) anywhere referencing it — same "skip rather than
        guess" posture as the Flask blueprint-without-url_prefix case."""
        (tmp_path / "standalone.js").write_text(
            "const router = require('express').Router();\n"
            "router.get('/ping', ping);\n",
            encoding="utf-8",
        )
        endpoints = discover_routes_from_source(tmp_path, "https://target.example")
        assert endpoints == [DiscoveredEndpoint(method="GET", url="https://target.example/ping")]

    def test_two_express_routers_each_get_their_own_prefix(self, tmp_path: Path):
        (tmp_path / "server.js").write_text(
            "import authRoutes from './routes/auth.routes.js';\n"
            "import productRoutes from './routes/product.routes.js';\n"
            "app.use('/auth', authRoutes);\n"
            "app.use('/products', productRoutes);\n",
            encoding="utf-8",
        )
        (tmp_path / "routes").mkdir()
        (tmp_path / "routes" / "auth.routes.js").write_text(
            "const router = express.Router();\nrouter.post('/login', login);\nexport default router;\n",
            encoding="utf-8",
        )
        (tmp_path / "routes" / "product.routes.js").write_text(
            "const router = express.Router();\nrouter.get('/', list);\nexport default router;\n",
            encoding="utf-8",
        )
        endpoints = discover_routes_from_source(tmp_path, "http://localhost:3000")
        urls = {(e.method, e.url) for e in endpoints}
        assert ("POST", "http://localhost:3000/auth/login") in urls
        assert ("GET", "http://localhost:3000/products/") in urls


class TestFindEnclosingRouteJsMountPrefix:
    """find_enclosing_route's single-finding lookup (used by
    build_dynamic_targets, not discover_routes_from_source's whole-repo
    walk) needs the same prefix applied — otherwise a static XSS/SQLi
    finding inside a modular Express router bridges to the wrong (unmounted)
    URL even though discover_routes_from_source resolves it correctly."""

    def test_express_route_gets_mount_prefix_via_file_path_lookup(self, tmp_path: Path):
        (tmp_path / "server.js").write_text(
            "import orderRoutes from './routes/order.routes.js';\n"
            "app.use('/orders', orderRoutes);\n",
            encoding="utf-8",
        )
        (tmp_path / "routes").mkdir()
        route_file = tmp_path / "routes" / "order.routes.js"
        route_file.write_text(
            "const router = express.Router();\n"
            "router.get('/:id', getOrderById);\n",
            encoding="utf-8",
        )
        candidate_files = [p for p in tmp_path.rglob("*") if p.is_file()]
        js_mount_prefixes = _discover_js_mount_prefixes(candidate_files)
        lines = route_file.read_text(encoding="utf-8").splitlines()

        route = find_enclosing_route(
            lines, 2, "javascript", js_mount_prefixes=js_mount_prefixes, file_path=route_file,
        )
        assert route is not None
        assert route.path == "/orders/:id"

    def test_express_route_without_file_path_arg_is_unprefixed(self, tmp_path: Path):
        """Backward-compat: omitting file_path/js_mount_prefixes (as every
        pre-existing call site not yet updated would) behaves exactly as
        before this feature existed."""
        lines = ["router.get('/:id', getOrderById);"]
        route = find_enclosing_route(lines, 1, "javascript")
        assert route is not None
        assert route.path == "/:id"
