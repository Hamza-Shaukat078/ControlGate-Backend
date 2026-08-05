from pathlib import Path

from app.domain.analysis.dast.bridge import _extract_param_name, build_dynamic_targets, find_enclosing_route


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
        vulns = [_make_vuln("BROKEN_ACCESS_CONTROL", "app.py", 9)]

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
