from pathlib import Path

from app.domain.analysis.dast.bridge import build_dynamic_targets, find_enclosing_route


FLASK_SOURCE = """\
from flask import Flask, request, redirect

app = Flask(__name__)


@app.route("/go", methods=["POST"])
def go():
    target = request.args.get("next")
    return redirect(target)
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


def _make_vuln(rule_id, file_path, start_line, controls=None, finding_id="v1"):
    return {
        "id": finding_id,
        "rule_id": rule_id,
        "asvs_controls": controls or ["V3.7.2"],
        "location": {"file": file_path, "start_line": start_line, "end_line": start_line},
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
        vulns = [_make_vuln("SQL_INJECTION", "app.py", 9)]

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
