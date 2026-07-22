import unittest

from app.domain.analysis.multi_file_repo_graph import MultiFileRepositoryGraph
from _utils import has_grammar, temporary_repo_dir


class TestCommonJSExports(unittest.TestCase):
    def test_module_exports_function(self):
        if not has_grammar("javascript"):
            self.skipTest("Tree-sitter JavaScript grammar not available")
        with temporary_repo_dir() as repo:
            (repo / "a.js").write_text(
                "function f() {}\\nmodule.exports = function g() {};",
                encoding="utf-8"
            )
            graph = MultiFileRepositoryGraph(str(repo)).build()
            exports = sum(len(m.exports) for m in graph["modules"])
            self.assertGreaterEqual(exports, 1)

    def test_exports_assignment(self):
        if not has_grammar("javascript"):
            self.skipTest("Tree-sitter JavaScript grammar not available")
        with temporary_repo_dir() as repo:
            (repo / "a.js").write_text("exports = function h() {};", encoding="utf-8")
            graph = MultiFileRepositoryGraph(str(repo)).build()
            exports = sum(len(m.exports) for m in graph["modules"])
            self.assertGreaterEqual(exports, 1)


if __name__ == "__main__":
    unittest.main()
