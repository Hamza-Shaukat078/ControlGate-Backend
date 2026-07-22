import unittest

from app.domain.analysis.multi_file_repo_graph import MultiFileRepositoryGraph
from _utils import has_grammar, temporary_repo_dir


class TestImportExportPatterns(unittest.TestCase):
    def test_ts_import_equals(self):
        if not has_grammar("typescript"):
            self.skipTest("Tree-sitter TypeScript grammar not available")
        with temporary_repo_dir() as repo:
            (repo / "a.ts").write_text("export const value = 1;", encoding="utf-8")
            (repo / "b.ts").write_text("import x = require('./a');\\nconsole.log(x);", encoding="utf-8")
            graph = MultiFileRepositoryGraph(str(repo)).build()
            imports = sum(len(m.imports) for m in graph["modules"])
            self.assertGreaterEqual(imports, 1)

    def test_commonjs_exports_assignment(self):
        if not has_grammar("javascript"):
            self.skipTest("Tree-sitter JavaScript grammar not available")
        with temporary_repo_dir() as repo:
            (repo / "a.js").write_text("function f() {}\\nmodule.exports = f;", encoding="utf-8")
            graph = MultiFileRepositoryGraph(str(repo)).build()
            exports = sum(len(m.exports) for m in graph["modules"])
            self.assertGreaterEqual(exports, 1)


if __name__ == "__main__":
    unittest.main()
