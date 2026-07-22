import unittest

from app.domain.analysis.multi_file_repo_graph import MultiFileRepositoryGraph
from app.domain.analysis.interprocedural_dfg import DFGEdgeType
from app.enums.edge_type import EdgeType
from _utils import has_grammar, temporary_repo_dir


class TestCrossFileFlow(unittest.TestCase):
    def test_import_export_flow(self):
        if not has_grammar("javascript"):
            self.skipTest("Tree-sitter JavaScript grammar not available")
        with temporary_repo_dir() as repo:
            (repo / "a.js").write_text(
                "export function sink(x) { return x; }",
                encoding="utf-8"
            )
            (repo / "b.js").write_text(
                "import { sink } from './a';\\n"
                "const data = 'tainted';\\n"
                "sink(data);",
                encoding="utf-8"
            )

            graph = MultiFileRepositoryGraph(str(repo)).build()
            edges = graph["global_cpg"].edges
            import_edges = [
                e for e in edges
                if e.metadata and e.metadata.get("cross_file_edge_type") == "IMPORT_CALL"
            ]
            self.assertTrue(import_edges, "Expected IMPORT_CALL edges")

            dfg_import_edges = [
                e for e in edges
                if e.type == EdgeType.DFG_FLOW
                and e.metadata
                and e.metadata.get("dfg_edge_type") == DFGEdgeType.DFG_IMPORT.value
            ]
            self.assertTrue(dfg_import_edges, "Expected DFG_IMPORT edges for cross-file flow")

    def test_cross_file_two_hop(self):
        if not has_grammar("javascript"):
            self.skipTest("Tree-sitter JavaScript grammar not available")
        with temporary_repo_dir() as repo:
            (repo / "a.js").write_text("export function sink(x) { return x; }", encoding="utf-8")
            (repo / "b.js").write_text("export { sink } from './a';", encoding="utf-8")
            (repo / "c.js").write_text(
                "import { sink } from './b';\\n"
                "const data = 'tainted';\\n"
                "sink(data);",
                encoding="utf-8"
            )

            graph = MultiFileRepositoryGraph(str(repo)).build()
            edges = graph["global_cpg"].edges
            dfg_import_edges = [
                e for e in edges
                if e.type == EdgeType.DFG_FLOW
                and e.metadata
                and e.metadata.get("dfg_edge_type") == DFGEdgeType.DFG_IMPORT.value
            ]
            self.assertTrue(dfg_import_edges, "Expected DFG_IMPORT edges across reexport chain")


if __name__ == "__main__":
    unittest.main()
