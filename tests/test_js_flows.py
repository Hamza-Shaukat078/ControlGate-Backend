import unittest

from app.domain.analysis.cpg_parser import CPGParser
from app.domain.analysis.interprocedural_dfg import InterproceduralDFG, DFGEdgeType


class TestJSFlows(unittest.TestCase):
    def setUp(self):
        self.parser = CPGParser()
        if not self.parser.has_language("javascript"):
            self.skipTest("Tree-sitter JavaScript grammar not available")

    def _build_edges(self, code: str):
        graph = self.parser.parse_code(code, "javascript", filename="test.js")
        dfg = InterproceduralDFG(graph).build()
        return dfg.edges

    def test_callback_flow(self):
        code = """
        function process(data, cb) {
            const result = data;
            cb(result);
        }

        process(input, function(output) {
            console.log(output);
        });
        """
        edges = self._build_edges(code)
        callback_edges = [
            e for e in edges
            if e.metadata and e.metadata.get("dfg_edge_type") == DFGEdgeType.DFG_CALLBACK.value
        ]
        self.assertTrue(callback_edges, "Expected callback DFG edges to be present")

    def test_closure_capture(self):
        code = """
        function outer(x) {
            return function inner(y) {
                return x + y;
            }
        }
        """
        edges = self._build_edges(code)
        closure_edges = [
            e for e in edges
            if e.metadata and e.metadata.get("dfg_edge_type") == DFGEdgeType.DFG_CLOSURE.value
        ]
        self.assertTrue(closure_edges, "Expected closure DFG edges to be present")


if __name__ == "__main__":
    unittest.main()
