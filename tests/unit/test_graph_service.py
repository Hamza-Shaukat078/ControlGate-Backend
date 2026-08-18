"""app/services/graph_service.py — retrieves AST/CFG/DFG/CPG graphs for a
completed scan. Zero prior coverage despite ~340 lines of real branching
logic (multi-file selection, vulnerability-supplemented file list, per-type
node/edge filtering).
"""
import pytest

from app.services.graph_service import GraphService, _language_from_path


def _node(id, node_type="AST", type_="Call", tainted=False, **props):
    return {"id": id, "node_type": node_type, "type": type_, "label": type_, "properties": {"tainted": tainted, **props}}


def _edge(source, target, edge_type="AST", **props):
    return {"source": source, "target": target, "edge_type": edge_type, "type": edge_type, "properties": props}


SINGLE_FILE_GRAPH = {
    "nodes": [_node("n1"), _node("n2", tainted=True)],
    "edges": [_edge("n1", "n2", edge_type="DFG")],
    "source_content": "print('hi')",
    "file_path": "app.py",
}


class TestGraphScanLookupGuards:
    @pytest.mark.asyncio
    async def test_unknown_scan_id_returns_not_found_error(self, mongo_db):
        service = GraphService(mongo_db)
        result = await service.graph("nope", "f1", "AST")
        assert result["error"] == "Scan not found"
        assert result["nodes"] == [] and result["edges"] == []

    @pytest.mark.asyncio
    async def test_incomplete_scan_returns_not_completed_error(self, mongo_db):
        await mongo_db.scans.insert_one({"scan_id": "s1", "state": "RUNNING"})
        service = GraphService(mongo_db)
        result = await service.graph("s1", "f1", "AST")
        assert result["error"] == "Scan not completed"
        assert "RUNNING" in result["detail"]

    @pytest.mark.asyncio
    async def test_completed_scan_without_graph_data_returns_error(self, mongo_db):
        await mongo_db.scans.insert_one({"scan_id": "s2", "state": "COMPLETED"})
        service = GraphService(mongo_db)
        result = await service.graph("s2", "f1", "AST")
        assert result["error"] == "No graph data available"

    @pytest.mark.asyncio
    async def test_unsupported_graph_type_returns_error(self, mongo_db):
        await mongo_db.scans.insert_one({"scan_id": "s3", "state": "COMPLETED", "graph_data": SINGLE_FILE_GRAPH})
        service = GraphService(mongo_db)
        result = await service.graph("s3", "f1", "XYZ")
        assert result["error"] == "Unsupported graph type"


class TestSingleFileGraph:
    @pytest.mark.asyncio
    async def test_ast_graph_includes_source_and_language(self, mongo_db):
        await mongo_db.scans.insert_one({"scan_id": "s4", "state": "COMPLETED", "graph_data": SINGLE_FILE_GRAPH})
        service = GraphService(mongo_db)
        result = await service.graph("s4", "irrelevant", "AST")
        assert result["type"] == "AST"
        assert result["file"]["source_content"] == "print('hi')"
        assert result["file"]["language"] == "python"


class TestMultiFileGraph:
    @staticmethod
    def _multi_file_graph_data():
        return {
            "files": {
                "f1": {
                    "nodes": [_node("n1"), _node("n2", tainted=True)],
                    "edges": [_edge("n1", "n2", edge_type="DFG")],
                    "source_content": "x = 1",
                },
                "f2": {"nodes": [_node("m1")], "edges": [], "source_content": "y = 2"},
            },
            "file_order": ["f1", "f2"],
            "file_map": {"f1": "a.py", "f2": "b.js"},
        }

    @pytest.mark.asyncio
    async def test_requested_file_id_is_selected(self, mongo_db):
        await mongo_db.scans.insert_one({
            "scan_id": "s5", "state": "COMPLETED", "graph_data": self._multi_file_graph_data(),
        })
        service = GraphService(mongo_db)
        result = await service.graph("s5", "f2", "AST")
        assert result["file"]["file_id"] == "f2"
        assert result["file"]["file_path"] == "b.js"
        assert result["file"]["language"] == "javascript"

    @pytest.mark.asyncio
    async def test_unknown_file_id_falls_back_to_first_in_order(self, mongo_db):
        await mongo_db.scans.insert_one({
            "scan_id": "s6", "state": "COMPLETED", "graph_data": self._multi_file_graph_data(),
        })
        service = GraphService(mongo_db)
        result = await service.graph("s6", "does-not-exist", "AST")
        assert result["file"]["file_id"] == "f1"

    @pytest.mark.asyncio
    async def test_available_files_lists_every_file_in_order(self, mongo_db):
        await mongo_db.scans.insert_one({
            "scan_id": "s7", "state": "COMPLETED", "graph_data": self._multi_file_graph_data(),
        })
        service = GraphService(mongo_db)
        result = await service.graph("s7", "f1", "AST")
        assert result["file"]["available_files"] == [
            {"id": "f1", "path": "a.py"}, {"id": "f2", "path": "b.js"},
        ]

    @pytest.mark.asyncio
    async def test_vulnerability_only_file_is_supplemented_into_available_list(self, mongo_db):
        graph_data = self._multi_file_graph_data()
        await mongo_db.scans.insert_one({
            "scan_id": "s8", "state": "COMPLETED", "graph_data": graph_data,
            "summary": {"vulnerabilities": [{"location": {"file": "requirements.txt"}}]},
        })
        service = GraphService(mongo_db)
        result = await service.graph("s8", "f1", "AST")
        paths = {f["path"] for f in result["file"]["available_files"]}
        assert "requirements.txt" in paths

    @pytest.mark.asyncio
    async def test_requesting_a_supplemented_non_source_file_returns_no_graph_data(self, mongo_db):
        graph_data = self._multi_file_graph_data()
        await mongo_db.scans.insert_one({
            "scan_id": "s9", "state": "COMPLETED", "graph_data": graph_data,
            "summary": {"vulnerabilities": [{"location": {"file": "requirements.txt"}}]},
        })
        service = GraphService(mongo_db)
        result = await service.graph("s9", "vfile-2", "AST")
        assert result["detail"].startswith("No graph data for this file type")
        assert result["file"]["file_path"] == "requirements.txt"


class TestGraphTypeFormatting:
    @pytest.mark.asyncio
    async def test_dfg_reports_tainted_node_count(self, mongo_db):
        await mongo_db.scans.insert_one({"scan_id": "s10", "state": "COMPLETED", "graph_data": SINGLE_FILE_GRAPH})
        service = GraphService(mongo_db)
        result = await service.graph("s10", "f1", "DFG")
        assert result["meta"]["tainted_nodes"] == 1
        assert len(result["nodes"]) == 2
        assert len(result["edges"]) == 1  # DFG edge type matched

    @pytest.mark.asyncio
    async def test_cfg_filters_out_non_control_flow_edges(self, mongo_db):
        graph_data = {
            "nodes": [_node("n1"), _node("n2")],
            "edges": [_edge("n1", "n2", edge_type="DFG")],  # not CFG/CONTROL_FLOW
        }
        await mongo_db.scans.insert_one({"scan_id": "s11", "state": "COMPLETED", "graph_data": graph_data})
        service = GraphService(mongo_db)
        result = await service.graph("s11", "f1", "CFG")
        assert result["edges"] == []

    @pytest.mark.asyncio
    async def test_ast_excludes_non_ast_typed_nodes(self, mongo_db):
        graph_data = {
            "nodes": [_node("n1", node_type="AST"), _node("n2", node_type="CFG_ONLY")],
            "edges": [],
        }
        await mongo_db.scans.insert_one({"scan_id": "s12", "state": "COMPLETED", "graph_data": graph_data})
        service = GraphService(mongo_db)
        result = await service.graph("s12", "f1", "AST")
        assert {n["id"] for n in result["nodes"]} == {"n1"}

    @pytest.mark.asyncio
    async def test_cpg_returns_every_node_and_edge_regardless_of_type(self, mongo_db):
        graph_data = {
            "nodes": [_node("n1", node_type="AST"), _node("n2", node_type="CFG_ONLY", tainted=True)],
            "edges": [_edge("n1", "n2", edge_type="ANYTHING")],
        }
        await mongo_db.scans.insert_one({"scan_id": "s13", "state": "COMPLETED", "graph_data": graph_data})
        service = GraphService(mongo_db)
        result = await service.graph("s13", "f1", "CPG")
        assert len(result["nodes"]) == 2
        assert len(result["edges"]) == 1
        assert result["meta"]["tainted_nodes"] == 1

    @pytest.mark.asyncio
    async def test_type_lookup_is_case_insensitive(self, mongo_db):
        await mongo_db.scans.insert_one({"scan_id": "s14", "state": "COMPLETED", "graph_data": SINGLE_FILE_GRAPH})
        service = GraphService(mongo_db)
        result = await service.graph("s14", "f1", "ast")
        assert result["type"] == "AST"


class TestLanguageFromPath:
    @pytest.mark.parametrize("path,expected", [
        ("app.py", "python"), ("index.tsx", "typescript"), ("Main.java", "java"),
        ("script.rb", "ruby"), ("styles.css", "css"), ("data.json", "json"),
        (None, "text"), ("no_extension", "text"), ("weird.xyz", "text"),
    ])
    def test_extension_mapping(self, path, expected):
        assert _language_from_path(path) == expected
