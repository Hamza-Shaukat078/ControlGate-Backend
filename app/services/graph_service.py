from pathlib import Path
from typing import Dict, Any, Optional
import logging

from motor.motor_asyncio import AsyncIOMotorDatabase

logger = logging.getLogger(__name__)


def _language_from_path(file_path: str | None) -> str:
    ext = Path(file_path or "").suffix.lower()
    return {
        ".py": "python",
        ".js": "javascript",
        ".jsx": "javascript",
        ".ts": "typescript",
        ".tsx": "typescript",
        ".java": "java",
        ".php": "php",
        ".go": "go",
        ".rb": "ruby",
        ".cs": "csharp",
        ".json": "json",
        ".html": "html",
        ".css": "css",
    }.get(ext, "text")


class GraphService:
    """
    Service for retrieving graph visualizations from completed scans.
    Returns actual AST/CFG/DFG graphs from the semantic analysis engine.
    """
    
    def __init__(self, db: AsyncIOMotorDatabase) -> None:
        self.db = db

    async def graph(self, scan_id: str, file_id: str, gtype: str) -> Dict[str, Any]:
        """
        Get graph visualization for a scanned file.
        
        Args:
            scan_id: Scan identifier
            file_id: File identifier (currently unused for direct code scans)
            gtype: Graph type (AST, CFG, DFG, or CPG)
        
        Returns:
            Graph data with nodes and edges
        """
        scan = await self.db.scans.find_one({"scan_id": scan_id})
        
        if not scan:
            return {
                "type": gtype.upper(),
                "nodes": [],
                "edges": [],
                "error": "Scan not found",
                "detail": f"No scan found with ID: {scan_id}"
            }
        
        # Check if scan is complete
        if scan.get("state") != "COMPLETED":
            return {
                "type": gtype.upper(),
                "nodes": [],
                "edges": [],
                "error": "Scan not completed",
                "detail": f"Scan is in state: {scan.get('state')}. Wait for completion."
            }
        
        # Get stored graph data
        graph_data = scan.get("graph_data")
        
        if not graph_data:
            return {
                "type": gtype.upper(),
                "nodes": [],
                "edges": [],
                "error": "No graph data available",
                "detail": "Graph data was not stored during scan. This may be an older scan."
            }
        
        selected_graph = graph_data
        file_info = None
        if isinstance(graph_data, dict) and "files" in graph_data:
            files = graph_data.get("files") or {}
            file_order = list(graph_data.get("file_order") or files.keys())
            file_map = dict(graph_data.get("file_map") or {})

            # Supplement file list with any files found in vulnerabilities
            # (e.g. Pipfile, requirements.txt, .npmrc that _collect_source_files skips)
            vuln_path_set = set(file_map.values())
            for vuln in ((scan.get("summary") or {}).get("vulnerabilities") or []):
                fpath = ((vuln.get("location") or {}).get("file") or "").strip()
                if fpath and fpath not in vuln_path_set:
                    vuln_path_set.add(fpath)
                    vid = f"vfile-{len(file_order)}"
                    file_map[vid] = fpath
                    file_order.append(vid)

            available = [{"id": k, "path": file_map.get(k)} for k in file_order]

            # Requested file is a supplemented (non-source) file — no graph data
            if file_id in file_map and file_id not in files:
                return {
                    "type": gtype.upper(),
                    "nodes": [],
                    "edges": [],
                    "meta": {"total_nodes": 0, "total_edges": 0},
                    "file": {
                        "file_id": file_id,
                        "file_path": file_map[file_id],
                        "available_files": available,
                    },
                    "detail": "No graph data for this file type — AST/CPG graphs are only generated for source code files.",
                }

            target_id = file_id if file_id in files else None
            if not target_id and file_order:
                target_id = file_order[0]
            if target_id:
                selected_graph = files.get(target_id)
                file_info = {
                    "file_id": target_id,
                    "file_path": file_map.get(target_id),
                    "available_files": available,
                }
            else:
                selected_graph = None

        if not selected_graph:
            return {
                "type": gtype.upper(),
                "nodes": [],
                "edges": [],
                "error": "No graph data available",
                "detail": "No graph data available for this file.",
            }

        # Return requested graph type
        graph_type = gtype.upper()
        
        if graph_type == "AST":
            response = self._format_ast_graph(selected_graph)
        elif graph_type == "CFG":
            response = self._format_cfg_graph(selected_graph)
        elif graph_type == "DFG":
            response = self._format_dfg_graph(selected_graph)
        elif graph_type == "CPG":
            response = self._format_cpg_graph(selected_graph)
        else:
            return {
                "error": "Unsupported graph type",
                "detail": f"Graph type '{gtype}' not supported. Use AST, CFG, DFG, or CPG."
            }
        source_content = selected_graph.get("source_content") if isinstance(selected_graph, dict) else None
        if file_info:
            file_info["source_content"] = source_content or ""
            file_info["language"] = _language_from_path(file_info.get("file_path"))
            response["file"] = file_info
        elif source_content is not None:
            response["file"] = {
                "file_id": file_id,
                "file_path": selected_graph.get("file_path"),
                "available_files": [],
                "source_content": source_content or "",
                "language": _language_from_path(selected_graph.get("file_path")),
            }
        return response
    
    def _format_ast_graph(self, graph_data: Dict[str, Any]) -> Dict[str, Any]:
        """Format AST graph for visualization."""
        nodes = graph_data.get("nodes", [])
        edges = graph_data.get("edges", [])
        
        # Filter to AST nodes and edges only
        ast_nodes = [
            {
                "id": node["id"],
                "label": node.get("label", node.get("type", "Node")),
                "type": node.get("type"),
                "properties": node.get("properties", {})
            }
            for node in nodes
            if node.get("node_type") in ["AST", None]  # Include nodes without explicit type
        ]
        
        # Get node IDs for filtering edges
        ast_node_ids = {n["id"] for n in ast_nodes}
        
        ast_edges = [
            {
                "from": edge["source"],
                "to": edge["target"],
                "label": edge.get("label", ""),
                "type": edge.get("type")
            }
            for edge in edges
            if edge.get("edge_type") in ["AST", "CHILD", None]
            and edge["source"] in ast_node_ids
            and edge["target"] in ast_node_ids
        ]
        
        return {
            "type": "AST",
            "nodes": ast_nodes,
            "edges": ast_edges,
            "meta": {
                "total_nodes": len(ast_nodes),
                "total_edges": len(ast_edges)
            }
        }
    
    def _format_cfg_graph(self, graph_data: Dict[str, Any]) -> Dict[str, Any]:
        """Format CFG graph for visualization."""
        nodes = graph_data.get("nodes", [])
        edges = graph_data.get("edges", [])
        
        # For CFG, show control flow nodes
        cfg_nodes = [
            {
                "id": node["id"],
                "label": node.get("label", "Block"),
                "type": node.get("type"),
                "properties": node.get("properties", {})
            }
            for node in nodes
        ]
        
        # Filter CFG edges
        cfg_node_ids = {n["id"] for n in cfg_nodes}
        
        cfg_edges = [
            {
                "from": edge["source"],
                "to": edge["target"],
                "label": edge.get("label", ""),
                "type": edge.get("type"),
                "condition": edge.get("properties", {}).get("condition")
            }
            for edge in edges
            if edge.get("edge_type") in ["CFG", "CONTROL_FLOW"]
            and edge["source"] in cfg_node_ids
            and edge["target"] in cfg_node_ids
        ]
        
        return {
            "type": "CFG",
            "nodes": cfg_nodes,
            "edges": cfg_edges,
            "meta": {
                "total_nodes": len(cfg_nodes),
                "total_edges": len(cfg_edges)
            }
        }
    
    def _format_dfg_graph(self, graph_data: Dict[str, Any]) -> Dict[str, Any]:
        """Format DFG graph for visualization."""
        nodes = graph_data.get("nodes", [])
        edges = graph_data.get("edges", [])
        
        # For DFG, show data flow nodes
        dfg_nodes = [
            {
                "id": node["id"],
                "label": node.get("label", "Variable"),
                "type": node.get("type"),
                "properties": node.get("properties", {}),
                "tainted": node.get("properties", {}).get("tainted", False)
            }
            for node in nodes
        ]
        
        # Filter DFG edges
        dfg_node_ids = {n["id"] for n in dfg_nodes}
        
        dfg_edges = [
            {
                "from": edge["source"],
                "to": edge["target"],
                "label": edge.get("label", ""),
                "type": edge.get("type"),
                "data_flow": edge.get("properties", {}).get("flow_type")
            }
            for edge in edges
            if edge.get("edge_type") in ["DFG", "DATA_FLOW", "DFG_INTERP", "DFG_TEMPLATE"]
            and edge["source"] in dfg_node_ids
            and edge["target"] in dfg_node_ids
        ]
        
        return {
            "type": "DFG",
            "nodes": dfg_nodes,
            "edges": dfg_edges,
            "meta": {
                "total_nodes": len(dfg_nodes),
                "total_edges": len(dfg_edges),
                "tainted_nodes": sum(1 for n in dfg_nodes if n.get("tainted"))
            }
        }
    
    def _format_cpg_graph(self, graph_data: Dict[str, Any]) -> Dict[str, Any]:
        """Format complete CPG (all graphs combined)."""
        nodes = graph_data.get("nodes", [])
        edges = graph_data.get("edges", [])
        
        # Return all nodes and edges
        all_nodes = [
            {
                "id": node["id"],
                "label": node.get("label", "Node"),
                "type": node.get("type"),
                "node_type": node.get("node_type"),
                "properties": node.get("properties", {}),
                "tainted": node.get("properties", {}).get("tainted", False)
            }
            for node in nodes
        ]
        
        all_edges = [
            {
                "from": edge["source"],
                "to": edge["target"],
                "label": edge.get("label", ""),
                "type": edge.get("type"),
                "edge_type": edge.get("edge_type")
            }
            for edge in edges
        ]
        
        return {
            "type": "CPG",
            "nodes": all_nodes,
            "edges": all_edges,
            "meta": {
                "total_nodes": len(all_nodes),
                "total_edges": len(all_edges),
                "tainted_nodes": sum(1 for n in all_nodes if n.get("tainted"))
            }
        }
