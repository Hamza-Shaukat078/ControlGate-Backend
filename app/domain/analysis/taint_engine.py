from typing import List
from app.schemas.graph import SemanticGraph, GraphNode
from app.schemas.taint import TaintSource, TaintSink, TaintResult
from app.enums.edge_type import EdgeType
from app.enums.node_type import NodeType


class TaintEngine:
    """
    Taint tracking engine.
    Identifies sources, sinks, and traces data flow paths between them.
    """
    
    # Initializes the engine with default taint source and sink rule sets.
    def __init__(self):
        self.sources = self._default_sources()
        self.sinks = self._default_sinks()
    
    def analyze(self, graph: SemanticGraph) -> List[TaintResult]:
        """
        Find all taint flows from sources to sinks.
        """
        results: List[TaintResult] = []
        
        # Identify source nodes
        source_nodes = self._find_sources(graph)
        
        # Identify sink nodes
        sink_nodes = self._find_sinks(graph)
        
        # For each source, trace flow to sinks
        for source in source_nodes:
            for sink in sink_nodes:
                paths = self._find_paths(graph, source, sink)
                for path in paths:
                    severity = self._compute_severity(source, sink, path)
                    results.append(TaintResult(
                        source_node=source,
                        sink_node=sink,
                        flow_path=path,
                        severity=severity
                    ))
        
        return results
    
    def _find_sources(self, graph: SemanticGraph) -> List[GraphNode]:
        """Identify taint source nodes based on patterns."""
        sources = []
        for node in graph.nodes:
            for source_def in self.sources:
                if self._matches_pattern(node, source_def):
                    # Mark node as tainted
                    if node.metadata:
                        node.metadata.is_tainted = True
                        node.metadata.security_role = "source"
                    sources.append(node)
                    break
        return sources
    
    def _find_sinks(self, graph: SemanticGraph) -> List[GraphNode]:
        """Identify taint sink nodes based on patterns."""
        sinks = []
        for node in graph.nodes:
            for sink_def in self.sinks:
                if self._matches_pattern(node, sink_def):
                    if node.metadata:
                        node.metadata.security_role = "sink"
                    sinks.append(node)
                    break
        return sinks
    
    def _matches_pattern(self, node: GraphNode, rule: TaintSource | TaintSink) -> bool:
        """Check if node matches a taint rule pattern."""
        if node.type != rule.match.node_type:
            return False
        
        # Parameters always match (they're user-controlled input)
        if node.type == NodeType.PARAMETER:
            return True
        
        if not node.name:
            return False
        
        for pattern in rule.match.patterns:
            if pattern.lower() in node.name.lower():
                return True
        
        return False
    
    def _find_paths(self, graph: SemanticGraph, source: GraphNode, sink: GraphNode) -> List[List[GraphNode]]:
        """
        Find all paths from source to sink via DFG/CFG edges.
        Uses simple BFS with path tracking.
        """
        # Build adjacency list
        adj: dict[str, list[str]] = {}
        for edge in graph.edges:
            if edge.type in (EdgeType.DFG_FLOW, EdgeType.CFG_NEXT, EdgeType.TAINT_FLOW):
                if edge.from_node not in adj:
                    adj[edge.from_node] = []
                adj[edge.from_node].append(edge.to_node)
        
        # BFS to find paths
        paths = []
        queue = [(source.id, [source.id])]
        visited_paths = set()
        max_depth = 20  # Prevent infinite loops
        
        while queue:
            current_id, path = queue.pop(0)
            
            if len(path) > max_depth:
                continue
            
            if current_id == sink.id:
                # Found a path
                path_key = tuple(path)
                if path_key not in visited_paths:
                    visited_paths.add(path_key)
                    # Convert IDs to nodes
                    node_map = {n.id: n for n in graph.nodes}
                    paths.append([node_map[nid] for nid in path if nid in node_map])
                continue
            
            if current_id in adj:
                for neighbor in adj[current_id]:
                    if neighbor not in path:  # Avoid cycles
                        queue.append((neighbor, path + [neighbor]))
        
        return paths
    
    def _compute_severity(self, source: GraphNode, sink: GraphNode, path: List[GraphNode]) -> str:
        """Compute severity based on source/sink types and path length."""
        # Simple heuristic
        if len(path) <= 3:
            return "critical"
        elif len(path) <= 6:
            return "high"
        elif len(path) <= 10:
            return "medium"
        else:
            return "low"
    
    def _default_sources(self) -> List[TaintSource]:
        """Default taint sources (user input, HTTP requests, function parameters, etc.)."""
        return [
            TaintSource(
                id="function_parameter",
                description="Function parameters (user-controlled input)",
                match={
                    "node_type": NodeType.PARAMETER,
                    "patterns": ["*"]  # All parameters are potential sources
                }
            ),
            TaintSource(
                id="http_request_data",
                description="HTTP request data (GET/POST params, headers)",
                match={
                    "node_type": NodeType.CALL_EXPRESSION,
                    "patterns": ["request.get", "request.post", "request.args", "request.form", "request.GET", "request.POST"]
                }
            ),
            TaintSource(
                id="user_input",
                description="User input functions",
                match={
                    "node_type": NodeType.CALL_EXPRESSION,
                    "patterns": ["input", "raw_input", "stdin"]
                }
            ),
            TaintSource(
                id="file_read",
                description="File read operations",
                match={
                    "node_type": NodeType.CALL_EXPRESSION,
                    "patterns": ["read", "open", "readlines"]
                }
            ),
        ]
    
    def _default_sinks(self) -> List[TaintSink]:
        """Default taint sinks (SQL, command execution, etc.)."""
        return [
            TaintSink(
                id="sql_execution",
                description="SQL query execution",
                match={
                    "node_type": NodeType.CALL_EXPRESSION,
                    "patterns": ["execute", "executemany", "raw", "query", "filter"]
                }
            ),
            TaintSink(
                id="command_execution",
                description="OS command execution",
                match={
                    "node_type": NodeType.CALL_EXPRESSION,
                    "patterns": ["system", "popen", "exec", "eval", "subprocess"]
                }
            ),
            TaintSink(
                id="file_write",
                description="File write operations",
                match={
                    "node_type": NodeType.CALL_EXPRESSION,
                    "patterns": ["write", "writelines"]
                }
            ),
        ]
