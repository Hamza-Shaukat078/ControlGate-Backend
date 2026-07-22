"""
Query Executor - Pattern Matching Engine
Executes static security queries against unified code property graph.
Finds source→sink paths, extracts minimal code slices for LLM classification.
"""
import re
import os
from typing import List, Dict, Set, Optional, Tuple
from dataclasses import dataclass
from collections import defaultdict, deque
import logging

from app.schemas.graph import SemanticGraph, GraphNode, GraphEdge
from app.enums.node_type import NodeType
from app.enums.edge_type import EdgeType
from semantic_engine.query_store.loader import QueryRule

logger = logging.getLogger(__name__)


@dataclass
class CodeSlice:
    """Represents a minimal code slice containing vulnerability evidence."""
    slice_id: str
    rule_id: str
    rule_name: str
    owasp: str
    cwe: Optional[str]
    severity: str
    confidence: str
    
    # Path information
    source_node_id: str
    sink_node_id: str
    path_nodes: List[str]  # List of node IDs in path
    
    # Code context
    code_snippet: str
    location: Dict  # {file, start_line, end_line}
    
    # Evidence
    source_label: str
    sink_label: str
    pattern_type: str  # DFG_FLOW, TAINT_FLOW, CFG_NEXT, etc.
    reason: str  # Human-readable explanation


class QueryExecutor:
    """
    Executes security queries against code property graph.
    Finds source→sink paths and extracts minimal slices.
    """
    
    def __init__(self, max_path_length: int = 50, max_paths_per_rule: int = 100):
        """
        Initialize Query Executor.
        
        Args:
            max_path_length: Maximum path length to search
            max_paths_per_rule: Maximum paths to return per rule
        """
        self.max_path_length = max_path_length
        self.max_paths_per_rule = max_paths_per_rule
    
    def execute_query(
        self,
        graph: SemanticGraph,
        query: QueryRule,
        source_code: str,
        source_code_map: Optional[Dict[str, str]] = None
    ) -> List[CodeSlice]:
        """
        Execute a single query rule against the graph.
        
        Args:
            graph: Unified code property graph
            query: Security detection rule
            source_code: Original source code for snippet extraction
        
        Returns:
            List of detected code slices (potential vulnerabilities)
        """
        logger.debug(f"Executing query: {query.rule_id}")

        # Regex/setting-based rules (no source/sink required).
        regex_slices = self._execute_regex_patterns(query, source_code, source_code_map)

        # Step 1: Resolve source nodes from query patterns.
        source_nodes = self._resolve_sources(graph, query)
        if not source_nodes:
            if regex_slices:
                return regex_slices
            logger.debug(f"No source nodes found for {query.rule_id}")
            return []
        
        # Step 2: Resolve sink nodes from query patterns.
        sink_nodes = self._resolve_sinks(graph, query)
        if not sink_nodes:
            if regex_slices:
                return regex_slices
            logger.debug(f"No sink nodes found for {query.rule_id}")
            return []
        
        logger.debug(f"Found {len(source_nodes)} sources, {len(sink_nodes)} sinks")
        
        # Step 3: For each pattern type, find paths source -> sink.
        slices = []
        for pattern in query.patterns:
            # Guard-aware patterns (e.g., "DFG_FLOW AND NOT exists(auth_check)")
            if "AND NOT exists" in pattern and query.required_guards:
                if self._has_required_guards(graph, query.required_guards):
                    continue
            paths = self._find_paths(
                graph, source_nodes, sink_nodes, pattern, query
            )
            
            # Step 4: Extract slices from paths
            for path in paths[:self.max_paths_per_rule]:
                slice_obj = self._extract_slice(
                    graph, path, query, pattern, source_code, source_code_map
                )
                if slice_obj:
                    slices.append(slice_obj)
        
        # Step 5: Deduplicate and rank slices (prefer stronger evidence).
        slices = self._deduplicate_slices(slices + regex_slices)
        
        logger.info(f"Query {query.rule_id}: found {len(slices)} potential issues")
        return slices

    def _execute_regex_patterns(
        self,
        query: QueryRule,
        source_code: str,
        source_code_map: Optional[Dict[str, str]]
    ) -> List[CodeSlice]:
        """Execute regex/dangerous-setting based rules."""
        # Combine all regex-like patterns into a single list to scan raw code.
        patterns = list(query.regex_patterns or [])
        patterns += list(query.dangerous_settings or [])
        patterns += list(query.dangerous_values or [])
        # Support simple pattern tokens like CALL(md5), ASSIGNMENT(debug)
        for p in query.patterns:
            if p.startswith("CALL(") and p.endswith(")"):
                token = p[len("CALL("):-1]
                patterns.append(f"{token}\\s*\\(")
            if p.startswith("ASSIGNMENT(") and p.endswith(")"):
                token = p[len("ASSIGNMENT("):-1]
                patterns.append(f"{token}\\s*=\\s*")
            if p.startswith("LITERAL(") and p.endswith(")"):
                token = p[len("LITERAL("):-1]
                patterns.append(f"['\"{token}'\"]")

        if not patterns:
            return []

        # Default to a single "input" file unless a file map is provided.
        files = {"input": source_code}
        if source_code_map:
            files = source_code_map

        file_filters = getattr(query, "file_patterns", None)
        if file_filters:
            compiled_filters = []
            for fp in file_filters:
                try:
                    compiled_filters.append(re.compile(fp))
                except re.error:
                    continue
        else:
            compiled_filters = []

        slices: List[CodeSlice] = []
        for file_path, code in files.items():
            if compiled_filters:
                normalized = (file_path or "").replace("\\", "/")
                if not any(rx.search(normalized) for rx in compiled_filters):
                    continue
            lines = code.split("\n")
            for pattern in patterns:
                try:
                    for match in re.finditer(pattern, code):
                        line_num = code[:match.start()].count("\n") + 1
                        snippet = self._extract_code_snippet(code, {line_num}, context=2)
                        slice_id = f"{query.rule_id}_REGEX_{file_path}_{line_num}"
                        slices.append(CodeSlice(
                            slice_id=slice_id,
                            rule_id=query.rule_id,
                            rule_name=query.name,
                            owasp=query.owasp,
                            cwe=query.cwe,
                            severity=query.severity,
                            confidence=query.confidence,
                            source_node_id="regex_source",
                            sink_node_id="regex_sink",
                            path_nodes=[],
                            code_snippet=snippet,
                            location={"file": file_path, "start_line": line_num, "end_line": line_num},
                            source_label="regex",
                            sink_label="regex",
                            pattern_type="REGEX",
                            reason=f"Matched regex pattern: {pattern}"
                        ))
                except re.error:
                    continue

        return slices

    def _has_required_guards(self, graph: SemanticGraph, guards: List[str]) -> bool:
        """Return True if guard patterns are found in the graph."""
        # Used for rules that should be skipped when auth guards exist.
        guard_set = {g.lower() for g in guards}
        for node in graph.nodes:
            label = (node.name or node.id or "").lower()
            code = (node.source_code or "").lower()
            if any(g in label or g in code for g in guard_set):
                return True
        return False
    
    def _resolve_sources(
        self, graph: SemanticGraph, query: QueryRule
    ) -> List[GraphNode]:
        """
        Find all source nodes matching query criteria.
        
        Args:
            graph: Code property graph
            query: Query rule with source patterns
        
        Returns:
            List of matching source nodes
        """
        sources = []
        
        for node in graph.nodes:
            if not self._language_allows_node(node, query):
                continue
            # Check if node matches any source pattern
            for source_pattern in query.sources:
                if self._matches_pattern(node, source_pattern):
                    sources.append(node)
                    break
        
        return sources
    
    def _resolve_sinks(
        self, graph: SemanticGraph, query: QueryRule
    ) -> List[GraphNode]:
        """
        Find all sink nodes matching query criteria.
        
        Args:
            graph: Code property graph
            query: Query rule with sink patterns
        
        Returns:
            List of matching sink nodes
        """
        sinks = []
        
        for node in graph.nodes:
            if not self._language_allows_node(node, query):
                continue
            # Check if node matches any sink pattern
            for sink_pattern in query.sinks:
                if self._matches_sink_pattern(node, sink_pattern):
                    sinks.append(node)
                    break
        
        return sinks
    
    def _matches_pattern(self, node: GraphNode, pattern: str) -> bool:
        """
        Check if a node matches a pattern string.
        
        Args:
            node: Graph node to check
            pattern: Pattern string (e.g., 'request.GET', 'execute', 'os.system')
        
        Returns:
            True if node matches pattern
        """
        # Get node label (use name or fallback to id).
        node_label = node.name or node.id
        label_lower = node_label.lower()
        pattern_lower = pattern.lower()
        
        # Special pattern: PARAMETER matches any function parameter.
        if pattern == 'PARAMETER' and node.type == NodeType.PARAMETER:
            name = (node.name or "").lower()
            if node.metadata and getattr(node.metadata, "security_role", None) == "source":
                return True
            common = {
                "input", "user_input", "data", "payload", "body", "query", "params",
                "username", "password", "token", "auth", "user", "userid", "id"
            }
            return name in common
        
        # Token-aware match to avoid false positives (e.g., exec vs execute).
        if self._label_matches_pattern(label_lower, pattern_lower):
            return True
        
        # Check node type for common patterns.
        if pattern in ['input', 'user_input'] and node.type == NodeType.PARAMETER:
            return True
        
        # Subscripts like sys.argv are common sources.
        if node.type == NodeType.SUBSCRIPT and pattern_lower in label_lower:
            return True
        
        if pattern in ['execute', 'query'] and node.type == NodeType.CALL_EXPRESSION:
            return self._label_matches_pattern(label_lower, pattern_lower)
        
        # Check value field if available.
        if hasattr(node, 'value') and node.value:
            if pattern_lower in str(node.value).lower():
                return True
        
        # Check metadata if available.
        if hasattr(node, 'metadata') and node.metadata:
            metadata_str = str(node.metadata).lower()
            if pattern_lower in metadata_str:
                return True
        
        return False

    def _matches_sink_pattern(self, node: GraphNode, pattern: str) -> bool:
        """
        Stricter sink matching to reduce false positives.
        Only checks node label/type and avoids metadata/value substring matches.
        """
        node_label = node.name or node.id
        label_lower = node_label.lower()
        pattern_lower = pattern.lower()

        if pattern == 'PARAMETER' and node.type == NodeType.PARAMETER:
            return True

        if self._label_matches_pattern(label_lower, pattern_lower):
            return True

        if node.type == NodeType.SUBSCRIPT and pattern_lower in label_lower:
            return True

        if pattern in ['execute', 'query'] and node.type == NodeType.CALL_EXPRESSION:
            return self._label_matches_pattern(label_lower, pattern_lower)

        return False

    def _language_allows_node(self, node: GraphNode, query: QueryRule) -> bool:
        # Filter nodes by rule language list using file extensions.
        languages = getattr(query, "languages", None)
        if not languages:
            return True
        file_path = (node.file or "").lower()
        if not file_path:
            return True
        if file_path.endswith(".py"):
            return "python" in [l.lower() for l in languages]
        if file_path.endswith(".js"):
            return "javascript" in [l.lower() for l in languages]
        if file_path.endswith(".ts"):
            return "typescript" in [l.lower() for l in languages]
        if file_path.endswith(".tsx"):
            return "typescript" in [l.lower() for l in languages] or "javascript" in [l.lower() for l in languages]
        return True

    def _label_matches_pattern(self, label_lower: str, pattern_lower: str) -> bool:
        """
        Token-aware matching for node labels.
        Avoids substring matches like exec vs execute.
        """
        if not pattern_lower:
            return False

        # Exact substring match for fully-qualified patterns.
        if any(ch in pattern_lower for ch in [".", "(", ")", "'", "\""]):
            return pattern_lower in label_lower

        # Strip leading dots like ".get".
        if pattern_lower.startswith("."):
            pattern_lower = pattern_lower[1:]

        # Tokenize on non-alphanumerics to avoid partial matches.
        tokens = []
        current = []
        for ch in label_lower:
            if ch.isalnum() or ch == "_":
                current.append(ch)
            else:
                if current:
                    tokens.append("".join(current))
                    current = []
        if current:
            tokens.append("".join(current))

        return pattern_lower in tokens
    
    def _find_paths(
        self,
        graph: SemanticGraph,
        sources: List[GraphNode],
        sinks: List[GraphNode],
        pattern_type: str,
        query: QueryRule
    ) -> List[List[str]]:
        """
        Find all paths from sources to sinks matching pattern.
        
        Args:
            graph: Code property graph
            sources: Source nodes
            sinks: Sink nodes
            pattern_type: Path pattern (DFG_FLOW, TAINT_FLOW, CFG_NEXT)
            query: Query rule (for sanitizer checking)
        
        Returns:
            List of paths (each path is list of node IDs)
        """
        # Build adjacency list for specified edge types.
        edge_types = self._get_edge_types_for_pattern(pattern_type)
        adj_list = self._build_adjacency_list(graph, edge_types)
        
        # Sanitizers are checked later to reduce confidence.
        sanitizers = set(query.sanitizers)
        
        # Find paths using BFS.
        all_paths = []
        source_ids = {s.id for s in sources}
        sink_ids = {s.id for s in sinks}
        
        for source in sources:
            paths = self._bfs_paths(
                source.id, sink_ids, adj_list, graph, sanitizers
            )
            all_paths.extend(paths)
        
        return all_paths
    
    def _get_edge_types_for_pattern(self, pattern_type: str) -> List[EdgeType]:
        """Map pattern type to edge types."""
        if "DFG_FLOW" in pattern_type:
            return [
                EdgeType.DFG_FLOW, 
                EdgeType.TAINT_FLOW, 
                EdgeType.DFG_INTERP,      # Variable → f-string/template
                EdgeType.DFG_PARAM_PASS,  # Argument → parameter
                EdgeType.DFG_RET,         # Return → caller
                EdgeType.DFG_ATTR,        # Object → attribute
                EdgeType.DATA_FLOW,
                EdgeType.CALL_GRAPH,
                EdgeType.DFG_TEMPLATE
            ]
        elif "TAINT_FLOW" in pattern_type:
            return [
                EdgeType.TAINT_FLOW, 
                EdgeType.DFG_FLOW,
                EdgeType.DFG_INTERP,
                EdgeType.DFG_PARAM_PASS
            ]
        elif "CFG_NEXT" in pattern_type:
            return [EdgeType.CFG_NEXT]
        elif pattern_type == "ANY":
            return [
                EdgeType.DFG_FLOW, 
                EdgeType.TAINT_FLOW, 
                EdgeType.CFG_NEXT,
                EdgeType.DFG_INTERP,
                EdgeType.DFG_PARAM_PASS
            ]
        else:
            logger.warning(f"Unknown pattern type: {pattern_type}, using DFG_FLOW")
            return [
                EdgeType.DFG_FLOW,
                EdgeType.DFG_INTERP,
                EdgeType.DFG_PARAM_PASS
            ]
    
    def _build_adjacency_list(
        self, graph: SemanticGraph, edge_types: List[EdgeType]
    ) -> Dict[str, List[str]]:
        """Build adjacency list for specified edge types."""
        adj = defaultdict(list)
        
        for edge in graph.edges:
            if edge.type in edge_types:
                adj[edge.from_node].append(edge.to_node)
        
        return adj
    
    def _bfs_paths(
        self,
        start: str,
        targets: Set[str],
        adj_list: Dict[str, List[str]],
        graph: SemanticGraph,
        sanitizers: Set[str]
    ) -> List[List[str]]:
        """
        BFS to find all paths from start to any target.
        
        Args:
            start: Start node ID
            targets: Set of target node IDs
            adj_list: Adjacency list
            graph: Full graph (for sanitizer checking)
            sanitizers: Set of sanitizer patterns
        
        Returns:
            List of paths (node ID lists)
        """
        # Adaptive BFS cap: give small graphs (few adjacency entries) more exploration
        # budget — they're fast and need deeper traversal to find taint paths.
        # Large graphs get a tighter cap to keep wall-clock time bounded.
        adj_total = sum(len(v) for v in adj_list.values())
        if adj_total < 1_000:
            MAX_BFS_OPS = 30_000   # small fixture, ≤ ~300 ms/rule in thread
        elif adj_total < 5_000:
            MAX_BFS_OPS = 15_000   # medium fixture
        else:
            MAX_BFS_OPS = 5_000    # large fixture, keeps thread task < ~5 s

        paths = []
        queue = deque([(start, [start])])
        # Track per-node reachability instead of full path tuples — O(n) not O(n*L).
        visited: Set[str] = {start}
        bfs_ops = 0

        node_map = {n.id: n for n in graph.nodes}

        while queue and len(paths) < self.max_paths_per_rule:
            bfs_ops += 1
            if bfs_ops > MAX_BFS_OPS:
                break
            current, path = queue.popleft()

            # Check if we reached a target.
            if current in targets:
                paths.append(path)
                continue

            # Check path length limit.
            if len(path) >= self.max_path_length:
                continue

            # Explore neighbors.
            for neighbor in adj_list.get(current, []):
                if neighbor in path:  # Avoid cycles within the current path
                    continue

                new_path = path + [neighbor]
                # Only enqueue if this edge would bring us closer to a sink or
                # is a novel node — avoids re-expanding the same subtree.
                if neighbor not in visited or neighbor in targets:
                    visited.add(neighbor)
                    queue.append((neighbor, new_path))

        return paths
    
    def _is_sanitizer(self, node: GraphNode, sanitizers: Set[str]) -> bool:
        """Check if node represents a sanitizer function."""
        if not sanitizers:
            return False
        node_label = (node.name or node.id or "").lower()
        node_code = (node.source_code or "").lower()
        if node.metadata and getattr(node.metadata, "security_role", None) == "sanitizer":
            return True
        for sanitizer in sanitizers:
            sanitizer_lower = sanitizer.lower()
            if self._label_matches_pattern(node_label, sanitizer_lower):
                return True
            if sanitizer_lower in node_code:
                return True
        return False
    
    def _extract_slice(
        self,
        graph: SemanticGraph,
        path: List[str],
        query: QueryRule,
        pattern_type: str,
        source_code: str,
        source_code_map: Optional[Dict[str, str]] = None
    ) -> Optional[CodeSlice]:
        """
        Extract minimal code slice from path.
        
        Args:
            graph: Code property graph
            path: Path of node IDs
            query: Query rule
            pattern_type: Pattern type used
            source_code: Original source code
        
        Returns:
            CodeSlice object or None
        """
        if not path or len(path) < 2:
            return None
        
        node_map = {n.id: n for n in graph.nodes}
        
        # Get source and sink nodes
        source_node = node_map.get(path[0])
        sink_node = node_map.get(path[-1])
        
        if not source_node or not sink_node:
            return None
        
        # Extract line numbers from path nodes.
        line_numbers = set()
        for node_id in path:
            node = node_map.get(node_id)
            if node and hasattr(node, 'line') and node.line:
                line_numbers.add(node.line)
        
        if not line_numbers:
            # Fallback: use source/sink lines
            if hasattr(source_node, 'line') and source_node.line:
                line_numbers.add(source_node.line)
            if hasattr(sink_node, 'line') and sink_node.line:
                line_numbers.add(sink_node.line)
        
        # Determine file and resolve source for snippet extraction.
        file_path = (source_node.file or sink_node.file or "input")
        file_source = self._resolve_file_source(file_path, source_code, source_code_map)

        # Extract code snippet with context (+/-3 lines).
        snippet = self._extract_code_snippet(file_source, line_numbers, context=3)
        if not snippet and (source_node.source_code or sink_node.source_code):
            # Fallback: use node source_code if we couldn't map lines to file
            parts = []
            if source_node.source_code:
                parts.append(f"SOURCE: {source_node.source_code}")
            if sink_node.source_code:
                parts.append(f"SINK: {sink_node.source_code}")
            snippet = "\n".join(parts).strip()
        
        # Determine location from line numbers.
        min_line = min(line_numbers) if line_numbers else 1
        max_line = max(line_numbers) if line_numbers else 1
        
        location = {
            "file": file_path,
            "start_line": min_line,
            "end_line": max_line
        }
        
        # Generate reason string, include sanitizer evidence.
        sanitizer_hits = self._count_sanitizers_in_path(path, graph, set(query.sanitizers))
        reason = self._generate_reason(source_node, sink_node, query, pattern_type)
        if sanitizer_hits:
            reason += f" Sanitizers observed: {sanitizer_hits}."
        
        # Create slice payload.
        slice_id = f"{query.rule_id}_{source_node.id}_{sink_node.id}"
        
        # Lower confidence/severity when sanitizers are on the path.
        confidence = query.confidence
        severity = query.severity
        if sanitizer_hits:
            confidence = "low"
            if severity.lower() in {"critical", "high"}:
                severity = "medium"

        return CodeSlice(
            slice_id=slice_id,
            rule_id=query.rule_id,
            rule_name=query.name,
            owasp=query.owasp,
            cwe=query.cwe,
            severity=severity,
            confidence=confidence,
            source_node_id=source_node.id,
            sink_node_id=sink_node.id,
            path_nodes=path,
            code_snippet=snippet,
            location=location,
            source_label=source_node.name or source_node.id,
            sink_label=sink_node.name or sink_node.id,
            pattern_type=pattern_type,
            reason=reason
        )

    def _count_sanitizers_in_path(
        self,
        path: List[str],
        graph: SemanticGraph,
        sanitizers: Set[str]
    ) -> int:
        node_map = {n.id: n for n in graph.nodes}
        hits = 0
        for node_id in path:
            node = node_map.get(node_id)
            if not node:
                continue
            if self._is_sanitizer(node, sanitizers):
                hits += 1
        return hits
    
    def _extract_code_snippet(
        self, source_code: str, line_numbers: Set[int], context: int = 3
    ) -> str:
        """
        Extract code snippet with context lines.
        
        Args:
            source_code: Full source code
            line_numbers: Set of line numbers to include
            context: Number of context lines before/after
        
        Returns:
            Code snippet string
        """
        lines = source_code.split('\n')
        
        if not line_numbers:
            return ""
        
        min_line = max(1, min(line_numbers) - context)
        max_line = min(len(lines), max(line_numbers) + context)
        
        snippet_lines = []
        for i in range(min_line - 1, max_line):
            line_num = i + 1
            prefix = ">>> " if line_num in line_numbers else "    "
            snippet_lines.append(f"{prefix}{line_num:4d} | {lines[i]}")
        
        return "\n".join(snippet_lines)

    def _resolve_file_source(
        self,
        file_path: str,
        fallback_source: str,
        source_code_map: Optional[Dict[str, str]] = None
    ) -> str:
        """
        Resolve file source from source_code_map or disk, with robust path matching.
        """
        if source_code_map:
            # Exact match.
            if file_path in source_code_map:
                return source_code_map[file_path]

            # Normalized slash match.
            norm_path = file_path.replace("\\", "/")
            if norm_path in source_code_map:
                return source_code_map[norm_path]

            # Suffix match (handle relative vs absolute).
            for key, code in source_code_map.items():
                key_norm = key.replace("\\", "/")
                if key_norm.endswith(norm_path):
                    return code

        # Disk fallback if file exists.
        try:
            if file_path and os.path.exists(file_path):
                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    return f.read()
        except Exception:
            pass

        return fallback_source
    
    def _generate_reason(
        self,
        source_node: GraphNode,
        sink_node: GraphNode,
        query: QueryRule,
        pattern_type: str
    ) -> str:
        """Generate human-readable explanation."""
        source_label = source_node.name or source_node.id
        sink_label = sink_node.name or sink_node.id
        
        return (
            f"Potential {query.name}: "
            f"User input from '{source_label}' "
            f"flows to dangerous sink '{sink_label}' "
            f"via {pattern_type} without sanitization."
        )
    
    def _deduplicate_slices(self, slices: List[CodeSlice]) -> List[CodeSlice]:
        """
        Remove duplicate slices (same rule + sink + location) and rank by certainty.
        Prefer "sure" evidence without multiplying near-identical findings.
        """
        best_by_key = {}

        def confidence_score(conf: str) -> float:
            scores = {"high": 0.9, "medium": 0.6, "low": 0.3}
            return scores.get((conf or "").lower(), 0.5)

        def rank(s: CodeSlice) -> tuple:
            severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
            sev = severity_order.get((s.severity or "").lower(), 4)
            conf = confidence_score(s.confidence)
            has_snippet = 1 if (s.code_snippet or "").strip() else 0
            is_dfg = 1 if "DFG_FLOW" in (s.pattern_type or "") else 0
            path_len = len(s.path_nodes or [])
            # Higher is better except severity/path_len which are inverted via negatives
            return (is_dfg, has_snippet, conf, -sev, -path_len)

        for slice_obj in slices:
            location = slice_obj.location or {}
            key = (
                slice_obj.rule_id,
                slice_obj.sink_label,
                location.get("file"),
                location.get("start_line"),
                location.get("end_line")
            )

            existing = best_by_key.get(key)
            if not existing or rank(slice_obj) > rank(existing):
                best_by_key[key] = slice_obj

        unique_slices = list(best_by_key.values())

        # Sort by severity (most severe first), then confidence.
        severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
        unique_slices.sort(
            key=lambda s: (
                severity_order.get((s.severity or "").lower(), 4),
                -confidence_score(s.confidence)
            )
        )

        return unique_slices
