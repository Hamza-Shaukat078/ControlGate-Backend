"""
Stage-1 Path Discovery for broad security-relevant candidate paths.
Ranks source -> sink paths using heuristic scoring and returns CodeSlice candidates.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional, Set, Tuple

from app.schemas.graph import SemanticGraph, GraphNode
from app.enums.node_type import NodeType
from app.enums.edge_type import EdgeType
from semantic_engine.query_executor.executor import CodeSlice
from semantic_engine.query_store.loader import QueryStore


@dataclass
class CandidatePath:
    score: float
    source_node: GraphNode
    sink_node: GraphNode
    path_nodes: List[str]
    reason: str


class PathDiscovery:
    # Stores BFS depth, candidate count, and score threshold config
    def __init__(
        self,
        max_depth: int = 50,
        max_candidates: int = 200,
        score_threshold: float = 0.35
    ):
        self.max_depth = max_depth
        self.max_candidates = max_candidates
        self.score_threshold = score_threshold

    # Main entry — runs BFS from all sources to sinks, scores paths, emits CodeSlices
    def discover(
        self,
        graph: SemanticGraph,
        source_code_map: Dict[str, str],
        query_store: QueryStore
    ) -> List[CodeSlice]:
        # Skip path discovery for large graphs — source/sink resolution alone is
        # O(nodes × patterns) and BFS adds little value when cross-file flows span
        # 40+ modules.  Regex detection handles these fixtures instead.
        if len(graph.nodes) > 3000:
            return []

        # High-level flow: collect candidate sources/sinks, traverse paths,
        # score them, then emit CodeSlice objects for downstream analysis.
        node_map = {n.id: n for n in graph.nodes}
        sources, sinks, sanitizers = self._collect_patterns(graph, query_store)
        if not sources or not sinks:
            return []

        adj, edge_map = self._build_adjacency(graph)
        candidates: List[CandidatePath] = []

        for source in sources:
            paths = self._bfs_paths(source.id, {s.id for s in sinks}, adj, node_map)
            for path in paths:
                sink_node = node_map.get(path[-1])
                if not sink_node:
                    continue
                if len(path) < 2:
                    continue
                score, reason = self._score_path(node_map, edge_map, path, source, sink_node, sanitizers)
                if score >= self.score_threshold:
                    candidates.append(CandidatePath(score, source, sink_node, path, reason))

        candidates.sort(key=lambda c: c.score, reverse=True)
        candidates = candidates[: self.max_candidates]

        slices: List[CodeSlice] = []
        for cand in candidates:
            snippet, location = self._extract_snippet(node_map, edge_map, cand.path_nodes, source_code_map)
            slices.append(CodeSlice(
                slice_id=f"DISCOVERY_{cand.source_node.id}_{cand.sink_node.id}",
                rule_id="PATH_DISCOVERY",
                rule_name="Path Discovery",
                owasp="A03",
                cwe=None,
                severity=self._severity_from_score(cand.score),
                confidence="medium",
                source_node_id=cand.source_node.id,
                sink_node_id=cand.sink_node.id,
                path_nodes=cand.path_nodes,
                code_snippet=snippet,
                location=location,
                source_label=cand.source_node.name or cand.source_node.id,
                sink_label=cand.sink_node.name or cand.sink_node.id,
                pattern_type="DFG_FLOW",
                reason=cand.reason
            ))

        return slices

    # Aggregates source/sink patterns from all query rules and graph metadata roles
    def _collect_patterns(
        self,
        graph: SemanticGraph,
        query_store: QueryStore
    ) -> Tuple[List[GraphNode], List[GraphNode], Set[str]]:
        # Sources/sinks come from both query patterns and graph metadata roles.
        sources: List[GraphNode] = []
        sinks: List[GraphNode] = []
        sanitizers: Set[str] = set()

        queries = query_store.get_all_queries()
        source_patterns = []
        sink_patterns = []
        for q in queries:
            source_patterns.extend(q.sources)
            sink_patterns.extend(q.sinks)
            sanitizers.update(q.sanitizers)

        for node in graph.nodes:
            node_label = (node.name or node.id).lower()
            if any(self._label_matches_pattern(node_label, p.lower()) for p in source_patterns):
                sources.append(node)
            if any(self._label_matches_pattern(node_label, p.lower()) for p in sink_patterns):
                sinks.append(node)
            if node.metadata and node.metadata.security_role == "source":
                if node not in sources:
                    sources.append(node)
            if node.metadata and node.metadata.security_role == "sink":
                if node not in sinks:
                    sinks.append(node)

        return sources, sinks, sanitizers

    # Token-aware label matching to avoid partial-word false positives
    def _label_matches_pattern(self, label_lower: str, pattern_lower: str) -> bool:
        # Tokenize labels to avoid accidental substring matches (e.g., "getuser").
        if not pattern_lower:
            return False
        if any(ch in pattern_lower for ch in [".", "(", ")", "'", "\""]):
            return pattern_lower in label_lower
        if pattern_lower.startswith("."):
            pattern_lower = pattern_lower[1:]

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

    # Builds forward adjacency list restricted to data/taint edge types
    def _build_adjacency(self, graph: SemanticGraph) -> Tuple[Dict[str, List[str]], Dict[Tuple[str, str], List[EdgeType]]]:
        # Only traverse edges that plausibly carry data/taint.
        edge_types = {
            EdgeType.DFG_FLOW,
            EdgeType.DFG_PARAM_PASS,
            EdgeType.DFG_RET,
            EdgeType.DFG_INTERP,
            EdgeType.DFG_TEMPLATE,
            EdgeType.TAINT_FLOW,
            EdgeType.DATA_FLOW,
            EdgeType.CALL_GRAPH,
            EdgeType.AUTH_COVERAGE,
            EdgeType.HTTP_ROUTE
        }
        adj: Dict[str, List[str]] = {}
        edge_map: Dict[Tuple[str, str], List[EdgeType]] = {}
        for edge in graph.edges:
            edge_map.setdefault((edge.from_node, edge.to_node), []).append(edge.type)
            if edge.type in edge_types:
                adj.setdefault(edge.from_node, []).append(edge.to_node)
        return adj, edge_map

    # BFS that finds all source→sink paths up to max depth and candidate count
    def _bfs_paths(
        self,
        source_id: str,
        sink_ids: Set[str],
        adj: Dict[str, List[str]],
        node_map: Dict[str, GraphNode]
    ) -> List[List[str]]:
        # BFS with depth, candidate, and hard operation limits to prevent queue explosion.
        MAX_BFS_OPS = 5_000

        paths: List[List[str]] = []
        from collections import deque as _deque
        queue: _deque = _deque([[source_id]])
        visited: set = {source_id}
        bfs_ops = 0

        while queue and len(paths) < self.max_candidates:
            bfs_ops += 1
            if bfs_ops > MAX_BFS_OPS:
                break
            path = queue.popleft()  # O(1) vs list.pop(0) which is O(n)
            if len(path) > self.max_depth:
                continue
            current = path[-1]
            if current in sink_ids:
                paths.append(path)
                continue

            for neighbor in adj.get(current, []):
                if neighbor in path:
                    continue
                if neighbor not in visited or neighbor in sink_ids:
                    visited.add(neighbor)
                    queue.append(path + [neighbor])

        return paths

    # Returns True if a node matches any known sanitizer pattern
    def _is_sanitizer(self, node: GraphNode, sanitizers: Set[str]) -> bool:
        if not sanitizers:
            return False
        label = (node.name or node.id or "").lower()
        code = (node.source_code or "").lower()
        if node.metadata and node.metadata.security_role == "sanitizer":
            return True
        for s in sanitizers:
            s_lower = s.lower()
            if self._label_matches_pattern(label, s_lower):
                return True
            if s_lower in code:
                return True
        return False

    # Computes heuristic score for a path from IIS, proximity, boundaries, and auth gap
    def _score_path(
        self,
        node_map: Dict[str, GraphNode],
        edge_map: Dict[Tuple[str, str], List[EdgeType]],
        path: List[str],
        source: GraphNode,
        sink: GraphNode,
        sanitizers: Set[str]
    ) -> Tuple[float, str]:
        # Heuristic scoring combines path length, boundary crossings, sanitizer hits,
        # and auth coverage indicators to prioritize likely true flows.
        path_len = max(1, len(path))
        iis = 1.0 / (1.0 + path_len)
        boundary_crossings = self._boundary_crossings(node_map, path)
        danger_proximity = 1.0 / (1.0 + (path_len - 1))
        explicit_sanitizers, heuristic_sanitizers = self._sanitizer_hits(node_map, path, sanitizers)
        ambiguity = self._sanitization_ambiguity(explicit_sanitizers, heuristic_sanitizers)
        edge_features = self._edge_features(edge_map, path)
        auth_gap = self._auth_gap(node_map, edge_features, sink)

        score = (
            0.35 * iis +
            0.25 * danger_proximity +
            0.2 * min(1.0, boundary_crossings * 0.2) +
            0.1 * ambiguity +
            0.1 * auth_gap
        )
        if explicit_sanitizers or heuristic_sanitizers:
            score *= max(0.3, 1.0 - (0.15 * explicit_sanitizers) - (0.05 * heuristic_sanitizers))
        reason = (
            f"IIS={iis:.2f}, proximity={danger_proximity:.2f}, "
            f"boundary={boundary_crossings}, ambiguity={ambiguity:.2f}, "
            f"sanitizers={explicit_sanitizers + heuristic_sanitizers}, "
            f"auth_gap={auth_gap:.2f}, edges={edge_features}"
        )
        return score, reason

    # Counts how many file and scope boundaries a path crosses
    def _boundary_crossings(self, node_map: Dict[str, GraphNode], path: List[str]) -> int:
        files = []
        scopes = []
        for node_id in path:
            node = node_map.get(node_id)
            if not node:
                continue
            files.append(node.file)
            scope_id = None
            if node.metadata:
                scope_id = node.metadata.scope_id
            scopes.append(scope_id)
        file_cross = len(set(files)) - 1 if files else 0
        scope_cross = len(set([s for s in scopes if s])) - 1 if scopes else 0
        return max(0, file_cross) + max(0, scope_cross)

    # Counts explicit and heuristic sanitizer nodes on the path
    def _sanitizer_hits(self, node_map: Dict[str, GraphNode], path: List[str], sanitizers: Set[str]) -> Tuple[int, int]:
        explicit_hits = 0
        heuristic_hits = 0
        sanitizer_set = {s.lower() for s in sanitizers}
        for node_id in path:
            node = node_map.get(node_id)
            if not node:
                continue
            label = (node.name or node.id or "").lower()
            code = (node.source_code or "").lower()
            if node.metadata and node.metadata.security_role == "sanitizer":
                explicit_hits += 1
                continue
            if any(self._label_matches_pattern(label, s) or s in code for s in sanitizer_set):
                heuristic_hits += 1
        return explicit_hits, heuristic_hits

    # Returns 0 if explicit sanitizer present, 0.4 if heuristic, 1.0 if none
    def _sanitization_ambiguity(self, explicit_hits: int, heuristic_hits: int) -> float:
        if explicit_hits:
            return 0.0
        if heuristic_hits:
            return 0.4
        return 1.0

    # Counts call-graph, HTTP-route, and auth-coverage edges on the path
    def _edge_features(self, edge_map: Dict[Tuple[str, str], List[EdgeType]], path: List[str]) -> Dict[str, int]:
        counts: Dict[str, int] = {
            "call_graph": 0,
            "http_route": 0,
            "auth_coverage": 0
        }
        for i in range(len(path) - 1):
            types = edge_map.get((path[i], path[i + 1]), [])
            for t in types:
                if t == EdgeType.CALL_GRAPH:
                    counts["call_graph"] += 1
                elif t == EdgeType.HTTP_ROUTE:
                    counts["http_route"] += 1
                elif t == EdgeType.AUTH_COVERAGE:
                    counts["auth_coverage"] += 1
        return counts

    # Estimates how exposed the sink is based on auth coverage and sink type
    def _auth_gap(self, node_map: Dict[str, GraphNode], edge_features: Dict[str, int], sink: GraphNode) -> float:
        if edge_features.get("auth_coverage"):
            return 0.2
        if sink.type in {NodeType.HTTP_ENDPOINT, NodeType.HTTP_RESPONSE}:
            return 0.7
        if sink.metadata and sink.metadata.security_role == "sink":
            return 0.7
        return 0.5

    # Maps numeric score to critical/high/medium/low severity string
    def _severity_from_score(self, score: float) -> str:
        if score >= 0.75:
            return "critical"
        if score >= 0.6:
            return "high"
        if score >= 0.45:
            return "medium"
        return "low"

    # Extracts code snippet and location dict for path nodes with context lines
    def _extract_snippet(
        self,
        node_map: Dict[str, GraphNode],
        edge_map: Dict[Tuple[str, str], List[EdgeType]],
        path: List[str],
        source_code_map: Dict[str, str]
    ) -> Tuple[str, Dict[str, int]]:
        # Build a human-readable snippet with path nodes/edges and line context.
        path_edge_types: List[str] = []
        for i in range(len(path) - 1):
            types = edge_map.get((path[i], path[i + 1]), [])
            if types:
                path_edge_types.append("|".join(sorted({t.value for t in types})))
            else:
                path_edge_types.append("unknown")

        context_nodes = self._expand_context_nodes(node_map, edge_map, path)
        nodes_by_file: Dict[str, Set[int]] = {}
        primary_file = "input"
        for node_id in context_nodes:
            node = node_map.get(node_id)
            if not node:
                continue
            if node.file:
                primary_file = node.file
            if node.line:
                nodes_by_file.setdefault(node.file, set()).add(node.line)

        if not nodes_by_file:
            return "", {"file": primary_file, "start_line": 1, "end_line": 1}

        snippets = []
        snippets.append("PATH NODES:")
        snippets.append(" -> ".join([node_map.get(n).name or n for n in path if node_map.get(n)]))
        if path_edge_types:
            snippets.append("PATH EDGES:")
            snippets.append(" -> ".join(path_edge_types))
        snippets.append("")
        for file_path, line_numbers in nodes_by_file.items():
            code = source_code_map.get(file_path, "")
            # Fallback for single-file analysis where node.file may not match the map key
            # (e.g. node.file=None but map has {"bench.py": code}).
            if not code and source_code_map:
                code = next(iter(source_code_map.values()), "")
            lines = code.split("\n")
            min_line = max(1, min(line_numbers) - 3)
            max_line = min(len(lines), max(line_numbers) + 3)
            snippets.append(f"FILE: {file_path}")
            for i in range(min_line - 1, max_line):
                line_num = i + 1
                prefix = ">>> " if line_num in line_numbers else "    "
                snippets.append(f"{prefix}{line_num:4d} | {lines[i]}")
            snippets.append("")

        return "\n".join(snippets).rstrip(), {
            "file": primary_file,
            "start_line": min(nodes_by_file.get(primary_file, {1})),
            "end_line": max(nodes_by_file.get(primary_file, {1}))
        }

    # Adds neighboring nodes (parent, children, call edges) around path nodes
    def _expand_context_nodes(
        self,
        node_map: Dict[str, GraphNode],
        edge_map: Dict[Tuple[str, str], List[EdgeType]],
        path: List[str]
    ) -> Set[str]:
        context: Set[str] = set(path)
        for node_id in path:
            # Include immediate neighbors for semantic context
            for (from_node, to_node), types in edge_map.items():
                if from_node == node_id or to_node == node_id:
                    if any(t in {EdgeType.CALL_GRAPH, EdgeType.DFG_PARAM_PASS, EdgeType.DFG_RET, EdgeType.AUTH_COVERAGE, EdgeType.HTTP_ROUTE} for t in types):
                        context.add(from_node)
                        context.add(to_node)
            node = node_map.get(node_id)
            if not node:
                continue
            if node.parent_id:
                context.add(node.parent_id)
            for child_id in node.child_ids:
                context.add(child_id)
        return context
