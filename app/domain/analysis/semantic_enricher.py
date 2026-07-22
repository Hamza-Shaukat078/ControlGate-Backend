"""
Semantic graph enrichment passes for Vulcan's custom CPG.

The parser owns syntax and scope extraction. This module appends higher-level
semantic edges without changing the graph schema, so visualization and query
consumers keep the same node/edge contract.
"""

from __future__ import annotations

import re
from collections import defaultdict
from typing import Iterable

from app.enums.edge_type import EdgeType
from app.enums.node_type import NodeType
from app.schemas.graph import GraphEdge, GraphNode, SemanticGraph


class SemanticGraphEnricher:
    """Append CPG-style semantic edges to an existing SemanticGraph."""

    HTTP_METHODS = {"get", "post", "put", "patch", "delete", "options", "head", "route"}
    AUTH_KEYWORDS = {
        "login_required", "permission_required", "authorize", "authenticated",
        "is_authenticated", "jwt_required", "require_auth", "has_permission",
        "requireauth", "permission", "role_required", "roles_required",
        "can_access", "authmiddleware"
    }
    SANITIZER_KEYWORDS = {
        "escape", "sanitize", "clean", "validate", "validator", "bleach",
        "markupsafe", "quote", "param", "parameterized"
    }
    SQL_METHODS = {
        "execute", "executemany", "raw", "query", "filter", "filter_by",
        "find", "find_one", "aggregate", "update", "delete", "insert"
    }
    ORM_HINTS = {
        "objects.", "session.", "db.session", "query.", ".filter", ".filter_by",
        ".find(", ".find_one(", ".aggregate(", ".execute(", ".raw("
    }
    SQL_WORDS = re.compile(r"\b(select|insert|update|delete|drop|alter|from|where)\b", re.I)
    CALL_TYPES = {
        NodeType.CALL_EXPRESSION, NodeType.EXTERNAL_CALL, NodeType.SYSTEM_CALL,
        NodeType.EVAL_CALL, NodeType.ORM_QUERY
    }

    def __init__(self, graph: SemanticGraph):
        self.graph = graph
        self.node_map: dict[str, GraphNode] = {node.id: node for node in graph.nodes}
        self.children: dict[str, list[str]] = defaultdict(list)
        self.parents: dict[str, list[str]] = defaultdict(list)
        self.existing: set[tuple[str, str, EdgeType]] = set()
        for edge in graph.edges:
            self.existing.add((edge.from_node, edge.to_node, edge.type))
            if edge.type == EdgeType.AST_CHILD:
                self.children[edge.from_node].append(edge.to_node)
                self.parents[edge.to_node].append(edge.from_node)

    def enrich(self) -> SemanticGraph:
        self._emit_module_edges()
        self._emit_control_flow_edges()
        self._emit_call_edges()
        self._emit_data_flow_edges()
        self._emit_taint_edges()
        self._emit_http_auth_edges()
        self._emit_database_edges()
        return self.graph

    def _add_edge(
        self,
        from_node: str,
        to_node: str,
        edge_type: EdgeType,
        metadata: dict | None = None,
        label: str | None = None,
        order: int | None = None,
    ) -> None:
        if not from_node or not to_node:
            return
        if from_node == to_node and edge_type not in {EdgeType.TAINT_SOURCE, EdgeType.TAINT_SINK}:
            return
        key = (from_node, to_node, edge_type)
        if key in self.existing:
            return
        edge = GraphEdge(**{"from": from_node, "to": to_node, "type": edge_type})
        edge.metadata = metadata or {}
        edge.label = label
        edge.order = order
        self.graph.edges.append(edge)
        self.existing.add(key)

    def _descendants(self, node_id: str) -> list[GraphNode]:
        found: list[GraphNode] = []
        stack = list(self.children.get(node_id, []))
        seen: set[str] = set()
        while stack:
            current = stack.pop()
            if current in seen:
                continue
            seen.add(current)
            node = self.node_map.get(current)
            if node:
                found.append(node)
            stack.extend(self.children.get(current, []))
        return found

    def _nearest_ancestor(self, node_id: str, types: Iterable[NodeType]) -> GraphNode | None:
        wanted = set(types)
        stack = list(self.parents.get(node_id, []))
        seen: set[str] = set()
        while stack:
            current = stack.pop()
            if current in seen:
                continue
            seen.add(current)
            node = self.node_map.get(current)
            if node and node.type in wanted:
                return node
            stack.extend(self.parents.get(current, []))
        return None

    def _emit_module_edges(self) -> None:
        for node in self.graph.nodes:
            if node.type != NodeType.FILE:
                continue
            for child_id in self.children.get(node.id, []):
                child = self.node_map.get(child_id)
                if child and child.type in {NodeType.FUNCTION, NodeType.ASYNC_FUNCTION, NodeType.CLASS, NodeType.ASSIGNMENT}:
                    self._add_edge(node.id, child.id, EdgeType.DEFINES, {"graph_type": "MODULE", "relationship": "file_defines"})
        by_symbol = defaultdict(list)
        for node in self.graph.nodes:
            if node.type in {NodeType.IDENTIFIER, NodeType.PARAMETER, NodeType.ASSIGNMENT, NodeType.VARIABLE} and node.name:
                by_symbol[node.name].append(node)
        for refs in by_symbol.values():
            definitions = [n for n in refs if n.type in {NodeType.PARAMETER, NodeType.ASSIGNMENT, NodeType.VARIABLE}]
            uses = [n for n in refs if n.type == NodeType.IDENTIFIER]
            for definition in definitions:
                for use in uses:
                    if definition.file == use.file and definition.line <= use.line:
                        self._add_edge(definition.id, use.id, EdgeType.USES, {"graph_type": "MODULE", "symbol": definition.name})

    def _emit_control_flow_edges(self) -> None:
        control_types = {
            NodeType.IF_STATEMENT, NodeType.FOR_STATEMENT, NodeType.WHILE_STATEMENT,
            NodeType.TRY_STATEMENT, NodeType.EXCEPT_HANDLER, NodeType.TRY,
            NodeType.EXCEPT, NodeType.RAISE
        }
        for parent_id, child_ids in self.children.items():
            ordered = [self.node_map[c] for c in child_ids if c in self.node_map]
            ordered.sort(key=lambda n: (n.line, n.column))
            executable = [
                n for n in ordered
                if n.type not in {NodeType.IDENTIFIER, NodeType.LITERAL, NodeType.PARAMETER}
            ]
            for left, right in zip(executable, executable[1:]):
                self._add_edge(left.id, right.id, EdgeType.CFG_NEXT, {"graph_type": "CFG"}, order=left.line)

            for node in executable:
                if node.type == NodeType.IF_STATEMENT:
                    branch_nodes = [n for n in self._descendants(node.id) if n.line > node.line]
                    branch_nodes.sort(key=lambda n: (n.line, n.column))
                    if branch_nodes:
                        self._add_edge(node.id, branch_nodes[0].id, EdgeType.CFG_BRANCH_TRUE, {"graph_type": "CFG"}, label="true")
                    following = [n for n in ordered if n.line > node.line and n.id != node.id]
                    if following:
                        self._add_edge(node.id, following[-1].id, EdgeType.CFG_BRANCH_FALSE, {"graph_type": "CFG"}, label="false")
                elif node.type in {NodeType.FOR_STATEMENT, NodeType.WHILE_STATEMENT}:
                    body = [n for n in self._descendants(node.id) if n.line > node.line]
                    body.sort(key=lambda n: (n.line, n.column))
                    if body:
                        self._add_edge(node.id, body[0].id, EdgeType.CFG_LOOP_ENTRY, {"graph_type": "CFG"}, label="loop")
                        self._add_edge(body[-1].id, node.id, EdgeType.CFG_NEXT, {"graph_type": "CFG", "loop_back": True})
                    following = [n for n in ordered if n.line > node.line]
                    if following:
                        self._add_edge(node.id, following[-1].id, EdgeType.CFG_LOOP_EXIT, {"graph_type": "CFG"}, label="exit")
                elif node.type in {NodeType.TRY_STATEMENT, NodeType.TRY, NodeType.RAISE, NodeType.EXCEPT_HANDLER, NodeType.EXCEPT}:
                    for target in [n for n in self._descendants(node.id) if n.type in {NodeType.EXCEPT_HANDLER, NodeType.EXCEPT}]:
                        self._add_edge(node.id, target.id, EdgeType.CFG_EXCEPTION, {"graph_type": "CFG"}, label="exception")

        for node in self.graph.nodes:
            if node.type in control_types:
                parent = self._nearest_ancestor(node.id, {NodeType.FUNCTION, NodeType.ASYNC_FUNCTION, NodeType.METHOD})
                if parent:
                    self._add_edge(parent.id, node.id, EdgeType.CONTROL_FLOW, {"graph_type": "CFG", "control": node.type.value})

    def _emit_call_edges(self) -> None:
        functions = {n.id for n in self.graph.nodes if n.type in {NodeType.FUNCTION, NodeType.ASYNC_FUNCTION, NodeType.METHOD, NodeType.ARROW_FUNCTION}}
        for call in [n for n in self.graph.nodes if n.type in self.CALL_TYPES]:
            args = self._call_args(call.id)
            for i, arg in enumerate(args):
                self._add_edge(call.id, arg.id, EdgeType.CALL_ARG, {"graph_type": "CALL", "arg_position": i}, order=i)
        for edge in list(self.graph.edges):
            if edge.type != EdgeType.CALL_GRAPH or edge.to_node not in functions:
                continue
            returns = [n for n in self._descendants(edge.to_node) if n.type == NodeType.RETURN]
            for ret in returns:
                self._add_edge(edge.to_node, ret.id, EdgeType.CALL_RETURN, {"graph_type": "CALL", "callee": self.node_map.get(edge.to_node).name})

    def _call_args(self, call_id: str) -> list[GraphNode]:
        args: list[GraphNode] = []
        for child_id in self.children.get(call_id, []):
            child = self.node_map.get(child_id)
            if not child:
                continue
            if child.type in {NodeType.IDENTIFIER, NodeType.MEMBER_ACCESS} and child.name and child.name in (self.node_map[call_id].name or ""):
                continue
            if child.type in {
                NodeType.IDENTIFIER, NodeType.PARAMETER, NodeType.LITERAL, NodeType.EXPRESSION,
                NodeType.MEMBER_ACCESS, NodeType.ATTRIBUTE_ACCESS, NodeType.CALL_EXPRESSION,
                NodeType.FSTRING, NodeType.TEMPLATE_LITERAL, NodeType.STRING_CONCAT,
                NodeType.STRING_FORMAT, NodeType.STRING_PERCENT
            }:
                args.append(child)
        return args

    def _emit_data_flow_edges(self) -> None:
        for node in self.graph.nodes:
            descendants = self._descendants(node.id)
            leaves = [n for n in descendants if n.type in {NodeType.IDENTIFIER, NodeType.PARAMETER, NodeType.LITERAL, NodeType.MEMBER_ACCESS}]
            if node.type == NodeType.FSTRING:
                for leaf in leaves:
                    if leaf.type != NodeType.LITERAL:
                        self._add_edge(leaf.id, node.id, EdgeType.DFG_INTERP, {"graph_type": "DFG", "dfg_edge_type": "DFG_INTERP"})
            elif node.type == NodeType.TEMPLATE_LITERAL:
                for leaf in leaves:
                    if leaf.type != NodeType.LITERAL:
                        self._add_edge(leaf.id, node.id, EdgeType.DFG_TEMPLATE, {"graph_type": "DFG", "dfg_edge_type": "DFG_TEMPLATE"})
            elif node.type in {NodeType.MEMBER_ACCESS, NodeType.ATTRIBUTE_ACCESS, NodeType.ATTRIBUTE}:
                parts = [n for n in leaves if n.id != node.id]
                if parts:
                    self._add_edge(parts[0].id, node.id, EdgeType.DFG_PROPERTY, {"graph_type": "DFG", "dfg_edge_type": "DFG_PROPERTY"})
                    self._add_edge(parts[0].id, node.id, EdgeType.DFG_ATTR, {"graph_type": "DFG", "dfg_edge_type": "DFG_ATTR"})
        for call in [n for n in self.graph.nodes if n.type in self.CALL_TYPES]:
            for arg in self._call_args(call.id):
                self._add_edge(arg.id, call.id, EdgeType.DFG_FLOW, {"graph_type": "DFG", "dfg_edge_type": "DFG_CALL_ARG"})

    def _emit_taint_edges(self) -> None:
        sources = [n for n in self.graph.nodes if self._is_source(n)]
        sinks = [n for n in self.graph.nodes if self._is_sink(n)]
        sanitizers = [n for n in self.graph.nodes if self._is_sanitizer(n)]
        for source in sources:
            if source.metadata:
                source.metadata.is_tainted = True
                source.metadata.security_role = "source"
            self._add_edge(source.id, source.id, EdgeType.TAINT_SOURCE, {"graph_type": "TAINT", "role": "source"})
        for sink in sinks:
            if sink.metadata:
                sink.metadata.security_role = "sink"
            self._add_edge(sink.id, sink.id, EdgeType.TAINT_SINK, {"graph_type": "TAINT", "role": "sink"})
        for sanitizer in sanitizers:
            if sanitizer.metadata:
                sanitizer.metadata.security_role = "sanitizer"
            for arg in self._call_args(sanitizer.id):
                self._add_edge(arg.id, sanitizer.id, EdgeType.SANITIZED, {"graph_type": "TAINT", "sanitizer": sanitizer.name})
        reachable = self._reachable_by_flow()
        for source in sources:
            for sink in sinks:
                if sink.id in reachable.get(source.id, set()):
                    self._add_edge(source.id, sink.id, EdgeType.TAINT_FLOW, {"graph_type": "TAINT", "confidence": 0.85})

    def _reachable_by_flow(self) -> dict[str, set[str]]:
        flow_types = {
            EdgeType.DFG_FLOW, EdgeType.DFG_INTERP, EdgeType.DFG_TEMPLATE,
            EdgeType.DFG_PARAM_PASS, EdgeType.DFG_RET, EdgeType.DFG_PROPERTY,
            EdgeType.DFG_ATTR, EdgeType.CALL_ARG, EdgeType.CALL_RETURN
        }
        adj: dict[str, list[str]] = defaultdict(list)
        for edge in self.graph.edges:
            if edge.type in flow_types:
                adj[edge.from_node].append(edge.to_node)
        reachable: dict[str, set[str]] = {}
        for node in self.graph.nodes:
            seen: set[str] = set()
            queue = list(adj.get(node.id, []))
            while queue and len(seen) < 500:
                current = queue.pop(0)
                if current in seen:
                    continue
                seen.add(current)
                queue.extend(adj.get(current, []))
            reachable[node.id] = seen
        return reachable

    def _emit_http_auth_edges(self) -> None:
        routes = [
            n for n in self.graph.nodes
            if n.type in {NodeType.ROUTE_DECORATOR, NodeType.HTTP_ENDPOINT} or self._looks_like_route(n)
        ]
        middlewares = [n for n in self.graph.nodes if n.type == NodeType.MIDDLEWARE or self._looks_like_middleware(n)]
        guards = [n for n in self.graph.nodes if n.type in {NodeType.AUTH_GUARD, NodeType.AUTH_CHECK, NodeType.PERMISSION_CHECK} or self._is_auth(n)]
        handlers = [
            n for n in self.graph.nodes
            if n.type in {NodeType.FUNCTION, NodeType.ASYNC_FUNCTION, NodeType.METHOD, NodeType.ARROW_FUNCTION}
        ]
        for route in routes:
            handler = self._nearest_handler_after(route, handlers)
            if handler:
                self._add_edge(route.id, handler.id, EdgeType.HTTP_ROUTE, {"graph_type": "HTTP", "route": route.source_code or route.name})
                for middleware in middlewares:
                    if middleware.file == handler.file:
                        self._add_edge(middleware.id, handler.id, EdgeType.HTTP_MIDDLEWARE, {"graph_type": "HTTP", "middleware": middleware.name})
                for guard in guards:
                    if guard.file == handler.file and guard.line <= handler.line:
                        self._add_edge(handler.id, guard.id, EdgeType.AUTH_COVERAGE, {"graph_type": "AUTH", "guard": guard.name})
                        self._add_edge(guard.id, handler.id, EdgeType.PERMISSION_FLOW, {"graph_type": "AUTH", "permission": guard.name})

    def _nearest_handler_after(self, node: GraphNode, handlers: list[GraphNode]) -> GraphNode | None:
        candidates = [h for h in handlers if h.file == node.file and h.line >= node.line]
        candidates.sort(key=lambda n: (n.line, n.column))
        return candidates[0] if candidates else None

    def _emit_database_edges(self) -> None:
        queries = [n for n in self.graph.nodes if self._is_sql_query(n)]
        db_calls = [n for n in self.graph.nodes if self._is_db_call(n)]
        for call in db_calls:
            for arg in self._call_args(call.id):
                self._add_edge(arg.id, call.id, EdgeType.SQL_PARAM, {"graph_type": "DATABASE", "sink": call.name})
            for query in queries:
                if query.file == call.file and abs(query.line - call.line) <= 8:
                    self._add_edge(query.id, call.id, EdgeType.ORM_FLOW, {"graph_type": "DATABASE", "query": query.source_code or query.name})
        for query in queries:
            ancestor = self._nearest_ancestor(query.id, self.CALL_TYPES | {NodeType.ASSIGNMENT})
            if ancestor:
                self._add_edge(query.id, ancestor.id, EdgeType.SQL_PARAM, {"graph_type": "DATABASE", "query": "sql_literal"})

    def _is_source(self, node: GraphNode) -> bool:
        text = f"{node.name or ''} {node.source_code or ''}".lower()
        return node.type == NodeType.PARAMETER or any(token in text for token in ["request.", "req.", "input(", "argv", "stdin", "body", "query"])

    def _is_sink(self, node: GraphNode) -> bool:
        text = f"{node.name or ''} {node.source_code or ''}".lower()
        return node.type in self.CALL_TYPES and any(token in text for token in self.SQL_METHODS | {"eval", "exec", "system", "popen", "subprocess"})

    def _is_sanitizer(self, node: GraphNode) -> bool:
        text = f"{node.name or ''} {node.source_code or ''}".lower()
        return node.type in self.CALL_TYPES and any(token in text for token in self.SANITIZER_KEYWORDS)

    def _is_auth(self, node: GraphNode) -> bool:
        text = f"{node.name or ''} {node.source_code or ''}".lower()
        return any(token in text for token in self.AUTH_KEYWORDS)

    def _looks_like_middleware(self, node: GraphNode) -> bool:
        text = f"{node.name or ''} {node.source_code or ''}".lower()
        return "middleware" in text or ".use(" in text or "before_request" in text

    def _looks_like_route(self, node: GraphNode) -> bool:
        text = f"{node.name or ''} {node.source_code or ''}".lower()
        return node.type in self.CALL_TYPES and any(f".{method}(" in text for method in self.HTTP_METHODS)

    def _is_sql_query(self, node: GraphNode) -> bool:
        text = f"{node.value or ''} {node.source_code or ''}"
        return node.type in {NodeType.LITERAL, NodeType.FSTRING, NodeType.TEMPLATE_LITERAL, NodeType.STRING_CONCAT, NodeType.SQL_QUERY} and bool(self.SQL_WORDS.search(text))

    def _is_db_call(self, node: GraphNode) -> bool:
        text = f"{node.name or ''} {node.source_code or ''}".lower()
        return node.type in self.CALL_TYPES and (
            any(method in text for method in self.SQL_METHODS) or any(hint in text for hint in self.ORM_HINTS)
        )
