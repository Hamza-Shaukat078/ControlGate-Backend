"""
PathDiscovery rule-attribution tests.

Every finding from the discovery pathway used to get rule_id="PATH_DISCOVERY"
unconditionally — not a real queries.json key, so query_store.get_query()
always returned None and asvs_controls was always []. Fixed by tracking which
rule's source/sink pattern matched each node (_collect_patterns) and, when a
discovered path's source and sink both trace back to the same rule, attributing
the CodeSlice to that rule's real rule_id/owasp/cwe (_attribute_rule) instead.
Paths that don't match any single rule's source+sink signature stay honestly
unclassified rather than defaulting to a fake owasp/cwe.
"""
from app.enums.edge_type import EdgeType
from app.enums.node_type import NodeType
from app.schemas.graph import GraphEdge, GraphNode, SemanticGraph
from semantic_engine.path_discovery import PathDiscovery
from semantic_engine.query_store.loader import get_query_store


def _node(node_id: str, name: str, node_type: NodeType = NodeType.IDENTIFIER, file: str = "app.py") -> GraphNode:
    return GraphNode(
        id=node_id, type=node_type, name=name,
        file=file, line=1, column=0,
    )


def _edge(from_id: str, to_id: str) -> GraphEdge:
    return GraphEdge(from_node=from_id, to_node=to_id, type=EdgeType.DFG_FLOW)


class TestAttributeRuleFromCommonSourceSink:
    def setup_method(self):
        self.discovery = PathDiscovery(score_threshold=0.0)
        self.query_store = get_query_store()

    def test_source_and_sink_from_same_rule_are_attributed_to_it(self):
        # "req.body" is a SQL_INJECTION source, "cursor.execute" one of its
        # sinks — a two-node path between them genuinely is a SQL-injection-shaped
        # finding, just discovered via the graph instead of the regex.
        graph = SemanticGraph(
            nodes=[
                _node("src", "req.body"),
                _node("sink", "cursor.execute"),
            ],
            edges=[_edge("src", "sink")],
        )
        slices = self.discovery.discover(graph, {"app.py": "cursor.execute(req.body['q'])"}, self.query_store)
        assert len(slices) == 1
        s = slices[0]
        assert s.rule_id == "SQL_INJECTION"
        assert s.rule_name == "SQL Injection"
        assert s.owasp == "A03"
        assert s.cwe == "CWE-89"

    def test_unrelated_source_and_sink_stay_unclassified(self):
        # "user_id" is only a SQL_INJECTION source; "eval" is only a
        # CODE_INJECTION sink. They share no single owning rule between source
        # and sink — this must NOT be mislabeled as either rule. It should
        # surface honestly as unclassified instead.
        graph = SemanticGraph(
            nodes=[
                _node("src", "user_id"),
                _node("sink", "eval"),
            ],
            edges=[_edge("src", "sink")],
        )
        slices = self.discovery.discover(graph, {"app.py": "eval(user_id)"}, self.query_store)
        assert len(slices) == 1
        s = slices[0]
        assert s.rule_id == "PATH_DISCOVERY"
        assert s.rule_name == "Unclassified Data-Flow Finding"
        assert s.owasp is None
        assert s.cwe is None

    def test_metadata_role_source_without_owning_rule_stays_unclassified(self):
        # A node reaching `sources`/`sinks` only via graph metadata security_role
        # (not any rule's pattern list) has no rule to attribute to, even if it
        # happens to reach a real sink.
        from app.schemas.graph import NodeMetadata
        src = GraphNode(
            id="src", type=NodeType.IDENTIFIER, name="some_custom_taint_origin",
            file="app.py", line=1, column=0,
            metadata=NodeMetadata(security_role="source"),
        )
        sink = _node("sink", "cursor.execute")
        graph = SemanticGraph(nodes=[src, sink], edges=[_edge("src", "sink")])
        slices = self.discovery.discover(graph, {"app.py": "cursor.execute(some_custom_taint_origin)"}, self.query_store)
        assert len(slices) == 1
        assert slices[0].rule_id == "PATH_DISCOVERY"


class TestCollectPatternsOwnership:
    def setup_method(self):
        self.discovery = PathDiscovery()
        self.query_store = get_query_store()

    def test_source_owners_and_sink_owners_track_matching_rule_ids(self):
        graph = SemanticGraph(
            nodes=[
                _node("src", "request.args"),
                _node("sink", "cursor.execute"),
            ],
            edges=[],
        )
        _sources, _sinks, _sanitizers, source_owners, sink_owners = self.discovery._collect_patterns(
            graph, self.query_store
        )
        assert "SQL_INJECTION" in source_owners["src"]
        assert "SQL_INJECTION" in sink_owners["sink"]


# ── Problem #8: no more hard node-count cliff; bounded cross-file sharding instead ──

class TestNoHardNodeCountCliff:
    """
    discover() used to unconditionally `return []` once graph.nodes exceeded
    3000 — a fixed 3-file fixture already hit 589 nodes, so a ~15-file repo
    silently disabled PathDiscovery for the rest of the repo's life. There's
    no size gate anymore; cost is bounded per-source by max_cross_file_hops
    instead (see TestCrossFileHopBudget), so discovery keeps working
    regardless of how many unrelated nodes/files the rest of the graph has.
    """

    def setup_method(self):
        self.discovery = PathDiscovery(score_threshold=0.0)
        self.query_store = get_query_store()

    def test_discovery_still_runs_well_past_the_old_3000_node_cliff(self):
        nodes = [
            _node("src", "req.body"),
            _node("sink", "cursor.execute"),
        ]
        edges = [_edge("src", "sink")]
        # Pad the graph with thousands of unrelated, disconnected nodes — the
        # kind of bulk a real multi-file repo graph accumulates — to push node
        # count well past the old 3000 cliff.
        for i in range(3200):
            nodes.append(_node(f"filler_{i}", f"filler_{i}", file=f"filler_{i % 50}.py"))

        graph = SemanticGraph(nodes=nodes, edges=edges)
        assert len(graph.nodes) > 3000
        slices = self.discovery.discover(graph, {"app.py": "cursor.execute(req.body['q'])"}, self.query_store)
        assert len(slices) == 1
        assert slices[0].rule_id == "SQL_INJECTION"


class TestCrossFileHopBudget:
    """
    _bfs_paths now tracks how many distinct file boundaries a path has
    crossed and prunes once that exceeds max_cross_file_hops (default 2).
    Traversal within a single file is never hop-limited (only max_depth /
    max_candidates / the MAX_BFS_OPS safety net apply there) — only crossing
    *into a different file* spends part of the budget. This is what keeps a
    single source's search cost roughly constant regardless of total repo
    size: the search can't wander arbitrarily far across modules.
    """

    def setup_method(self):
        self.query_store = get_query_store()

    def _chain_graph(self, hop_count: int) -> SemanticGraph:
        # source (file 0) -> mid_1 (file 1) -> mid_2 (file 2) -> ... -> sink (file hop_count)
        # Each edge crosses into a new file, so reaching the sink costs exactly
        # `hop_count` file-crossing hops.
        nodes = [_node("src", "req.body", file="f0.py")]
        edges = []
        prev = "src"
        for i in range(1, hop_count):
            nid = f"mid_{i}"
            nodes.append(_node(nid, f"mid_{i}", file=f"f{i}.py"))
            edges.append(_edge(prev, nid))
            prev = nid
        nodes.append(_node("sink", "cursor.execute", file=f"f{hop_count}.py"))
        edges.append(_edge(prev, "sink"))
        return SemanticGraph(nodes=nodes, edges=edges)

    def test_sink_within_hop_budget_is_found(self):
        discovery = PathDiscovery(score_threshold=0.0, max_cross_file_hops=2)
        graph = self._chain_graph(hop_count=2)
        slices = discovery.discover(graph, {}, self.query_store)
        assert len(slices) == 1

    def test_sink_beyond_hop_budget_is_not_found(self):
        discovery = PathDiscovery(score_threshold=0.0, max_cross_file_hops=2)
        graph = self._chain_graph(hop_count=3)
        slices = discovery.discover(graph, {}, self.query_store)
        assert slices == []

    def test_raising_the_budget_reaches_the_farther_sink(self):
        discovery = PathDiscovery(score_threshold=0.0, max_cross_file_hops=3)
        graph = self._chain_graph(hop_count=3)
        slices = discovery.discover(graph, {}, self.query_store)
        assert len(slices) == 1

    def test_unlimited_hops_within_a_single_file_are_not_budget_limited(self):
        # A long same-file chain must not be pruned by the cross-file budget —
        # only crossing *into a different file* should ever spend it.
        discovery = PathDiscovery(score_threshold=0.0, max_cross_file_hops=0, max_depth=50)
        nodes = [_node("src", "req.body", file="app.py")]
        edges = []
        prev = "src"
        for i in range(30):
            nid = f"step_{i}"
            nodes.append(_node(nid, f"step_{i}", file="app.py"))
            edges.append(_edge(prev, nid))
            prev = nid
        nodes.append(_node("sink", "cursor.execute", file="app.py"))
        edges.append(_edge(prev, "sink"))
        graph = SemanticGraph(nodes=nodes, edges=edges)

        slices = discovery.discover(graph, {}, self.query_store)
        assert len(slices) == 1
