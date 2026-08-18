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


# ── Phase 5.1 — framework-aware sanitizer inventory ──
#
# _is_sanitizer/_sanitizer_hits (path_discovery.py:296/367) already de-score
# any path whose sanitizers set matches a node's name/source_code — the gap
# was inventory, not engine logic: queries.json's per-rule sanitizers arrays
# only had the generic keywords ("escape", "sanitize", ...), not the actual
# framework-specific idioms real codebases use. One test per framework here
# locks in that the newly-added patterns are recognized as sanitizers, using
# the real queries.json (via get_query_store(), same as
# TestCollectPatternsOwnership above) rather than a hand-built fixture — a
# regression in the data file itself, not just the engine, should fail this.

class TestFrameworkAwareSanitizers:
    def setup_method(self):
        self.discovery = PathDiscovery()
        self.query_store = get_query_store()
        _sources, _sinks, self.sanitizers, _so, _sko = self.discovery._collect_patterns(
            SemanticGraph(nodes=[], edges=[]), self.query_store,
        )

    def test_django_orm_filter_recognized_as_sanitizer(self):
        # Django's QuerySet API (.filter()/.exclude()/.get()) parameterizes
        # automatically — a genuinely different code path than the raw/.raw()
        # SQL_INJECTION sink this rule also defines.
        node = _node("n", "User.objects.filter(id=user_id)")
        assert self.discovery._is_sanitizer(node, self.sanitizers)

    def test_sqlalchemy_bindparam_recognized_as_sanitizer(self):
        node = _node("n", "stmt.bindparams(id=user_id)")
        assert self.discovery._is_sanitizer(node, self.sanitizers)

    def test_flask_jinja_autoescape_recognized_as_sanitizer(self):
        # select_autoescape()/autoescape=True on a Jinja Environment is the
        # explicit opt-in that makes Environment.from_string/jinja2.Template
        # (TEMPLATE_INJECTION's sinks) safe to build from a string at all.
        node = _node("n", "Environment(loader=loader, autoescape=select_autoescape(['html']))")
        assert self.discovery._is_sanitizer(node, self.sanitizers)

    def test_dompurify_recognized_as_sanitizer(self):
        node = _node("n", "DOMPurify.sanitize(userInput)")
        assert self.discovery._is_sanitizer(node, self.sanitizers)

    def test_html_escape_recognized_as_sanitizer(self):
        node = _node("n", "html.escape(user_comment)")
        assert self.discovery._is_sanitizer(node, self.sanitizers)

    def test_shlex_quote_recognized_as_sanitizer(self):
        node = _node("n", "shlex.quote(filename)")
        assert self.discovery._is_sanitizer(node, self.sanitizers)

    def test_react_jsx_escape_helper_recognized_as_sanitizer(self):
        # Plain JSX interpolation ({expr}) is already safe by omission — it's
        # simply never in XSS's sinks list (only dangerouslySetInnerHTML is).
        # This covers the explicit escape helpers React/JS code uses instead
        # of DOMPurify when building an HTML string outside JSX itself.
        node = _node("n", "lodash.escape(userInput)")
        assert self.discovery._is_sanitizer(node, self.sanitizers)

    def test_unrelated_call_is_not_a_sanitizer(self):
        node = _node("n", "cursor.execute(query)")
        assert not self.discovery._is_sanitizer(node, self.sanitizers)

    def test_django_orm_sanitizer_suppresses_the_score(self):
        # End-to-end: _score_path scores an otherwise-identical-length path
        # lower when the middle hop is a Django-ORM-filtered call than when
        # it's an unrelated identifier — isolating the sanitizer penalty
        # from the path-length terms (iis/proximity/boundary) by keeping
        # both paths the same length, so only the sanitizer hit differs.
        # CodeSlice itself doesn't carry the raw numeric score (only a
        # fixed "medium" confidence + a severity bucket), so this calls
        # _score_path directly, same as _collect_patterns is called
        # directly in TestCollectPatternsOwnership above.
        src = _node("src", "request.args")
        sink = _node("sink", "cursor.execute")
        neutral_mid = _node("mid", "some_local_variable")
        sanitizer_mid = _node("mid", "User.objects.filter(id=request.args)")

        path = ["src", "mid", "sink"]
        edge_map: dict = {}

        unsanitized_score, _ = self.discovery._score_path(
            {"src": src, "mid": neutral_mid, "sink": sink}, edge_map, path, src, sink, self.sanitizers,
        )
        sanitized_score, _ = self.discovery._score_path(
            {"src": src, "mid": sanitizer_mid, "sink": sink}, edge_map, path, src, sink, self.sanitizers,
        )
        assert sanitized_score < unsanitized_score


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


class TestParameterizedQuerySinkSuppression:
    """Regression — the same false positive SQL_INJECTION's own sink
    matching has (query_executor.py: sink matched by call NAME alone, no
    argument-position awareness) shows up here too, under the generic
    "PATH_DISCOVERY" identity: a bare "req" source label (as opposed to
    "req.body"/"req.query") doesn't match SQL_INJECTION's own declared
    source patterns closely enough to be attributed to it directly, so it
    falls through to this unclassified pathway instead — which needs the
    same parameterized-call suppression applied independently. Confirmed
    false positive against a real scan: 13 of 13 PATH_DISCOVERY findings
    that scan produced were this exact `req -> query` shape."""

    def setup_method(self):
        self.discovery = PathDiscovery(score_threshold=0.0)
        self.query_store = get_query_store()

    @staticmethod
    def _req_to_query_graph() -> SemanticGraph:
        # Bare "req"/"query" match neither SQL_INJECTION's dotted source
        # patterns ("req.query", "req.body", ...) nor its sink list ("db.query",
        # "pool.query", ...) via the regex/token matcher — exactly why this
        # class of finding falls through to PATH_DISCOVERY's metadata-role
        # path in real usage (the AST graph builder tags a bare `req`
        # parameter/`query(...)` call as source/sink via security_role
        # directly), same pattern
        # test_metadata_role_source_without_owning_rule_stays_unclassified
        # above already establishes for this file.
        from app.schemas.graph import NodeMetadata
        src = GraphNode(
            id="src", type=NodeType.IDENTIFIER, name="req", file="app.py", line=1, column=0,
            metadata=NodeMetadata(security_role="source"),
        )
        sink = GraphNode(
            id="sink", type=NodeType.CALL_EXPRESSION, name="query", file="app.py", line=2, column=0,
            metadata=NodeMetadata(security_role="sink"),
        )
        return SemanticGraph(nodes=[src, sink], edges=[_edge("src", "sink")])

    def test_parameterized_query_call_suppressed(self):
        code = (
            "async function findByEmail(email) {\n"
            "  const result = await query(\n"
            "    'SELECT * FROM users WHERE email = $1',\n"
            "    [email]\n"
            "  );\n"
            "}\n"
        )
        slices = self.discovery.discover(self._req_to_query_graph(), {"app.py": code}, self.query_store)
        assert slices == []

    def test_string_concatenation_still_flagged(self):
        # No array-literal argument anywhere near the call — the genuinely
        # vulnerable shape must still produce a finding.
        code = (
            "async function findByEmail(email) {\n"
            "  const result = await query(\"SELECT * FROM users WHERE email = \" + email);\n"
            "}\n"
        )
        slices = self.discovery.discover(self._req_to_query_graph(), {"app.py": code}, self.query_store)
        assert len(slices) == 1
        assert slices[0].rule_id == "PATH_DISCOVERY"
