"""
Dedup/merge-step tests for semantic_engine/pipeline.py.

_filter_discovery_slices and _dedupe_vulnerabilities used to each key on an
exact (file, start_line, end_line, sink_label[, rule_name]) tuple. A minor
line-range or label discrepancy between two detectors of the *same*
vulnerability — e.g. SQL_INJECTION's regex and PathDiscovery's taint graph
both catching one cursor.execute(...) call — let real duplicates survive as
separate findings. Fixed with a shared _same_finding() check (overlapping
range + normalized sink, ignoring rule identity) and, when a merge collapses
findings from different rules, unioning their rule metadata (via
contributing_rule_ids / _format_vulnerability) instead of discarding the
loser's — the same underlying fix problem #6 (PATH_DISCOVERY attribution) and
the "legitimate dual-signal pairs" question from problem #2 both needed.
"""
from semantic_engine.classifier.classifier import ClassifiedVulnerability
from semantic_engine.classifier.llm_service import Classification
from semantic_engine.pipeline import (
    PipelineConfig,
    SemanticPipeline,
    _cluster_by_same_finding,
    _normalize_sink,
    _same_finding,
)
from semantic_engine.query_executor.executor import CodeSlice


def _slice(**overrides) -> CodeSlice:
    defaults = dict(
        slice_id="s1", rule_id="SQL_INJECTION", rule_name="SQL Injection",
        owasp="A03", cwe="CWE-89", severity="high", confidence="medium",
        source_node_id="src", sink_node_id="sink", path_nodes=["src", "sink"],
        code_snippet="cursor.execute(query)",
        location={"file": "app.py", "start_line": 10, "end_line": 10},
        source_label="request.args", sink_label="cursor.execute",
        pattern_type="DFG_FLOW", reason="test",
    )
    defaults.update(overrides)
    return CodeSlice(**defaults)


def _vuln(**overrides) -> ClassifiedVulnerability:
    defaults = dict(
        slice_id="s1", rule_id="SQL_INJECTION", rule_name="SQL Injection",
        owasp="A03", cwe="CWE-89",
        code_snippet="cursor.execute(query)",
        location={"file": "app.py", "start_line": 10, "end_line": 10},
        source_label="request.args", sink_label="cursor.execute",
        path_nodes=["src", "sink"],
        static_severity="high", static_confidence="medium",
        pattern_type="DFG_FLOW", static_reason="test",
        llm_classification=Classification.VULNERABLE,
        llm_explanation="test", llm_severity="high",
        llm_exploitability=0.7, llm_remediation="test", llm_confidence=0.7,
        final_severity="high", final_confidence=0.7, is_vulnerable=True,
    )
    defaults.update(overrides)
    return ClassifiedVulnerability(**defaults)


class TestNormalizeSink:
    def test_bare_dotted_call_unchanged(self):
        assert _normalize_sink("cursor.execute") == "cursor.execute"

    def test_case_and_parens_normalized(self):
        assert _normalize_sink("Cursor.Execute(") == "cursor.execute"

    def test_self_prefix_and_call_parens_stripped(self):
        assert _normalize_sink("self.cursor.execute()") == "cursor.execute"

    def test_full_call_expression_reduces_to_callee(self):
        assert _normalize_sink('cursor.execute(f"SELECT * FROM t WHERE id={x}")') == "cursor.execute"

    def test_empty_label(self):
        assert _normalize_sink("") == ""
        assert _normalize_sink(None) == ""

    def test_distinct_sinks_stay_distinct(self):
        assert _normalize_sink("eval") != _normalize_sink("cursor.execute")


class TestSameFinding:
    def test_identical_location_and_sink_same_rule(self):
        a = _slice()
        b = _slice(rule_id="SQL_INJECTION")
        assert _same_finding(a, b)

    def test_same_location_and_sink_different_rule_still_same_finding(self):
        # This is the deliberate part: _same_finding ignores rule identity so
        # SQL_INJECTION's regex hit and PathDiscovery's graph hit on the same
        # call converge, and so do legitimate dual-signal pairs.
        a = _slice(rule_id="SQL_INJECTION")
        b = _slice(rule_id="PATH_DISCOVERY", rule_name="Unclassified Data-Flow Finding")
        assert _same_finding(a, b)

    def test_overlapping_but_not_identical_line_range_matches(self):
        a = _slice(location={"file": "app.py", "start_line": 8, "end_line": 12})
        b = _slice(location={"file": "app.py", "start_line": 10, "end_line": 10})
        assert _same_finding(a, b)

    def test_different_file_never_matches(self):
        a = _slice(location={"file": "app.py", "start_line": 10, "end_line": 10})
        b = _slice(location={"file": "other.py", "start_line": 10, "end_line": 10})
        assert not _same_finding(a, b)

    def test_non_overlapping_lines_do_not_match(self):
        a = _slice(location={"file": "app.py", "start_line": 10, "end_line": 10})
        b = _slice(location={"file": "app.py", "start_line": 50, "end_line": 55})
        assert not _same_finding(a, b)

    def test_overlapping_lines_but_different_sink_do_not_match(self):
        a = _slice(sink_label="cursor.execute")
        b = _slice(sink_label="eval")
        assert not _same_finding(a, b)

    def test_old_bug_regex_placeholder_never_matched_real_sink_label(self):
        # Documents the pre-fix failure mode: query_executor used to hardcode
        # sink_label="regex" for every regex-detected slice, which could never
        # normalize to the same token as a graph-detected "cursor.execute".
        a = _slice(sink_label="regex")
        b = _slice(sink_label="cursor.execute")
        assert not _same_finding(a, b)


class TestClusterBySameFinding:
    def test_two_matching_one_distinct_forms_two_clusters(self):
        a = _slice(slice_id="a", rule_id="SQL_INJECTION")
        b = _slice(slice_id="b", rule_id="PATH_DISCOVERY")
        c = _slice(slice_id="c", location={"file": "app.py", "start_line": 200, "end_line": 200})
        clusters = _cluster_by_same_finding([a, b, c])
        sizes = sorted(len(cl) for cl in clusters)
        assert sizes == [1, 2]

    def test_transitive_chain_merges_into_one_cluster(self):
        # a overlaps b, b overlaps c, a does not directly overlap c — union-find
        # still merges all three via the b bridge.
        a = _slice(slice_id="a", location={"file": "app.py", "start_line": 1, "end_line": 3})
        b = _slice(slice_id="b", location={"file": "app.py", "start_line": 3, "end_line": 6})
        c = _slice(slice_id="c", location={"file": "app.py", "start_line": 6, "end_line": 9})
        clusters = _cluster_by_same_finding([a, b, c])
        assert len(clusters) == 1
        assert len(clusters[0]) == 3


class TestFilterDiscoverySlices:
    def setup_method(self):
        self.pipeline = SemanticPipeline(PipelineConfig(enable_llm=False))

    def test_same_rule_overlapping_discovery_slice_dropped(self):
        query_slice = _slice(rule_id="SQL_INJECTION")
        discovery_slice = _slice(
            rule_id="SQL_INJECTION",
            location={"file": "app.py", "start_line": 9, "end_line": 11},
        )
        result = self.pipeline._filter_discovery_slices([discovery_slice], [query_slice])
        assert result == []

    def test_different_rule_overlapping_discovery_slice_is_kept(self):
        # Attributed (post problem #6 fix) to a different real rule than the
        # nearby query slice — a genuinely distinct signal at this
        # pre-classification stage, so it must survive to be classified and
        # let _dedupe_vulnerabilities decide/merge afterwards.
        query_slice = _slice(rule_id="SQL_INJECTION")
        discovery_slice = _slice(rule_id="CODE_INJECTION", sink_label="eval")
        result = self.pipeline._filter_discovery_slices([discovery_slice], [query_slice])
        assert result == [discovery_slice]

    def test_non_overlapping_discovery_slice_is_kept(self):
        query_slice = _slice(rule_id="SQL_INJECTION")
        discovery_slice = _slice(
            rule_id="SQL_INJECTION",
            location={"file": "app.py", "start_line": 500, "end_line": 500},
        )
        result = self.pipeline._filter_discovery_slices([discovery_slice], [query_slice])
        assert result == [discovery_slice]


class TestDedupeVulnerabilities:
    def setup_method(self):
        self.pipeline = SemanticPipeline(PipelineConfig(enable_llm=False))

    def test_same_rule_overlapping_findings_collapse_to_one(self):
        a = _vuln(slice_id="a", final_confidence=0.5)
        b = _vuln(slice_id="b", final_confidence=0.9)
        result = self.pipeline._dedupe_vulnerabilities([a, b])
        assert len(result) == 1
        # Higher-ranked (higher confidence) survives as primary.
        assert result[0].slice_id == "b"

    def test_different_rule_overlapping_findings_merge_with_union(self):
        primary = _vuln(
            slice_id="xss", rule_id="XSS", rule_name="Cross-Site Scripting",
            sink_label="innerHTML", final_confidence=0.9,
        )
        secondary = _vuln(
            slice_id="dom", rule_id="UNSAFE_DOM_RENDERING", rule_name="Unsafe DOM Rendering",
            sink_label="innerHTML", final_confidence=0.5,
        )
        result = self.pipeline._dedupe_vulnerabilities([primary, secondary])
        assert len(result) == 1
        merged = result[0]
        assert merged.rule_id == "XSS"
        assert merged.contributing_rule_ids == ["UNSAFE_DOM_RENDERING"]

    def test_non_overlapping_findings_stay_separate(self):
        a = _vuln(slice_id="a", location={"file": "app.py", "start_line": 10, "end_line": 10})
        b = _vuln(slice_id="b", location={"file": "app.py", "start_line": 500, "end_line": 500})
        result = self.pipeline._dedupe_vulnerabilities([a, b])
        assert len(result) == 2

    def test_empty_list_returns_empty(self):
        assert self.pipeline._dedupe_vulnerabilities([]) == []


class TestFormatVulnerabilityUnionsContributingAsvsControls:
    def setup_method(self):
        self.pipeline = SemanticPipeline(PipelineConfig(enable_llm=False))

    def test_merged_finding_unions_asvs_controls_from_both_rules(self):
        merged = _vuln(
            rule_id="XSS", rule_name="Cross-Site Scripting",
            contributing_rule_ids=["UNSAFE_DOM_RENDERING"],
        )
        formatted = self.pipeline._format_vulnerability(merged)
        # XSS -> V1.2.1, UNSAFE_DOM_RENDERING -> V3.2.2 (see queries.json) — both
        # must survive on the merged result, not just the primary's.
        assert "V1.2.1" in formatted["asvs_controls"]
        assert "V3.2.2" in formatted["asvs_controls"]
        assert formatted["contributing_rules"] == [
            {"rule_id": "UNSAFE_DOM_RENDERING", "name": "Unsafe DOM Rendering (innerHTML vs textContent)"}
        ]
        assert formatted["needs_manual_triage"] is False

    def test_path_discovery_merged_with_real_rule_is_not_flagged_needs_triage(self):
        # A PATH_DISCOVERY-tagged primary that absorbed a real rule's finding
        # during dedup must NOT be flagged needs_manual_triage — the real
        # rule's ASVS controls are still present via contributing_rule_ids.
        merged = _vuln(
            rule_id="PATH_DISCOVERY", rule_name="Unclassified Data-Flow Finding",
            owasp=None, cwe=None,
            contributing_rule_ids=["SQL_INJECTION"],
        )
        formatted = self.pipeline._format_vulnerability(merged)
        assert formatted["asvs_controls"] == ["V1.2.4"]
        assert formatted["needs_manual_triage"] is False

    def test_pure_path_discovery_with_no_contributing_rule_is_flagged(self):
        unclassified = _vuln(
            rule_id="PATH_DISCOVERY", rule_name="Unclassified Data-Flow Finding",
            owasp=None, cwe=None,
        )
        formatted = self.pipeline._format_vulnerability(unclassified)
        assert formatted["asvs_controls"] == []
        assert formatted["needs_manual_triage"] is True
