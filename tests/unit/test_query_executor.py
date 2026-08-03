"""
Query Executor tests — whole-file sanitizer downgrade for regex-based findings.

Inline negative lookaheads inside a regex pattern can only see text *after* the
flagged call. Guard/setup code (trust-proxy config, middleware registration,
etc.) is often declared once, earlier in the same file, where a forward-only
lookahead can't reach it. QueryExecutor._execute_regex_patterns now checks the
whole file for any of the rule's `sanitizers` markers and, if found, downgrades
confidence to "low" and caps severity at "medium" — mirroring the treatment
already given to DFG/TAINT path sanitizer hits — instead of either missing the
mitigation entirely or silently dropping the finding.
"""
from app.schemas.graph import SemanticGraph
from semantic_engine.query_executor.executor import QueryExecutor
from semantic_engine.query_store.loader import QueryRule

EMPTY_GRAPH = SemanticGraph(nodes=[], edges=[])


def _rule(**overrides) -> QueryRule:
    defaults = dict(
        rule_id="TEST_RULE",
        name="Test Rule",
        owasp="A01",
        cwe="CWE-000",
        description="test",
        severity="high",
        confidence="medium",
        regex_patterns=[r"req\.ip\b"],
        sanitizers=["trust proxy", "ProxyFix"],
    )
    defaults.update(overrides)
    return QueryRule(**defaults)


class TestWholeFileSanitizerDowngrade:
    def test_no_sanitizer_in_file_keeps_original_confidence_and_severity(self):
        code = "if (req.ip == bannedIp) { block(); }"
        slices = QueryExecutor().execute_query(EMPTY_GRAPH, _rule(), code)
        assert len(slices) == 1
        assert slices[0].confidence == "medium"
        assert slices[0].severity == "high"

    def test_sanitizer_declared_earlier_in_file_downgrades_finding(self):
        # The mitigating config sits well before the flagged call — out of reach
        # for any forward-only inline lookahead inside the regex itself.
        code = (
            "app.set('trust proxy', 1);\n"
            "// ... 50 lines of unrelated setup ...\n"
            "function checkIp(req) {\n"
            "  if (req.ip == bannedIp) { block(); }\n"
            "}\n"
        )
        slices = QueryExecutor().execute_query(EMPTY_GRAPH, _rule(), code)
        assert len(slices) == 1
        assert slices[0].confidence == "low"
        assert slices[0].severity == "medium"
        assert "Sanitizer observed elsewhere in file" in slices[0].reason

    def test_sanitizer_declared_after_the_call_also_downgrades(self):
        code = (
            "if (req.ip == bannedIp) { block(); }\n"
            "app.set('trust proxy', 1);\n"
        )
        slices = QueryExecutor().execute_query(EMPTY_GRAPH, _rule(), code)
        assert slices[0].confidence == "low"

    def test_severity_below_high_is_not_raised(self):
        code = "app.set('trust proxy', 1);\nreq.ip;\n"
        slices = QueryExecutor().execute_query(EMPTY_GRAPH, _rule(severity="low"), code)
        assert slices[0].severity == "low"
        assert slices[0].confidence == "low"

    def test_no_sanitizers_configured_never_downgrades(self):
        code = "app.set('trust proxy', 1);\nreq.ip;\n"
        slices = QueryExecutor().execute_query(EMPTY_GRAPH, _rule(sanitizers=[]), code)
        assert slices[0].confidence == "medium"
        assert slices[0].severity == "high"

    def test_compliant_polarity_rule_is_never_downgraded(self):
        # Compliant-marker rules (a match = evidence the control IS satisfied)
        # shouldn't have their "positive" finding softened by a sanitizer hit.
        code = "app.set('trust proxy', 1);\nreq.ip;\n"
        rule = _rule(finding_polarity="compliant")
        slices = QueryExecutor().execute_query(EMPTY_GRAPH, rule, code)
        assert slices[0].confidence == "medium"
        assert slices[0].severity == "high"

    def test_multi_file_scan_only_downgrades_the_file_with_the_sanitizer(self):
        source_map = {
            "routes/admin.js": "if (req.ip == bannedIp) { block(); }",
            "app.js": (
                "app.set('trust proxy', 1);\n"
                "if (req.ip == otherIp) { block(); }\n"
            ),
        }
        slices = QueryExecutor().execute_query(EMPTY_GRAPH, _rule(), "", source_map)
        by_file = {s.location["file"]: s for s in slices}
        assert by_file["routes/admin.js"].confidence == "medium"
        assert by_file["app.js"].confidence == "low"


class TestRegexSliceSinkLabel:
    """
    sink_label used to be hardcoded to the literal string "regex" for every
    regex-detected slice — meaningless, and impossible for pipeline.py's
    dedup step to ever match against a graph-detected finding's real sink
    label like "cursor.execute". It now prefers whichever of the rule's own
    declared `sinks` tokens actually appears in the matched text — the same
    tokens PathDiscovery matches graph nodes against — so a regex hit and a
    taint-graph hit on the same call can be recognized as the same finding.
    """

    def test_sink_label_uses_matching_rule_sink_token(self):
        rule = _rule(
            regex_patterns=[r"cursor\.execute\s*\("],
            sinks=["cursor.execute", "cur.execute"],
        )
        code = "cursor.execute(query)"
        slices = QueryExecutor().execute_query(EMPTY_GRAPH, rule, code)
        assert len(slices) == 1
        assert slices[0].sink_label == "cursor.execute"

    def test_sink_label_falls_back_to_matched_text_when_no_sink_token_present(self):
        rule = _rule(
            regex_patterns=[r"password\s*=\s*request\.args"],
            sinks=["cursor.execute"],
        )
        code = "password = request.args.get('pw')"
        slices = QueryExecutor().execute_query(EMPTY_GRAPH, rule, code)
        assert len(slices) == 1
        assert slices[0].sink_label != "regex"
        assert "password" in slices[0].sink_label

    def test_sink_label_never_the_old_placeholder_when_rule_has_sinks(self):
        rule = _rule(regex_patterns=[r"eval\s*\("], sinks=["eval"])
        slices = QueryExecutor().execute_query(EMPTY_GRAPH, rule, "eval(x)")
        assert slices[0].sink_label == "eval"
