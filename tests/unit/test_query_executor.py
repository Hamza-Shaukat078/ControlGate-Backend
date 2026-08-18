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
from app.enums.node_type import NodeType
from app.schemas.graph import GraphNode, SemanticGraph
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


class TestSqlInjectionParameterizedCallSuppression:
    """SQL_INJECTION's sinks (pool.query, db.query, cursor.execute, ...)
    match on call NAME alone (_matches_sink_pattern has no argument-position
    awareness), so a taint path reaching the SECOND argument of
    `pool.query(text, params)` was flagged identically to one reaching the
    query-string argument itself — even though the second argument is
    exactly what makes a parameterized call safe. Confirmed false positive
    against a real scan (both findings were `query('...$1...', [x])`-shaped).
    _extract_slice now checks the sink's own call site for a bind-params
    array as a later argument and suppresses the finding outright when
    found — exercised directly here since building a full DFG/TAINT path
    through execute_query needs a much larger graph fixture than the
    regex-only tests above use."""

    SQL_RULE = QueryRule(
        rule_id="SQL_INJECTION", name="SQL Injection", owasp="A03", cwe="CWE-89",
        description="test", severity="critical", confidence="high",
        sources=["req.body"], sinks=["pool.query", "cursor.execute"],
        patterns=["DFG_FLOW"], sanitizers=[],
    )

    def _slice_for(self, call_line_1_indexed: int, file_source: str):
        source_node = GraphNode(
            id="src1", type=NodeType.PARAMETER, name="email",
            file="db.js", line=1, column=0,
        )
        sink_node = GraphNode(
            id="sink1", type=NodeType.CALL_EXPRESSION, name="query",
            file="db.js", line=call_line_1_indexed, column=0,
        )
        graph = SemanticGraph(nodes=[source_node, sink_node], edges=[])
        return QueryExecutor()._extract_slice(
            graph, ["src1", "sink1"], self.SQL_RULE, "DFG_FLOW", file_source,
        )

    def test_multiline_parameterized_call_suppressed(self):
        # The exact shape from the real false positive — array argument on
        # its own line, a few lines below the call.
        code = (
            "async function findByEmail(email) {\n"
            "  const result = await query(\n"
            "    'SELECT * FROM users WHERE email = $1',\n"
            "    [email]\n"
            "  );\n"
            "  return result.rows[0];\n"
            "}\n"
        )
        assert self._slice_for(2, code) is None

    def test_single_line_parameterized_call_suppressed(self):
        code = "const r = await pool.query('SELECT * FROM t WHERE id = $1', [id]);\n"
        assert self._slice_for(1, code) is None

    def test_string_concatenation_still_flagged(self):
        # No array-literal argument anywhere near the call — the genuinely
        # vulnerable shape must still produce a finding.
        code = "cursor.execute(\"SELECT * FROM t WHERE u='\" + username + \"'\")\n"
        result = self._slice_for(1, code)
        assert result is not None
        assert result.rule_id == "SQL_INJECTION"

    def test_suppression_is_sql_injection_specific(self):
        # A different rule_id with the same call shape must NOT be suppressed
        # by this check — it's deliberately scoped to SQL_INJECTION only.
        other_rule = QueryRule(
            rule_id="COMMAND_INJECTION", name="Command Injection", owasp="A03",
            cwe="CWE-78", description="test", severity="critical", confidence="high",
            sources=["req.body"], sinks=["query"], patterns=["DFG_FLOW"], sanitizers=[],
        )
        code = "const r = await pool.query('SELECT * FROM t WHERE id = $1', [id]);\n"
        source_node = GraphNode(id="src1", type=NodeType.PARAMETER, name="id", file="db.js", line=1, column=0)
        sink_node = GraphNode(id="sink1", type=NodeType.CALL_EXPRESSION, name="query", file="db.js", line=1, column=0)
        graph = SemanticGraph(nodes=[source_node, sink_node], edges=[])
        result = QueryExecutor()._extract_slice(graph, ["src1", "sink1"], other_rule, "DFG_FLOW", code)
        assert result is not None


class TestSourceValueMatchingNotSubstring:
    """Regression — _matches_pattern's node.value fallback used to be a
    naive `pattern_lower in str(node.value)` substring check, bypassing the
    token-aware _label_matches_pattern matcher used everywhere else in this
    function. SSRF's source list includes bare "url" (meant to catch
    request-derived values like req.query.url), and a plain substring
    check treats "url" as present inside "API_URL" or
    "PRODUCT_SERVICE_URL" — hardcoded environment-config constants
    (docker-compose service-discovery URLs), never user input. Confirmed
    false positive against a real scan on exactly those two identifiers."""

    SSRF_RULE = QueryRule(
        rule_id="SSRF", name="SSRF", owasp="A03", cwe="CWE-918",
        description="test", severity="critical", confidence="high",
        sources=["url"], sinks=["axios.get"], patterns=["DFG_FLOW"], sanitizers=[],
    )

    def test_env_config_constant_not_treated_as_source(self):
        node = GraphNode(
            id="n1", type=NodeType.IDENTIFIER, name="API_URL", value="API_URL",
            file="a.ts", line=1, column=0,
        )
        graph = SemanticGraph(nodes=[node], edges=[])
        sources = QueryExecutor()._resolve_sources(graph, self.SSRF_RULE)
        assert sources == []

    def test_service_discovery_url_env_var_not_treated_as_source(self):
        node = GraphNode(
            id="n1", type=NodeType.IDENTIFIER, name="PRODUCT_SERVICE_URL", value="PRODUCT_SERVICE_URL",
            file="a.js", line=1, column=0,
        )
        graph = SemanticGraph(nodes=[node], edges=[])
        sources = QueryExecutor()._resolve_sources(graph, self.SSRF_RULE)
        assert sources == []

    def test_bare_url_value_still_matches(self):
        # A dict-key access like data['url'] — node.value genuinely IS the
        # word "url" itself, not a substring of a longer identifier. Must
        # still match; this isn't a blanket suppression.
        node = GraphNode(
            id="n1", type=NodeType.SUBSCRIPT, name="data_url_key", value="url",
            file="a.js", line=1, column=0,
        )
        graph = SemanticGraph(nodes=[node], edges=[])
        sources = QueryExecutor()._resolve_sources(graph, self.SSRF_RULE)
        assert sources == [node]


class TestSensitiveDataExposureValueMatchingScopedToSubscript:
    """Follow-up regression to TestSourceValueMatchingNotSubstring — the
    token-aware fix there still let through a second, broader bug: it was
    scoped as "every node type except LITERAL", but CALL_EXPRESSION and
    MEMBER_ACCESS nodes store their *entire raw source snippet* in
    `.value` (not a short semantic value), so an everyday word like
    "password" matched as a whole word inside plain response-message
    prose ('Password changed successfully') with no credential anywhere
    nearby — tainting the res.json() call itself as a "source". Confirmed
    false positive against a real scan. _matches_pattern's value fallback
    is now scoped to NodeType.SUBSCRIPT only (the one case it was built
    for — see test_bare_url_value_still_matches above)."""

    SDE_RULE = QueryRule(
        rule_id="SENSITIVE_DATA_EXPOSURE", name="Sensitive Data Exposure", owasp="A02",
        cwe="CWE-200", description="test", severity="high", confidence="medium",
        sources=["password", "secret", "api_key", "private_key"],
        sinks=["res.json", "res.send"], patterns=["DFG_FLOW"], sanitizers=[],
    )

    def test_literal_response_message_containing_the_word_password_not_a_source(self):
        # 'Password changed successfully' — a UI message, not a credential.
        node = GraphNode(
            id="n1", type=NodeType.LITERAL, name="string",
            value="'Password changed successfully'", file="auth.js", line=285, column=0,
        )
        graph = SemanticGraph(nodes=[node], edges=[])
        sources = QueryExecutor()._resolve_sources(graph, self.SDE_RULE)
        assert sources == []

    def test_call_expression_snippet_containing_the_word_password_not_a_source(self):
        # node.value on a CALL_EXPRESSION is the call's own raw source text,
        # not a semantic value — it must never be treated as a source label.
        node = GraphNode(
            id="n1", type=NodeType.CALL_EXPRESSION, name="res.json",
            value="res.json({ success: true, message: 'Password changed successfully' })",
            file="auth.js", line=285, column=0,
        )
        graph = SemanticGraph(nodes=[node], edges=[])
        sources = QueryExecutor()._resolve_sources(graph, self.SDE_RULE)
        assert sources == []

    def test_bare_password_key_subscript_still_matches(self):
        # The one case this fallback exists for is preserved: a dict-key
        # access where node.value IS the key name itself.
        node = GraphNode(
            id="n1", type=NodeType.SUBSCRIPT, name="user_password_key", value="password",
            file="auth.js", line=1, column=0,
        )
        graph = SemanticGraph(nodes=[node], edges=[])
        sources = QueryExecutor()._resolve_sources(graph, self.SDE_RULE)
        assert sources == [node]

    def test_password_named_identifier_still_matches(self):
        # The genuine, common case — matched via node.name/label, unaffected
        # by the value-fallback scoping change.
        node = GraphNode(
            id="n1", type=NodeType.IDENTIFIER, name="password", value=None,
            file="auth.js", line=1, column=0,
        )
        graph = SemanticGraph(nodes=[node], edges=[])
        sources = QueryExecutor()._resolve_sources(graph, self.SDE_RULE)
        assert sources == [node]


class TestSensitiveDataExposureTokenIssuanceNotFlagged:
    """"token" was removed from SENSITIVE_DATA_EXPOSURE's own source list —
    ASVS V15.3.1 ("only return the required subset of fields from a data
    object") is violated by over-serialization (e.g. returning an entire
    user record including a password hash), not by an auth endpoint
    returning the one token it exists to issue. A bare "token" source can't
    distinguish "issuing a fresh token to its own owner" (the standard job
    of login/refresh/register endpoints) from an actual leak. Confirmed
    false positive against a real scan: POST /auth/refresh's
    `res.json({ data: { accessToken: newAccessToken } })` — the correct,
    intended response of that exact endpoint."""

    SDE_RULE = QueryRule(
        rule_id="SENSITIVE_DATA_EXPOSURE", name="Sensitive Data Exposure", owasp="A02",
        cwe="CWE-200", description="test", severity="high", confidence="medium",
        sources=["password", "secret", "api_key", "private_key"],
        sinks=["res.json", "res.send"], patterns=["DFG_FLOW"], sanitizers=[],
    )

    def test_access_token_identifier_not_a_source(self):
        node = GraphNode(
            id="n1", type=NodeType.IDENTIFIER, name="newAccessToken", value=None,
            file="auth.js", line=187, column=0,
        )
        graph = SemanticGraph(nodes=[node], edges=[])
        sources = QueryExecutor()._resolve_sources(graph, self.SDE_RULE)
        assert sources == []

    def test_refresh_token_identifier_not_a_source(self):
        node = GraphNode(
            id="n1", type=NodeType.IDENTIFIER, name="refreshToken", value=None,
            file="auth.js", line=163, column=0,
        )
        graph = SemanticGraph(nodes=[node], edges=[])
        sources = QueryExecutor()._resolve_sources(graph, self.SDE_RULE)
        assert sources == []

    def test_api_key_and_private_key_are_still_flagged(self):
        # The narrowing is specific to "token" — the other clearly-dangerous
        # source patterns are untouched.
        for name in ("api_key", "private_key", "secret"):
            node = GraphNode(
                id="n1", type=NodeType.IDENTIFIER, name=name, value=None,
                file="auth.js", line=1, column=0,
            )
            graph = SemanticGraph(nodes=[node], edges=[])
            sources = QueryExecutor()._resolve_sources(graph, self.SDE_RULE)
            assert sources == [node], f"{name} should still match"


class TestInputValidationMissingLocalSanitizationSuppression:
    """INPUT_VALIDATION_MISSING's sinks (req.body/query/params subscript or
    attribute access) match on the read alone — a request value being
    reassigned through a sanitizing `.replace(...)` call is itself a
    validation/sanitization step, not "input used without validation".
    Without this, the sanitizeRequest() middleware in security.js — the
    file that IS the sanitization layer — flagged its own
    `req.query[key] = req.query[key].replace(/[<>]/g, '')` line as the
    very thing it exists to prevent. Confirmed false positive against a
    real scan (both the typeof-guard line and the replace() line itself
    matched). Checked as a plain substring on a small fixed-size line
    window — not a regex lookahead — so it carries none of the ReDoS risk
    documented in test_redos_regex_patterns.py."""

    RULE = QueryRule(
        rule_id="INPUT_VALIDATION_MISSING", name="Business Input Used Without Visible Validation",
        owasp="A04", cwe="CWE-20", description="test", severity="medium", confidence="low",
        sources=[], sinks=[], patterns=[], sanitizers=[],
        regex_patterns=[r"req\.(?:body|query|params)\s*\["],
    )

    def test_sanitized_reassignment_line_not_flagged(self):
        code = (
            "export function sanitizeRequest(req, res, next) {\n"
            "  if (req.query) {\n"
            "    Object.keys(req.query).forEach((key) => {\n"
            "      if (typeof req.query[key] === 'string') {\n"
            "        req.query[key] = req.query[key].replace(/[<>]/g, '');\n"
            "      }\n"
            "    });\n"
            "  }\n"
            "  next();\n"
            "}\n"
        )
        slices = QueryExecutor().execute_query(EMPTY_GRAPH, self.RULE, code, {"security.js": code})
        assert slices == []

    def test_typeof_guard_line_immediately_before_the_replace_not_flagged(self):
        # The typeof-check line itself matches the sink pattern too, one line
        # above the .replace() call — must also be suppressed by the window.
        code = (
            "if (typeof req.query[key] === 'string') {\n"
            "  req.query[key] = req.query[key].replace(/[<>]/g, '');\n"
            "}\n"
        )
        slices = QueryExecutor().execute_query(EMPTY_GRAPH, self.RULE, code, {"security.js": code})
        assert slices == []

    def test_unsanitized_use_still_flagged(self):
        # No .replace(...) anywhere nearby — the genuinely vulnerable shape
        # (raw concatenation into a query) must still produce a finding.
        code = (
            "function handler(req, res) {\n"
            "  db.query('SELECT * FROM t WHERE id = ' + req.query['id']);\n"
            "}\n"
        )
        slices = QueryExecutor().execute_query(EMPTY_GRAPH, self.RULE, code, {"x.js": code})
        assert len(slices) == 1

    def test_replace_call_far_away_does_not_suppress(self):
        # A .replace() call several lines away (outside the local window)
        # is unrelated sanitization — must not suppress this match.
        code = (
            "function handler(req, res) {\n"
            "  db.query('SELECT * FROM t WHERE id = ' + req.query['id']);\n"
            "  // ... 5 unrelated lines ...\n"
            "  // ... more unrelated lines ...\n"
            "  // ... more unrelated lines ...\n"
            "  const title = pageTitle.replace(/foo/g, 'bar');\n"
            "}\n"
        )
        slices = QueryExecutor().execute_query(EMPTY_GRAPH, self.RULE, code, {"x.js": code})
        assert len(slices) == 1

    def test_suppression_is_input_validation_missing_specific(self):
        # A different rule_id with the same regex shape must NOT be
        # suppressed by this check — it's deliberately scoped to
        # INPUT_VALIDATION_MISSING only.
        other_rule = QueryRule(
            rule_id="SOME_OTHER_RULE", name="Some Other Rule", owasp="A04", cwe="CWE-20",
            description="test", severity="medium", confidence="low",
            sources=[], sinks=[], patterns=[], sanitizers=[],
            regex_patterns=[r"req\.(?:body|query|params)\s*\["],
        )
        code = "req.query[key] = req.query[key].replace(/[<>]/g, '');\n"
        slices = QueryExecutor().execute_query(EMPTY_GRAPH, other_rule, code, {"x.js": code})
        # Both the LHS and RHS `req.query[` occurrences on this line match —
        # unlike INPUT_VALIDATION_MISSING, this unrelated rule_id gets no
        # suppression at all.
        assert len(slices) == 2
