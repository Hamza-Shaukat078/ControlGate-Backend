from app.domain.analysis.semantic_graph_builder import SemanticGraphBuilder
from app.enums.edge_type import EdgeType


def _edge_counts(graph):
    counts = {}
    for edge in graph.edges:
        edge_type = edge.type.value if hasattr(edge.type, "value") else str(edge.type)
        counts[edge_type] = counts.get(edge_type, 0) + 1
    return counts


def test_python_cpg_enrichment_emits_security_graph_edges():
    code = """
from flask import request

def helper(x):
    return x

@app.before_request
def check_role():
    if not request.user.is_authenticated:
        raise Exception("no")

@app.route('/users/<uid>')
@login_required
def get_user(uid):
    clean = escape(uid)
    query = f"SELECT * FROM users WHERE id={uid}"
    if uid:
        cursor.execute(query, uid)
    return helper(query)
"""

    graph = SemanticGraphBuilder(language="python").build(code, filename="app.py")
    counts = _edge_counts(graph)

    for edge_type in [
        EdgeType.CFG_BRANCH_TRUE,
        EdgeType.CFG_BRANCH_FALSE,
        EdgeType.DFG_INTERP,
        EdgeType.CALL_ARG,
        EdgeType.CALL_RETURN,
        EdgeType.TAINT_SOURCE,
        EdgeType.TAINT_SINK,
        EdgeType.SANITIZED,
        EdgeType.HTTP_ROUTE,
        EdgeType.HTTP_MIDDLEWARE,
        EdgeType.AUTH_COVERAGE,
        EdgeType.PERMISSION_FLOW,
        EdgeType.ORM_FLOW,
        EdgeType.SQL_PARAM,
        EdgeType.DEFINES,
        EdgeType.USES,
    ]:
        assert counts.get(edge_type.value, 0) > 0, edge_type.value


def test_javascript_enrichment_emits_template_property_and_call_edges():
    code = """
function run(id) {
  return id;
}

app.use(authMiddleware);
app.get('/users/:id', requireAuth, (req, res) => {
  const query = `SELECT * FROM users WHERE id=${req.params.id}`;
  db.query(query, req.params.id);
  return run(query);
});
"""

    graph = SemanticGraphBuilder(language="javascript").build(code, filename="app.js")
    counts = _edge_counts(graph)

    for edge_type in [
        EdgeType.DFG_TEMPLATE,
        EdgeType.DFG_PROPERTY,
        EdgeType.DFG_ATTR,
        EdgeType.CALL_ARG,
        EdgeType.CALL_RETURN,
        EdgeType.HTTP_MIDDLEWARE,
        EdgeType.PERMISSION_FLOW,
        EdgeType.ORM_FLOW,
        EdgeType.SQL_PARAM,
    ]:
        assert counts.get(edge_type.value, 0) > 0, edge_type.value
