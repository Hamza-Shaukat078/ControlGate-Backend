"""
HTML-to-Backend Linker for XSS Path Detection
==============================================

Links HTML/template files to backend code:
- Forms → Backend routes
- Template variables → Backend data sources
- Complete XSS paths (input → backend → template → output)

Supports:
- Flask routes (@app.route)
- Express routes (app.get, app.post)
- Django views (urlpatterns)
"""

from typing import List, Dict, Optional, Tuple
from pathlib import Path
import re

from app.schemas.graph import GraphNode, GraphEdge, SemanticGraph , NodeType
from app.enums.edge_type import EdgeType
from app.domain.analysis.html_parser import HTMLParser, HTMLEdgeType, HTMLNodeType


class HTMLBackendLinker:
    """
    Links HTML elements to backend code
    
    Creates edges:
    - HTML forms → Backend route handlers
    - Backend variables → Template variables
    - Complete XSS paths
    """
    
    def __init__(
        self,
        html_graph: SemanticGraph,
        backend_graph: SemanticGraph,
        html_file: str,
        backend_files: List[str]
    ):
        """
        Initialize linker
        
        Args:
            html_graph: Graph from HTML parser
            backend_graph: Graph from backend code (CPG)
            html_file: Path to HTML/template file
            backend_files: List of backend file paths
        """
        self.html_graph = html_graph
        self.backend_graph = backend_graph
        self.html_file = html_file
        self.backend_files = backend_files
        
        # Route mappings
        self.route_to_handler: Dict[str, str] = {}  # URL → handler node ID
        self.handler_to_template: Dict[str, str] = {}  # handler ID → template path
        self.template_vars: Dict[str, List[str]] = {}  # template → [var names]
        
        # Cross-file edges
        self.cross_file_edges: List[GraphEdge] = []
    
    def link(self) -> List[GraphEdge]:
        """
        Create links between HTML and backend
        
        Returns:
            List of cross-file edges
        """
        print("Linking HTML to backend...")
        
        # Step 1: Extract backend routes
        self._extract_backend_routes()
        
        # Step 2: Link forms to routes
        self._link_forms_to_routes()
        
        # Step 3: Link template variables to backend data
        self._link_template_variables()

        # Step 4: Link DOM event handlers to backend routes (heuristic)
        self._link_dom_handlers()
        
        print(f"  ✓ Created {len(self.cross_file_edges)} cross-file edges")
        
        return self.cross_file_edges
    
    def _extract_backend_routes(self):
        """Extract route definitions from backend code"""
        for node in self.backend_graph.nodes:
            # Flask: @app.route('/path')
            if node.source_code and '@app.route' in node.source_code:
                route_match = re.search(r'@app\.route\(["\']([^"\']+)["\']', node.source_code)
                if route_match:
                    route = route_match.group(1)
                    # Find the function node (should be next)
                    self.route_to_handler[route] = node.id

            # Flask Blueprint: @bp.route('/path')
            elif node.source_code and re.search(r'@\w+\.route\(', node.source_code):
                route_match = re.search(r'@\w+\.route\(["\']([^"\']+)["\']', node.source_code)
                if route_match:
                    route = route_match.group(1)
                    self.route_to_handler[route] = node.id

            # FastAPI / Starlette: @app.get('/path') / @router.post('/path')
            elif node.source_code and re.search(r'@(app|router)\.(get|post|put|delete|patch|options|head)\(', node.source_code):
                route_match = re.search(r'@(app|router)\.\w+\(["\']([^"\']+)["\']', node.source_code)
                if route_match:
                    route = route_match.group(2)
                    self.route_to_handler[route] = node.id
            
            # Express: app.get('/path', handler)
            elif node.source_code and re.search(r'app\.(get|post|put|delete)\(', node.source_code):
                route_match = re.search(r'app\.\w+\(["\']([^"\']+)["\']', node.source_code)
                if route_match:
                    route = route_match.group(1)
                    self.route_to_handler[route] = node.id

            # Express Router: router.get('/path', handler)
            elif node.source_code and re.search(r'router\.(get|post|put|delete)\(', node.source_code):
                route_match = re.search(r'router\.\w+\(["\']([^"\']+)["\']', node.source_code)
                if route_match:
                    route = route_match.group(1)
                    self.route_to_handler[route] = node.id
            
            # Django: path('path/', view)
            elif node.source_code and 'path(' in node.source_code:
                route_match = re.search(r'path\(["\']([^"\']+)["\']', node.source_code)
                if route_match:
                    route = route_match.group(1)
                    self.route_to_handler[route] = node.id

            # Django: re_path('regex', view) / url('regex', view)
            elif node.source_code and ('re_path(' in node.source_code or 'url(' in node.source_code):
                route_match = re.search(r'(re_path|url)\(["\']([^"\']+)["\']', node.source_code)
                if route_match:
                    route = route_match.group(2)
                    self.route_to_handler[route] = node.id
            
            # Template rendering: render_template('file.html', var=data)
            if node.source_code:
                # Flask
                template_match = re.search(
                    r'render_template\(["\']([^"\']+)["\']([^)]*)\)',
                    node.source_code
                )
                if template_match:
                    template_name = template_match.group(1)
                    var_args = template_match.group(2)
                    self.handler_to_template[node.id] = template_name
                    
                    # Extract variables passed to template
                    vars_passed = re.findall(r'(\w+)=', var_args)
                    self.template_vars[template_name] = vars_passed
                
                # Express: res.render('file', {var: data})
                template_match = re.search(
                    r'res\.render\(["\']([^"\']+)["\']',
                    node.source_code
                )
                if template_match:
                    template_name = template_match.group(1)
                    self.handler_to_template[node.id] = template_name

                # Django: render(request, "file.html", {...})
                template_match = re.search(
                    r'render\([^,]+,\s*["\']([^"\']+)["\']',
                    node.source_code
                )
                if template_match:
                    template_name = template_match.group(1)
                    self.handler_to_template[node.id] = template_name

                # FastAPI: templates.TemplateResponse("file.html", {...})
                template_match = re.search(
                    r'TemplateResponse\(["\']([^"\']+)["\']',
                    node.source_code
                )
                if template_match:
                    template_name = template_match.group(1)
                    self.handler_to_template[node.id] = template_name
    
    def _link_forms_to_routes(self):
        """Link HTML forms to backend route handlers"""
        for node in self.html_graph.nodes:
            # Check if this is a form node (HTML-specific data in value field)
            if node.value and node.value.get('html_node_type') == HTMLNodeType.HTML_FORM.value:
                form_action = node.value.get('form_action', '')
                
                # Find matching backend route
                handler_id = self._find_route_handler(form_action)
                
                if handler_id:
                    # Create edge: Form → Backend handler
                    edge = GraphEdge(
                        **{
                            "from": node.id,
                            "to": handler_id,
                            "type": EdgeType.CALL_GRAPH
                        }
                    )
                    edge.metadata = {
                        'html_edge_type': HTMLEdgeType.FORM_TO_ROUTE.value,
                        'form_action': form_action,
                        'source_file': self.html_file,
                        'target_file': self._find_handler_file(handler_id)
                    }
                    self.cross_file_edges.append(edge)

                # Also link form to known endpoints (HTTP_ENDPOINT nodes)
                for handler in self.backend_graph.nodes:
                    if handler.type == NodeType.HTTP_ENDPOINT:
                        if form_action and (form_action in (handler.name or "")):
                            edge = GraphEdge(
                                **{
                                    "from": node.id,
                                    "to": handler.id,
                                    "type": EdgeType.HTTP_FLOW
                                }
                            )
                            edge.metadata = {
                                'html_edge_type': HTMLEdgeType.FORM_TO_ROUTE.value,
                                'form_action': form_action,
                                'source_file': self.html_file,
                                'target_file': handler.file
                            }
                            self.cross_file_edges.append(edge)
    
    def _link_template_variables(self):
        """Link template variables to backend data sources"""
        # Get template name from HTML file
        template_name = Path(self.html_file).name
        
        # Find template variables in HTML (HTML-specific data in value field)
        html_template_nodes = [
            node for node in self.html_graph.nodes
            if node.value and node.value.get('html_node_type') == HTMLNodeType.HTML_TEMPLATE_VAR.value
        ]
        
        # Find backend variables passed to this template
        for handler_id, tmpl_name in self.handler_to_template.items():
            if tmpl_name == template_name or tmpl_name in self.html_file:
                # Find variable assignments in backend handler
                backend_var_nodes = self._find_handler_variables(handler_id)
                
                for html_var_node in html_template_nodes:
                    var_name = html_var_node.value.get('template_var', '')
                    
                    # Match with backend variable
                    for backend_var_node in backend_var_nodes:
                        if backend_var_node.name == var_name or var_name in (backend_var_node.source_code or ''):
                            # Create edge: Backend var → Template var
                            edge = GraphEdge(
                                **{
                                    "from": backend_var_node.id,
                                    "to": html_var_node.id,
                                    "type": EdgeType.DATA_FLOW
                                }
                            )
                            edge.metadata = {
                                'html_edge_type': HTMLEdgeType.DATA_TO_TEMPLATE.value,
                                'variable_name': var_name,
                                'source_file': backend_var_node.file,
                                'target_file': self.html_file,
                                'is_xss_sink': True
                            }
                            self.cross_file_edges.append(edge)
    
    def _find_route_handler(self, form_action: str) -> Optional[str]:
        """Find backend handler for a route"""
        # Exact match
        if form_action in self.route_to_handler:
            return self.route_to_handler[form_action]
        
        # Try without leading/trailing slashes
        normalized = form_action.strip('/')
        for route, handler_id in self.route_to_handler.items():
            if route.strip('/') == normalized:
                return handler_id
        
        # Try parameter matching: /user/<id> matches /user/123
        for route, handler_id in self.route_to_handler.items():
            if self._routes_match(route, form_action):
                return handler_id
        
        return None
    
    def _routes_match(self, pattern: str, actual: str) -> bool:
        """Check if route pattern matches actual URL"""
        # Convert Flask/Django patterns to regex
        # /user/<id> → /user/[^/]+
        # /user/<int:id> → /user/\d+
        pattern_regex = pattern
        pattern_regex = re.sub(r'<int:\w+>', r'\\d+', pattern_regex)
        pattern_regex = re.sub(r'<\w+>', r'[^/]+', pattern_regex)
        pattern_regex = '^' + pattern_regex + '$'
        
        return bool(re.match(pattern_regex, actual))
    
    def _find_handler_file(self, handler_id: str) -> str:
        """Find file containing handler node"""
        for node in self.backend_graph.nodes:
            if node.id == handler_id:
                return node.file
        return ""
    
    def _find_handler_variables(self, handler_id: str) -> List[GraphNode]:
        """Find all variable nodes in a handler function"""
        # Find all nodes in the handler's scope
        handler_nodes = []
        
        for node in self.backend_graph.nodes:
            # Simple heuristic: nodes in same file and nearby lines
            if node.file == self._find_handler_file(handler_id):
                handler_nodes.append(node)
        
        return handler_nodes

    def _link_dom_handlers(self):
        """Link DOM event handlers and inline scripts to backend routes."""
        for node in self.html_graph.nodes:
            if node.value and node.value.get('html_node_type') == HTMLNodeType.HTML_EVENT_HANDLER.value:
                handler_code = node.value.get('handler_code', '')
                # Heuristic: fetch('/path') or $.ajax('/path')
                match = re.search(r'["\'](/[^"\']+)["\']', handler_code)
                if match:
                    action = match.group(1)
                    handler_id = self._find_route_handler(action)
                    if handler_id:
                        edge = GraphEdge(
                            **{
                                "from": node.id,
                                "to": handler_id,
                                "type": EdgeType.HTTP_FLOW
                            }
                        )
                        edge.metadata = {
                            'html_edge_type': HTMLEdgeType.EVENT_TRIGGER.value,
                            'form_action': action,
                            'source_file': self.html_file,
                            'target_file': self._find_handler_file(handler_id)
                        }
                        self.cross_file_edges.append(edge)


def extract_xss_paths(
    html_graph: SemanticGraph,
    backend_graph: SemanticGraph,
    cross_file_edges: List[GraphEdge]
) -> List[List[GraphEdge]]:
    """
    Extract complete XSS paths from input to output
    
    Args:
        html_graph: HTML graph
        backend_graph: Backend graph
        cross_file_edges: Edges linking HTML and backend
    
    Returns:
        List of XSS paths (each path is a list of edges)
    """
    # Combine all edges
    all_edges = (
        list(html_graph.edges) + 
        list(backend_graph.edges) + 
        cross_file_edges
    )
    
    # Build edge lookup
    edges_from_node: Dict[str, List[GraphEdge]] = {}
    for edge in all_edges:
        from_node = edge.from_node
        if from_node not in edges_from_node:
            edges_from_node[from_node] = []
        edges_from_node[from_node].append(edge)
    
    # Find sources (HTML inputs)
    sources = [
        node for node in html_graph.nodes
        if node.metadata and node.metadata.security_role == 'source'
    ]
    
    # Find sinks (Template variables)
    sinks = [
        node for node in html_graph.nodes
        if node.metadata and node.metadata.security_role == 'sink'
    ]
    
    # DFS to find paths
    xss_paths = []
    
    for source in sources:
        for sink in sinks:
            paths = _dfs_path(source.id, sink.id, edges_from_node, max_depth=20)
            xss_paths.extend(paths)
    
    return xss_paths


def _dfs_path(
    start: str,
    end: str,
    edges_from_node: Dict[str, List[GraphEdge]],
    max_depth: int = 20,
    visited: Optional[set] = None,
    current_path: Optional[List[GraphEdge]] = None
) -> List[List[GraphEdge]]:
    """DFS to find all paths from start to end"""
    if visited is None:
        visited = set()
    if current_path is None:
        current_path = []
    
    if len(current_path) >= max_depth:
        return []
    
    if start == end:
        return [current_path.copy()]
    
    if start in visited:
        return []
    
    visited.add(start)
    paths = []
    
    for edge in edges_from_node.get(start, []):
        next_node = edge.to_node
        current_path.append(edge)
        
        sub_paths = _dfs_path(
            next_node, end, edges_from_node,
            max_depth, visited.copy(), current_path.copy()
        )
        paths.extend(sub_paths)
        
        current_path.pop()
    
    return paths
