"""
HTML + Template Parser for XSS Analysis
========================================

Parses HTML and template files to identify:
- Input vectors (forms, inputs, event handlers)
- Output sinks (template interpolation, innerHTML, etc.)
- Frontend-to-backend connections

Supports multiple template engines:
- Jinja2 (Flask): {{ var }}, {% ... %}
- Django: {{ var }}, {% ... %}
- EJS (Express): <%= var %>, <%- var %>
- Handlebars: {{ var }}, {{{ var }}}
- React JSX: {var}
"""

from typing import List, Dict, Set, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
import re

try:
    from app.domain.analysis.universal_parser import UniversalParser, LanguageType, StandardNode
    TREE_SITTER_HTML_AVAILABLE = True
except Exception:
    TREE_SITTER_HTML_AVAILABLE = False

from app.schemas.graph import GraphNode, GraphEdge, SemanticGraph, NodeMetadata
from app.enums.node_type import NodeType
from app.enums.edge_type import EdgeType


class HTMLNodeType(str, Enum):
    """Node types specific to HTML/template analysis"""
    HTML_FORM = "HTML_FORM"
    HTML_INPUT = "HTML_INPUT"
    HTML_TEXTAREA = "HTML_TEXTAREA"
    HTML_SELECT = "HTML_SELECT"
    HTML_BUTTON = "HTML_BUTTON"
    HTML_EVENT_HANDLER = "HTML_EVENT_HANDLER"
    HTML_TEMPLATE_VAR = "HTML_TEMPLATE_VAR"
    HTML_SCRIPT_TAG = "HTML_SCRIPT_TAG"
    HTML_ANCHOR = "HTML_ANCHOR"
    HTML_IFRAME = "HTML_IFRAME"


class HTMLEdgeType(str, Enum):
    """Edge types for HTML flow analysis"""
    FORM_SUBMIT = "FORM_SUBMIT"           # Form → Backend route
    EVENT_TRIGGER = "EVENT_TRIGGER"       # Event handler → JS function
    TEMPLATE_RENDER = "TEMPLATE_RENDER"   # Backend data → Template output
    INPUT_TO_FORM = "INPUT_TO_FORM"       # Input field → Form
    FORM_TO_ROUTE = "FORM_TO_ROUTE"       # Form action → Backend route
    DATA_TO_TEMPLATE = "DATA_TO_TEMPLATE" # Backend variable → Template variable


class TemplateEngine(str, Enum):
    """Supported template engines"""
    JINJA2 = "jinja2"           # Flask: {{ var }}, {% %}
    DJANGO = "django"           # Django: {{ var }}, {% %}
    EJS = "ejs"                 # Express: <%= var %>, <%- var %>
    HANDLEBARS = "handlebars"   # Handlebars: {{ var }}, {{{ var }}}
    MUSTACHE = "mustache"       # Mustache: {{ var }}
    PUG = "pug"                 # Pug/Jade: #{var}
    JSX = "jsx"                 # React: {var}
    PLAIN_HTML = "plain_html"   # No template engine


@dataclass
class HTMLForm:
    """Represents an HTML form"""
    action: str                        # Form action URL
    method: str                        # GET, POST, etc.
    inputs: List['HTMLInput']          # Form inputs
    node_id: str                       # Node ID in graph
    line_number: int
    is_ajax: bool = False              # Submitted via AJAX


@dataclass
class HTMLInput:
    """Represents an HTML input field"""
    name: str                          # Input name attribute
    input_type: str                    # text, password, email, etc.
    node_id: str                       # Node ID in graph
    line_number: int
    default_value: Optional[str] = None
    is_required: bool = False


@dataclass
class HTMLEventHandler:
    """Represents an HTML event handler"""
    event_type: str                    # onclick, onload, onmouseover, etc.
    handler_code: str                  # JavaScript code
    node_id: str                       # Node ID in graph
    element_type: str                  # button, div, etc.
    line_number: int


@dataclass
class TemplateVariable:
    """Represents a template variable (output sink)"""
    variable_name: str                 # Variable being rendered
    template_syntax: str               # Original syntax: {{ var }}, <%= var %>, etc.
    is_safe: bool                      # Safe/escaped output
    node_id: str                       # Node ID in graph
    line_number: int
    engine: TemplateEngine


class HTMLParser:
    """
    HTML and Template Parser
    
    Extracts security-relevant elements from HTML and template files:
    - Forms and inputs (XSS/injection entry points)
    - Event handlers (DOM-based XSS)
    - Template variables (XSS output sinks)
    - Links and navigation
    
    Uses regex-based parsing (partial parsing allowed).
    """
    
    # Template syntax patterns
    TEMPLATE_PATTERNS = {
        TemplateEngine.JINJA2: [
            (r'\{\{([^}]+)\}\}', False),           # {{ var }} - auto-escaped
            (r'\{\{([^}]+)\|safe\}\}', True),      # {{ var|safe }} - not escaped
            (r'\{\{([^}]+)\|raw\}\}', True),       # {{ var|raw }} - not escaped
        ],
        TemplateEngine.DJANGO: [
            (r'\{\{([^}]+)\}\}', False),           # {{ var }} - auto-escaped
            (r'\{\{([^}]+)\|safe\}\}', True),      # {{ var|safe }} - not escaped
        ],
        TemplateEngine.EJS: [
            (r'<%=([^%]+)%>', False),              # <%= var %> - escaped
            (r'<%-([^%]+)%>', True),               # <%- var %> - not escaped
        ],
        TemplateEngine.HANDLEBARS: [
            (r'\{\{([^}]+)\}\}', False),           # {{ var }} - escaped
            (r'\{\{\{([^}]+)\}\}\}', True),        # {{{ var }}} - not escaped
        ],
        TemplateEngine.JSX: [
            (r'\{([^}]+)\}', True),                # {var} - not auto-escaped
            (r'dangerouslySetInnerHTML=\{\{__html:\s*([^}]+)\}\}', True),
        ],
    }
    
    # Event handler attributes (DOM-based XSS vectors)
    EVENT_HANDLERS = [
        'onclick', 'ondblclick', 'onmousedown', 'onmouseup', 'onmouseover',
        'onmousemove', 'onmouseout', 'onmouseenter', 'onmouseleave',
        'onload', 'onunload', 'onchange', 'onsubmit', 'onreset',
        'onselect', 'onblur', 'onfocus', 'onkeydown', 'onkeypress',
        'onkeyup', 'onerror', 'onabort', 'onbeforeunload'
    ]
    
    def __init__(self, file_path: str, content: str):
        """
        Initialize HTML parser
        
        Args:
            file_path: Path to HTML/template file
            content: File content
        """
        self.file_path = file_path
        self.content = content
        self.lines = content.split('\n')
        
        # Detect template engine
        self.template_engine = self._detect_template_engine()
        
        # Parsed elements
        self.forms: List[HTMLForm] = []
        self.inputs: List[HTMLInput] = []
        self.event_handlers: List[HTMLEventHandler] = []
        self.template_vars: List[TemplateVariable] = []
        self.script_blocks: List[Tuple[str, int]] = []
        self.dom_sinks: List[Tuple[str, int]] = []
        
        # Graph nodes and edges
        self.nodes: List[GraphNode] = []
        self.edges: List[GraphEdge] = []
        
        # Node ID counter
        self.node_counter = 0

        # Tree-sitter parser (optional)
        self.ts_parser: Optional[UniversalParser] = None
        if TREE_SITTER_HTML_AVAILABLE:
            try:
                self.ts_parser = UniversalParser()
            except Exception:
                self.ts_parser = None
    
    def parse(self) -> SemanticGraph:
        """
        Parse HTML/template file
        
        Returns:
            SemanticGraph with HTML nodes and edges
        """
        print(f"Parsing HTML: {Path(self.file_path).name} ({self.template_engine.value})")
        
        # Extract elements
        if self.ts_parser:
            self._parse_with_tree_sitter()
            # Template vars are still regex-based (engine-specific)
            self._extract_template_variables()
        else:
            self._extract_forms()
            self._extract_event_handlers()
            self._extract_template_variables()
            self._extract_script_blocks()
        
        # Build graph nodes
        self._build_nodes()
        self._build_edges()
        
        print(f"  ✓ Found: {len(self.forms)} forms, {len(self.inputs)} inputs, "
              f"{len(self.event_handlers)} event handlers, {len(self.template_vars)} template vars")
        
        return SemanticGraph(
            nodes=self.nodes,
            edges=self.edges
        )

    def _parse_with_tree_sitter(self):
        """Parse HTML using tree-sitter and populate forms/inputs/events."""
        root = self.ts_parser.parse_code(self.content, LanguageType.HTML, self.file_path)
        if not root:
            self._extract_forms()
            self._extract_event_handlers()
            self._extract_script_blocks()
            return

        def walk(node: StandardNode):
            if node.type == "element":
                self._handle_element_node(node)
            for child in node.children:
                walk(child)

        walk(root)
    
    def _detect_template_engine(self) -> TemplateEngine:
        """Detect template engine from file extension and content"""
        ext = Path(self.file_path).suffix.lower()
        
        # Check extension first
        if ext in ['.jinja', '.jinja2', '.j2']:
            return TemplateEngine.JINJA2
        elif ext == '.ejs':
            return TemplateEngine.EJS
        elif ext in ['.hbs', '.handlebars']:
            return TemplateEngine.HANDLEBARS
        elif ext == '.pug':
            return TemplateEngine.PUG
        elif ext in ['.jsx', '.tsx']:
            return TemplateEngine.JSX
        
        # Check content patterns
        if re.search(r'\{\%.*?\%\}|\{\{.*?\}\}', self.content):
            # Could be Jinja2 or Django
            if 'extends' in self.content or 'block' in self.content:
                return TemplateEngine.JINJA2
            return TemplateEngine.DJANGO
        elif re.search(r'<%.*?%>', self.content):
            return TemplateEngine.EJS
        elif re.search(r'\{\{\{.*?\}\}\}', self.content):
            return TemplateEngine.HANDLEBARS
        elif re.search(r'\{[^}]+\}', self.content) and ext in ['.js', '.ts']:
            return TemplateEngine.JSX
        
        return TemplateEngine.PLAIN_HTML
    
    def _extract_forms(self):
        """Extract HTML forms and their inputs"""
        # Regex for form tags
        form_pattern = r'<form\s+([^>]*?)>(.*?)</form>'
        
        for match in re.finditer(form_pattern, self.content, re.DOTALL | re.IGNORECASE):
            form_attrs = match.group(1)
            form_content = match.group(2)
            line_num = self.content[:match.start()].count('\n') + 1
            
            # Extract action and method
            action_match = re.search(r'action=["\'](.*?)["\']', form_attrs, re.IGNORECASE)
            method_match = re.search(r'method=["\'](.*?)["\']', form_attrs, re.IGNORECASE)
            
            action = action_match.group(1) if action_match else ""
            method = method_match.group(1).upper() if method_match else "GET"
            
            # Check for AJAX
            is_ajax = 'onsubmit' in form_attrs.lower() and 'preventdefault' in form_content.lower()
            
            # Extract inputs in this form
            form_inputs = self._extract_inputs_from_content(form_content, line_num)
            
            form = HTMLForm(
                action=action,
                method=method,
                inputs=form_inputs,
                node_id=self._generate_node_id(),
                line_number=line_num,
                is_ajax=is_ajax
            )
            
            self.forms.append(form)
            self.inputs.extend(form_inputs)
    
    def _extract_inputs_from_content(self, content: str, base_line: int) -> List[HTMLInput]:
        """Extract input fields from HTML content"""
        inputs = []
        
        # Input pattern
        input_pattern = r'<input\s+([^>]*?)/?>'
        
        for match in re.finditer(input_pattern, content, re.IGNORECASE):
            attrs = match.group(1)
            line_num = base_line + content[:match.start()].count('\n')
            
            # Extract attributes
            name_match = re.search(r'name=["\'](.*?)["\']', attrs, re.IGNORECASE)
            type_match = re.search(r'type=["\'](.*?)["\']', attrs, re.IGNORECASE)
            value_match = re.search(r'value=["\'](.*?)["\']', attrs, re.IGNORECASE)
            required = 'required' in attrs.lower()
            
            if name_match:  # Only include inputs with names
                input_field = HTMLInput(
                    name=name_match.group(1),
                    input_type=type_match.group(1) if type_match else 'text',
                    node_id=self._generate_node_id(),
                    line_number=line_num,
                    default_value=value_match.group(1) if value_match else None,
                    is_required=required
                )
                inputs.append(input_field)
        
        # Also extract textareas
        textarea_pattern = r'<textarea\s+([^>]*?)>.*?</textarea>'
        for match in re.finditer(textarea_pattern, content, re.DOTALL | re.IGNORECASE):
            attrs = match.group(1)
            line_num = base_line + content[:match.start()].count('\n')
            
            name_match = re.search(r'name=["\'](.*?)["\']', attrs, re.IGNORECASE)
            if name_match:
                input_field = HTMLInput(
                    name=name_match.group(1),
                    input_type='textarea',
                    node_id=self._generate_node_id(),
                    line_number=line_num
                )
                inputs.append(input_field)
        
        return inputs
    
    def _extract_event_handlers(self):
        """Extract event handlers (DOM XSS vectors)"""
        for event_name in self.EVENT_HANDLERS:
            pattern = rf'{event_name}=["\']([^"\']*)["\']'
            
            for match in re.finditer(pattern, self.content, re.IGNORECASE):
                handler_code = match.group(1)
                line_num = self.content[:match.start()].count('\n') + 1
                
                # Find element type
                element_start = self.content.rfind('<', 0, match.start())
                element_match = re.search(r'<(\w+)', self.content[element_start:match.start()])
                element_type = element_match.group(1) if element_match else 'unknown'
                
                handler = HTMLEventHandler(
                    event_type=event_name,
                    handler_code=handler_code,
                    node_id=self._generate_node_id(),
                    element_type=element_type,
                    line_number=line_num
                )
                
                self.event_handlers.append(handler)
    
    def _extract_template_variables(self):
        """Extract template variables (output sinks)"""
        patterns = self.TEMPLATE_PATTERNS.get(self.template_engine, [])
        
        for pattern, is_unsafe in patterns:
            for match in re.finditer(pattern, self.content):
                var_name = match.group(1).strip()
                line_num = self.content[:match.start()].count('\n') + 1
                
                template_var = TemplateVariable(
                    variable_name=var_name,
                    template_syntax=match.group(0),
                    is_safe=is_unsafe,  # is_safe means "marked as safe" (dangerous!)
                    node_id=self._generate_node_id(),
                    line_number=line_num,
                    engine=self.template_engine
                )
                
                self.template_vars.append(template_var)
    
    def _extract_script_blocks(self):
        """Extract inline script blocks"""
        script_pattern = r'<script[^>]*>(.*?)</script>'
        
        for match in re.finditer(script_pattern, self.content, re.DOTALL | re.IGNORECASE):
            script_content = match.group(1)
            line_num = self.content[:match.start()].count('\n') + 1
            
            self.script_blocks.append((script_content, line_num))
            for sink in ("innerHTML", "outerHTML", "document.write", "dangerouslySetInnerHTML"):
                if sink in script_content:
                    self.dom_sinks.append((sink, line_num))

    # ==============================
    # Tree-sitter HTML helpers
    # ==============================

    def _handle_element_node(self, node: 'StandardNode'):
        """Handle a tree-sitter HTML element node."""
        start_tag = self._extract_start_tag(node)
        if not start_tag:
            return

        tag_name = self._parse_tag_name(start_tag)
        attrs = self._parse_attributes(start_tag)
        line_number = node.start_point[0] + 1

        if tag_name == "form":
            action = attrs.get("action", "")
            method = attrs.get("method", "GET").upper()
            form_node_id = self._generate_node_id()
            self.forms.append(HTMLForm(
                action=action,
                method=method,
                inputs=[],
                node_id=form_node_id,
                line_number=line_number,
                is_ajax=False
            ))
        elif tag_name in ("input", "textarea", "select"):
            name = attrs.get("name", tag_name)
            input_type = attrs.get("type", "text") if tag_name == "input" else tag_name
            input_node_id = self._generate_node_id()
            input_obj = HTMLInput(
                name=name,
                input_type=input_type,
                node_id=input_node_id,
                line_number=line_number,
                default_value=attrs.get("value"),
                is_required="required" in attrs
            )
            self.inputs.append(input_obj)
            if self.forms:
                self.forms[-1].inputs.append(input_obj)
        elif tag_name == "button":
            input_node_id = self._generate_node_id()
            input_obj = HTMLInput(
                name=attrs.get("name", "button"),
                input_type="button",
                node_id=input_node_id,
                line_number=line_number,
                default_value=attrs.get("value"),
                is_required=False
            )
            self.inputs.append(input_obj)
            if self.forms:
                self.forms[-1].inputs.append(input_obj)

        # Event handlers (DOM XSS)
        for attr, value in attrs.items():
            if attr.lower().startswith("on") and value:
                handler_id = self._generate_node_id()
                self.event_handlers.append(HTMLEventHandler(
                    event_type=attr.lower(),
                    handler_code=value,
                    node_id=handler_id,
                    element_type=tag_name,
                    line_number=line_number
                ))

        # Script blocks
        if tag_name == "script":
            if node.source_code:
                self.script_blocks.append((node.source_code, line_number))

    def _extract_start_tag(self, node: 'StandardNode') -> Optional[str]:
        """Extract the start tag source from an element node."""
        for child in node.children:
            if child.type == "start_tag":
                return child.source_code
        return node.source_code

    # Extract and lowercase the HTML tag name from a start-tag string.
    def _parse_tag_name(self, start_tag: str) -> str:
        match = re.search(r'<\s*([a-zA-Z0-9:_-]+)', start_tag)
        return match.group(1).lower() if match else ""

    # Parse all key-value attribute pairs from a start-tag string into a dict.
    def _parse_attributes(self, start_tag: str) -> Dict[str, str]:
        attrs: Dict[str, str] = {}
        pattern = r"([:@\w-]+)(?:\s*=\s*(\"[^\"]*\"|'[^']*'|[^\s>]+))?"
        for match in re.finditer(pattern, start_tag):
            key = match.group(1)
            value = match.group(2) or ""
            value = value.strip("\"'")
            attrs[key] = value
        return attrs
    
    def _build_nodes(self):
        """Build graph nodes from parsed elements"""
        # Form nodes
        for form in self.forms:
            node = GraphNode(
                id=form.node_id,
                type=NodeType.EXPRESSION,  # Using existing enum
                name=f"form_{form.action}",
                file=self.file_path,
                line=form.line_number,
                column=0,
                metadata=NodeMetadata(
                    security_role="source" if form.method == "POST" else None
                ),
                source_code=f'<form action="{form.action}" method="{form.method}">',
                # Store HTML-specific metadata in value field
                value={
                    'html_node_type': HTMLNodeType.HTML_FORM.value,
                    'form_action': form.action,
                    'form_method': form.method,
                    'is_ajax': form.is_ajax
                }
            )
            self.nodes.append(node)
        
        # Input nodes
        for input_field in self.inputs:
            node = GraphNode(
                id=input_field.node_id,
                type=NodeType.IDENTIFIER,
                name=input_field.name,
                file=self.file_path,
                line=input_field.line_number,
                column=0,
                metadata=NodeMetadata(
                    security_role="source",
                    is_tainted=True
                ),
                source_code=f'<input name="{input_field.name}" type="{input_field.input_type}">',
                value={
                    'html_node_type': HTMLNodeType.HTML_INPUT.value,
                    'input_type': input_field.input_type,
                    'input_name': input_field.name
                }
            )
            self.nodes.append(node)
        
        # Event handler nodes
        for handler in self.event_handlers:
            node = GraphNode(
                id=handler.node_id,
                type=NodeType.EXPRESSION,
                name=handler.event_type,
                file=self.file_path,
                line=handler.line_number,
                column=0,
                metadata=NodeMetadata(
                    security_role="sink"  # DOM XSS sink
                ),
                source_code=f'{handler.event_type}="{handler.handler_code}"',
                value={
                    'html_node_type': HTMLNodeType.HTML_EVENT_HANDLER.value,
                    'event_type': handler.event_type,
                    'handler_code': handler.handler_code,
                    'onclick': handler.handler_code if handler.event_type == "onclick" else None,
                    'action': None
                }
            )
            self.nodes.append(node)
        
        # Template variable nodes (XSS sinks)
        for template_var in self.template_vars:
            node = GraphNode(
                id=template_var.node_id,
                type=NodeType.IDENTIFIER,
                name=template_var.variable_name,
                file=self.file_path,
                line=template_var.line_number,
                column=0,
                metadata=NodeMetadata(
                    security_role="sink"  # XSS sink
                ),
                source_code=template_var.template_syntax,
                value={
                    'html_node_type': HTMLNodeType.HTML_TEMPLATE_VAR.value,
                    'template_var': template_var.variable_name,
                    'is_safe_output': template_var.is_safe,
                    'template_engine': template_var.engine.value
                }
            )
            self.nodes.append(node)

        # DOM sink nodes from script blocks
        for sink_name, line_num in self.dom_sinks:
            node = GraphNode(
                id=self._generate_node_id(),
                type=NodeType.DOM_PROPERTY,
                name=sink_name,
                file=self.file_path,
                line=line_num,
                column=0,
                metadata=NodeMetadata(
                    security_role="sink"
                ),
                source_code=sink_name,
                value={
                    'html_node_type': HTMLNodeType.HTML_SCRIPT_TAG.value,
                    'dom_sink': sink_name
                }
            )
            self.nodes.append(node)
    
    def _build_edges(self):
        """Build edges between HTML elements"""
        # Link inputs to their forms
        for form in self.forms:
            for input_field in form.inputs:
                edge = GraphEdge(
                    **{
                        "from": input_field.node_id,
                        "to": form.node_id,
                        "type": EdgeType.DATA_FLOW
                    }
                )
                edge.metadata = {
                    'html_edge_type': HTMLEdgeType.INPUT_TO_FORM.value,
                    'input_name': input_field.name
                }
                self.edges.append(edge)
    
    def _generate_node_id(self) -> str:
        """Generate unique node ID"""
        self.node_counter += 1
        return f"html_{Path(self.file_path).stem}_{self.node_counter}"
    
    def get_xss_sources(self) -> List[GraphNode]:
        """Get all potential XSS sources (user inputs)"""
        return [node for node in self.nodes 
                if node.metadata and node.metadata.get('security_role') == 'source']
    
    def get_xss_sinks(self) -> List[GraphNode]:
        """Get all potential XSS sinks (outputs)"""
        return [node for node in self.nodes 
                if node.metadata and node.metadata.get('security_role') == 'sink']


# Helper function for integration
def parse_html_file(file_path: str) -> SemanticGraph:
    """
    Parse an HTML/template file
    
    Args:
        file_path: Path to HTML/template file
    
    Returns:
        SemanticGraph with HTML nodes
    """
    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
        content = f.read()
    
    parser = HTMLParser(file_path, content)
    return parser.parse()
