"""
Code Property Graph (CPG) Parser using Tree-sitter
Similar to Joern/CodeQL for JavaScript and TypeScript

This module provides:
- Complete AST extraction with Tree-sitter
- Lexical scope tracking (functions, blocks, closures)
- Symbol table construction
- Reference resolution
- CPG-compatible output for DFG/CFG construction
- Error-tolerant parsing

Author: Vulcan Static Analysis Engine
"""

from dataclasses import dataclass, field
from typing import Optional, List, Dict, Set, Tuple, Any
from pathlib import Path
from enum import Enum
import logging

try:
    from tree_sitter import Language, Parser, Node as TSNode
    TREE_SITTER_AVAILABLE = True
except ImportError:
    TREE_SITTER_AVAILABLE = False
    logging.warning("tree-sitter not installed")
    from typing import Any as TSNode

from app.schemas.graph import GraphNode, GraphEdge, SemanticGraph, NodeMetadata
from app.enums.node_type import NodeType
from app.enums.edge_type import EdgeType
from app.core.trace import trace_step

logger = logging.getLogger(__name__)


class LanguageType(Enum):
    """Supported languages for CPG extraction"""
    JAVASCRIPT = "javascript"
    TYPESCRIPT = "typescript"
    PYTHON = "python"


@dataclass
class ScopeInfo:
    """Scope information for lexical scoping"""
    scope_id: str
    scope_type: str  # "global", "function", "block", "class"
    parent_scope_id: Optional[str]
    symbols: Dict[str, str]  # symbol_name -> node_id
    start_line: int
    end_line: int


@dataclass
class SymbolReference:
    """Symbol reference for data flow tracking"""
    symbol_name: str
    node_id: str
    scope_id: str
    is_declaration: bool
    is_write: bool
    is_read: bool


class CPGParser:
    """
    Code Property Graph Parser
    
    Extracts a complete CPG from JavaScript/TypeScript code:
    - AST nodes with full parent/child relationships
    - Lexical scopes and symbol tables
    - Symbol references (declarations and uses)
    - Function/class/import extraction
    - Member expression chains (obj.prop.method)
    - Call expression tracking
    
    Output is compatible with DFG/CFG construction pipelines.
    """
    
    def __init__(self, grammar_path: Optional[Path] = None):
        """Initialize CPG parser with Tree-sitter grammars"""
        trace_step("CPG: CPGParser.__init__() (app/domain/analysis/cpg_parser.py)")
        if not TREE_SITTER_AVAILABLE:
            raise RuntimeError("tree-sitter is required. Install: pip install tree-sitter==0.21.3")
        
        self.grammar_path = grammar_path or self._find_grammar_path()
        self.languages: Dict[LanguageType, Language] = {}
        self.parsers: Dict[LanguageType, Parser] = {}
        
        # Load grammars
        self._load_languages()
        
        # CPG state
        self.node_counter = 0
        self.scopes: Dict[str, ScopeInfo] = {}
        self.current_scope_id: Optional[str] = None
        self.symbol_references: List[SymbolReference] = []
        self.symbol_table: Dict[str, List[str]] = {}  # symbol -> [node_ids]
        self.call_nodes: List[GraphNode] = []
        self._source_bytes: Optional[bytes] = None

    def _slice_source(self, start: int, end: int, source_code: str) -> str:
        """Slice source using byte offsets from tree-sitter."""
        if self._source_bytes is not None:
            return self._source_bytes[start:end].decode("utf-8", errors="ignore")
        return source_code[start:end]

    def has_language(self, language: LanguageType | str) -> bool:
        """Return True if parser for language is loaded."""
        lang = self._normalize_language(language)
        if not lang:
            return False
        return lang in self.parsers

    def available_languages(self) -> List[str]:
        """Return list of loaded language names."""
        return [lang.value for lang in self.parsers.keys()]
    
    def _find_grammar_path(self) -> Path:
        """Find grammar files directory"""
        candidates = [
            Path.cwd() / "build",
            Path.cwd() / "tree-sitter-grammars",
            Path.home() / ".tree-sitter",
        ]
        
        for path in candidates:
            if path.exists() and path.is_dir():
                return path
        
        default_path = Path.cwd() / "build"
        default_path.mkdir(exist_ok=True)
        return default_path
    
    def _load_languages(self):
        """Load grammars with compatibility for both old/new tree-sitter APIs."""

        def _create_parser(language_obj: Language) -> Parser:
            # Prefer explicit set_language for old API stacks; fallback to Parser(language).
            # This avoids creating an unbound parser that later fails on parse().
            try:
                parser = Parser()
                parser.set_language(language_obj)
                return parser
            except Exception:
                return Parser(language_obj)

        loaded_any = False

        # Prefer the legacy tree_sitter_languages API when it is compatible with
        # the installed tree-sitter runtime.
        try:
            from tree_sitter_languages import get_language

            language_names = {
                LanguageType.PYTHON: "python",
                LanguageType.JAVASCRIPT: "javascript",
                LanguageType.TYPESCRIPT: "typescript",
            }

            for lang, name in language_names.items():
                try:
                    language = get_language(name)
                    self.languages[lang] = language
                    self.parsers[lang] = _create_parser(language)
                    loaded_any = True
                    logger.info(f"Loaded {lang.value} grammar via tree_sitter_languages")
                except Exception as inner_exc:
                    logger.debug(f"Fallback grammar load failed for {lang.value}: {inner_exc}")
        except Exception as fallback_exc:
            logger.debug(f"tree_sitter_languages fallback unavailable: {fallback_exc}")

        # For newer tree-sitter wheels (like 0.25.x), use the dedicated grammar
        # packages. These expose PyCapsules that can be wrapped by Language(...).
        package_loaders = {
            LanguageType.PYTHON: ("tree_sitter_python", "language"),
            LanguageType.JAVASCRIPT: ("tree_sitter_javascript", "language"),
            LanguageType.TYPESCRIPT: ("tree_sitter_typescript", "language_typescript"),
        }

        for lang, (module_name, attr_name) in package_loaders.items():
            if lang in self.parsers:
                continue
            try:
                module = __import__(module_name, fromlist=[attr_name])
                capsule_fn = getattr(module, attr_name)
                language = Language(capsule_fn())
                self.languages[lang] = language
                self.parsers[lang] = _create_parser(language)
                loaded_any = True
                logger.info(f"Loaded {lang.value} grammar via {module_name}")
            except Exception as package_exc:
                logger.debug(f"Direct grammar load failed for {lang.value}: {package_exc}")

        if not loaded_any:
            logger.warning(
                "No Tree-sitter grammars loaded. Install compatible parser packages "
                "or pin tree-sitter to the versions documented by this project."
            )

    def _normalize_language(self, language: LanguageType | str) -> Optional[LanguageType]:
        """Normalize language input to LanguageType enum."""
        if isinstance(language, LanguageType):
            return language
        if isinstance(language, str):
            name = language.lower()
            if name in ["python", "py"]:
                return LanguageType.PYTHON
            if name in ["javascript", "js", "jsx"]:
                return LanguageType.JAVASCRIPT
            if name in ["typescript", "ts", "tsx"]:
                return LanguageType.TYPESCRIPT
        return None
    
    def parse_file(self, filepath: str, language: Optional[LanguageType | str] = None) -> SemanticGraph:
        """
        Parse a JavaScript or TypeScript file into a CPG.
        
        Args:
            filepath: Path to .js or .ts file
            
        Returns:
            SemanticGraph with full CPG representation
        """
        trace_step(f"CPG: parse_file(filepath={filepath}) (app/domain/analysis/cpg_parser.py)")
        # Detect language
        ext = Path(filepath).suffix.lower()
        if language is None:
            if ext in ['.ts', '.tsx']:
                lang = LanguageType.TYPESCRIPT
            elif ext in ['.js', '.jsx', '.mjs', '.cjs']:
                lang = LanguageType.JAVASCRIPT
            elif ext in ['.py', '.pyw']:
                lang = LanguageType.PYTHON
            else:
                lang = LanguageType.JAVASCRIPT
        else:
            lang = self._normalize_language(language)
            if lang is None:
                logger.error(f"Unsupported language: {language}")
                return SemanticGraph(nodes=[], edges=[])
        
        # Read source code
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                source_code = f.read()
        except Exception as e:
            logger.error(f"Failed to read {filepath}: {e}")
            return SemanticGraph(nodes=[], edges=[])
        
        return self.parse_code(source_code, lang, filepath)
    
    def parse_code(self, source_code: str, language: LanguageType | str, filename: str = "unknown") -> SemanticGraph:
        """
        Parse source code into a Code Property Graph.
        
        Args:
            source_code: JavaScript/TypeScript source code
            language: Language type
            filename: Filename for reference
            
        Returns:
            SemanticGraph with:
            - AST nodes (functions, classes, expressions)
            - Scope information
            - Symbol references
            - Parent/child relationships
        """
        trace_step(f"CPG: parse_code(language={language}, filename={filename}) (app/domain/analysis/cpg_parser.py)")
        lang = self._normalize_language(language)
        if lang is None:
            logger.error(f"Unsupported language: {language}")
            return SemanticGraph(nodes=[], edges=[])
        if lang not in self.parsers:
            logger.error(f"No parser for {lang.value}")
            return SemanticGraph(nodes=[], edges=[])
        
        # Reset state
        self.node_counter = 0
        self.scopes = {}
        self.current_scope_id = None
        self.symbol_references = []
        self.symbol_table = {}
        self.call_nodes = []
        self._source_bytes = source_code.encode("utf-8", errors="ignore")
        
        try:
            # Parse with Tree-sitter
            parser = self.parsers[lang]
            tree = parser.parse(bytes(source_code, "utf8"))
            
            # Check for errors (but continue anyway - error-tolerant)
            if tree.root_node.has_error:
                logger.warning(f"Syntax errors in {filename}, continuing with partial parse")
            
            # Create CPG
            nodes: List[GraphNode] = []
            edges: List[GraphEdge] = []
            
            # Create file root node
            file_node_id = self._next_id()
            file_node = GraphNode(
                id=file_node_id,
                type=NodeType.FILE,
                name=filename,
                file=filename,
                line=1,
                column=0,
                metadata=NodeMetadata(
                    language=lang.value,
                    scope_id="global"
                )
            )
            nodes.append(file_node)
            
            # Create global scope
            global_scope = ScopeInfo(
                scope_id="global",
                scope_type="global",
                parent_scope_id=None,
                symbols={},
                start_line=1,
                end_line=tree.root_node.end_point[0] + 1
            )
            self.scopes["global"] = global_scope
            self.current_scope_id = "global"
            
            # Extract CPG from AST
            self._extract_cpg(tree.root_node, file_node_id, source_code, filename, nodes, edges, lang)

            # Build symbol table
            for ref in self.symbol_references:
                if ref.symbol_name not in self.symbol_table:
                    self.symbol_table[ref.symbol_name] = []
                self.symbol_table[ref.symbol_name].append(ref.node_id)

            # Link call graph edges (name-based resolution)
            self._link_call_graph(nodes, edges)
            
            # Create semantic graph
            graph = SemanticGraph(
                nodes=nodes,
                edges=edges,
                symbol_table=self.symbol_table,
                scopes={sid: {
                    "type": scope.scope_type,
                    "parent": scope.parent_scope_id,
                    "symbols": scope.symbols,
                    "range": (scope.start_line, scope.end_line)
                } for sid, scope in self.scopes.items()}
            )
            
            logger.info(f"Extracted CPG: {len(nodes)} nodes, {len(edges)} edges, {len(self.scopes)} scopes")
            
            return graph
            
        except Exception as e:
            logger.error(f"Failed to parse {filename}: {e}")
            import traceback
            traceback.print_exc()
            return SemanticGraph(nodes=[], edges=[])
    
    def _extract_cpg(
        self,
        ts_node: TSNode,
        parent_id: str,
        source_code: str,
        filename: str,
        nodes: List[GraphNode],
        edges: List[GraphEdge],
        language: LanguageType
    ):
        """
        Recursively extract CPG nodes from Tree-sitter AST.
        
        This is the core method that:
        - Identifies important constructs (functions, classes, etc.)
        - Creates scope boundaries
        - Tracks symbol declarations and references
        - Builds parent/child relationships
        """
        node_type = ts_node.type

        # A bare `function` keyword token (leaf, no children) vs. a real
        # function-expression node sharing the same type name — see the
        # NOTE in _should_skip. Only the keyword-token form gets skipped here.
        if node_type == "function" and ts_node.child_count <= 1:
            for child in ts_node.children:
                self._extract_cpg(child, parent_id, source_code, filename, nodes, edges, language)
            return

        # Skip certain node types
        if self._should_skip(node_type):
            for child in ts_node.children:
                self._extract_cpg(child, parent_id, source_code, filename, nodes, edges, language)
            return
        
        # Extract source code for this node
        start_byte = ts_node.start_byte
        end_byte = ts_node.end_byte
        node_source = self._slice_source(start_byte, end_byte, source_code)
        
        # Truncate long source code
        if len(node_source) > 200:
            node_source = node_source[:200] + "..."
        
        # Create node based on type
        node_id = self._next_id()
        graph_node = None
        
        # ROUTE DECORATORS (Python)
        if node_type == "decorator":
            graph_node = self._extract_decorator(ts_node, node_id, source_code, filename, language)
            if graph_node:
                nodes.append(graph_node)
                edges.append(GraphEdge(from_node=parent_id, to_node=node_id, type=EdgeType.AST_CHILD))

        # FUNCTION DECLARATIONS
        #
        # tree-sitter-javascript types a function *expression* (named or
        # anonymous — e.g. `return function inner(y) {...}` or a callback
        # literal passed as a call argument) as a bare "function" node, the
        # same type name used for the `function` *keyword* token that's a
        # leaf child of every function_declaration/function node. Guard on
        # child_count to tell them apart: the keyword token has none, the
        # real expression node has formal_parameters/statement_block children.
        is_function_expression_node = node_type == "function" and ts_node.child_count > 1
        if node_type in ("function_declaration", "function_definition", "function_expression") or is_function_expression_node:
            graph_node = self._extract_function(ts_node, node_id, source_code, filename, language)
            if graph_node:
                nodes.append(graph_node)
                edges.append(GraphEdge(from_node=parent_id, to_node=node_id, type=EdgeType.AST_CHILD))
                
                # Create function scope
                self._enter_scope(node_id, "function", ts_node, graph_node.name)
                # Create parameter nodes
                for param_node in self._extract_parameters(ts_node, node_id, source_code, filename, language):
                    nodes.append(param_node)
                    edges.append(GraphEdge(from_node=node_id, to_node=param_node.id, type=EdgeType.AST_CHILD))
                # Attach decorators (Python): link decorator nodes to function
                for child in ts_node.children:
                    if child.type == "decorator":
                        decorator_node_id = self._next_id()
                        deco_node = self._extract_decorator(child, decorator_node_id, source_code, filename, language)
                        if deco_node:
                            nodes.append(deco_node)
                            edges.append(GraphEdge(from_node=node_id, to_node=decorator_node_id, type=EdgeType.AST_CHILD))
                
                # Process children
                for child in ts_node.children:
                    self._extract_cpg(child, node_id, source_code, filename, nodes, edges, language)
                
                self._exit_scope()
                return
        
        # ARROW FUNCTIONS
        elif node_type == "arrow_function":
            graph_node = self._extract_arrow_function(ts_node, node_id, source_code, filename, language)
            if graph_node:
                nodes.append(graph_node)
                edges.append(GraphEdge(from_node=parent_id, to_node=node_id, type=EdgeType.AST_CHILD))
                
                # Create function scope
                self._enter_scope(node_id, "function", ts_node, graph_node.name or "anonymous")
                # Create parameter nodes
                for param_node in self._extract_parameters(ts_node, node_id, source_code, filename, language):
                    nodes.append(param_node)
                    edges.append(GraphEdge(from_node=node_id, to_node=param_node.id, type=EdgeType.AST_CHILD))
                
                for child in ts_node.children:
                    self._extract_cpg(child, node_id, source_code, filename, nodes, edges, language)
                
                self._exit_scope()
                return
        
        # CLASS DECLARATIONS
        elif node_type in ("class_declaration", "class_definition"):
            graph_node = self._extract_class(ts_node, node_id, source_code, filename, language)
            if graph_node:
                nodes.append(graph_node)
                edges.append(GraphEdge(from_node=parent_id, to_node=node_id, type=EdgeType.AST_CHILD))
                
                # Create class scope
                self._enter_scope(node_id, "class", ts_node, graph_node.name)
                
                for child in ts_node.children:
                    self._extract_cpg(child, node_id, source_code, filename, nodes, edges, language)
                
                self._exit_scope()
                return
        
        # METHOD DEFINITIONS
        elif node_type == "method_definition":
            graph_node = self._extract_method(ts_node, node_id, source_code, filename, language)
            if graph_node:
                nodes.append(graph_node)
                edges.append(GraphEdge(from_node=parent_id, to_node=node_id, type=EdgeType.AST_CHILD))
                
                self._enter_scope(node_id, "function", ts_node, graph_node.name)
                # Create parameter nodes
                for param_node in self._extract_parameters(ts_node, node_id, source_code, filename, language):
                    nodes.append(param_node)
                    edges.append(GraphEdge(from_node=node_id, to_node=param_node.id, type=EdgeType.AST_CHILD))
                
                for child in ts_node.children:
                    self._extract_cpg(child, node_id, source_code, filename, nodes, edges, language)
                
                self._exit_scope()
                return
        
        # CONTROL FLOW
        elif node_type in ("if_statement", "if_statement_clause", "elif_clause", "else_clause"):
            graph_node = self._extract_generic_node(ts_node, node_id, source_code, filename, language, NodeType.IF_STATEMENT, "if")
            if graph_node:
                nodes.append(graph_node)
                edges.append(GraphEdge(from_node=parent_id, to_node=node_id, type=EdgeType.AST_CHILD))
        elif node_type in ("for_statement", "for_in_statement"):
            graph_node = self._extract_generic_node(ts_node, node_id, source_code, filename, language, NodeType.FOR_STATEMENT, "for")
            if graph_node:
                nodes.append(graph_node)
                edges.append(GraphEdge(from_node=parent_id, to_node=node_id, type=EdgeType.AST_CHILD))
        elif node_type == "while_statement":
            graph_node = self._extract_generic_node(ts_node, node_id, source_code, filename, language, NodeType.WHILE_STATEMENT, "while")
            if graph_node:
                nodes.append(graph_node)
                edges.append(GraphEdge(from_node=parent_id, to_node=node_id, type=EdgeType.AST_CHILD))
        elif node_type in ("try_statement", "try"):
            graph_node = self._extract_generic_node(ts_node, node_id, source_code, filename, language, NodeType.TRY_STATEMENT, "try")
            if graph_node:
                nodes.append(graph_node)
                edges.append(GraphEdge(from_node=parent_id, to_node=node_id, type=EdgeType.AST_CHILD))
        elif node_type in ("except_clause", "except_handler", "catch_clause"):
            graph_node = self._extract_generic_node(ts_node, node_id, source_code, filename, language, NodeType.EXCEPT_HANDLER, "except")
            if graph_node:
                nodes.append(graph_node)
                edges.append(GraphEdge(from_node=parent_id, to_node=node_id, type=EdgeType.AST_CHILD))
        elif node_type in ("raise_statement", "throw_statement"):
            graph_node = self._extract_generic_node(ts_node, node_id, source_code, filename, language, NodeType.RAISE, "raise")
            if graph_node:
                nodes.append(graph_node)
                edges.append(GraphEdge(from_node=parent_id, to_node=node_id, type=EdgeType.AST_CHILD))
        elif node_type == "return_statement":
            graph_node = self._extract_generic_node(ts_node, node_id, source_code, filename, language, NodeType.RETURN, "return")
            if graph_node:
                nodes.append(graph_node)
                edges.append(GraphEdge(from_node=parent_id, to_node=node_id, type=EdgeType.AST_CHILD))

        # IMPORTS
        elif node_type in ("import_statement", "import_declaration", "import_specifier", "import_from_statement"):
            graph_node = self._extract_import(ts_node, node_id, source_code, filename, language)
            if graph_node:
                nodes.append(graph_node)
                edges.append(GraphEdge(from_node=parent_id, to_node=node_id, type=EdgeType.AST_CHILD))
        
        # EXPORTS
        elif node_type in ("export_statement", "export_declaration", "export_clause", "export_specifier"):
            graph_node = self._extract_export(ts_node, node_id, source_code, filename, language)
            if graph_node:
                nodes.append(graph_node)
                edges.append(GraphEdge(from_node=parent_id, to_node=node_id, type=EdgeType.AST_CHILD))
        
        # CALL EXPRESSIONS
        elif node_type in ("call_expression", "call"):
            graph_node = self._extract_call(ts_node, node_id, source_code, filename, language)
            if graph_node:
                nodes.append(graph_node)
                edges.append(GraphEdge(from_node=parent_id, to_node=node_id, type=EdgeType.AST_CHILD))
                self.call_nodes.append(graph_node)

        # STRINGS / TEMPLATES
        elif node_type in ("string", "string_literal"):
            graph_node = self._extract_literal_or_string(ts_node, node_id, source_code, filename, language)
            if graph_node:
                nodes.append(graph_node)
                edges.append(GraphEdge(from_node=parent_id, to_node=node_id, type=EdgeType.AST_CHILD))
        elif node_type in ("template_string", "template_substitution"):
            graph_node = self._extract_generic_node(ts_node, node_id, source_code, filename, language, NodeType.TEMPLATE_LITERAL, "template")
            if graph_node:
                nodes.append(graph_node)
                edges.append(GraphEdge(from_node=parent_id, to_node=node_id, type=EdgeType.AST_CHILD))
        elif node_type in ("interpolation", "formatted_string", "f_string"):
            graph_node = self._extract_generic_node(ts_node, node_id, source_code, filename, language, NodeType.FSTRING, "fstring")
            if graph_node:
                nodes.append(graph_node)
                edges.append(GraphEdge(from_node=parent_id, to_node=node_id, type=EdgeType.AST_CHILD))
        elif node_type in ("binary_expression", "binary_operator"):
            graph_node = self._extract_string_or_binary(ts_node, node_id, source_code, filename, language)
            if graph_node:
                nodes.append(graph_node)
                edges.append(GraphEdge(from_node=parent_id, to_node=node_id, type=EdgeType.AST_CHILD))
        
        # MEMBER EXPRESSIONS (obj.prop.method)
        elif node_type in ("member_expression", "attribute"):
            graph_node = self._extract_member_expression(ts_node, node_id, source_code, filename, language)
            if graph_node:
                nodes.append(graph_node)
                edges.append(GraphEdge(from_node=parent_id, to_node=node_id, type=EdgeType.AST_CHILD))
        
        # VARIABLE DECLARATIONS
        elif node_type == "variable_declaration":
            graph_node = self._extract_variable_declaration(ts_node, node_id, source_code, filename, language)
            if graph_node:
                nodes.append(graph_node)
                edges.append(GraphEdge(from_node=parent_id, to_node=node_id, type=EdgeType.AST_CHILD))
        elif node_type in ("assignment", "assignment_expression"):
            graph_node = self._extract_assignment(ts_node, node_id, source_code, filename, language)
            if graph_node:
                nodes.append(graph_node)
                edges.append(GraphEdge(from_node=parent_id, to_node=node_id, type=EdgeType.AST_CHILD))
        
        # IDENTIFIERS (symbol references)
        elif node_type == "identifier":
            graph_node = self._extract_identifier(ts_node, node_id, source_code, filename, language)
            if graph_node:
                nodes.append(graph_node)
                edges.append(GraphEdge(from_node=parent_id, to_node=node_id, type=EdgeType.AST_CHILD))
        elif node_type in ("integer", "float", "true", "false", "none", "null", "number"):
            graph_node = self._extract_generic_node(ts_node, node_id, source_code, filename, language, NodeType.LITERAL, "literal")
            if graph_node:
                nodes.append(graph_node)
                edges.append(GraphEdge(from_node=parent_id, to_node=node_id, type=EdgeType.AST_CHILD))
        
        # BLOCK STATEMENTS (create scope)
        elif node_type == "statement_block":
            self._enter_scope(self._next_id(), "block", ts_node, "block")
            
            for child in ts_node.children:
                self._extract_cpg(child, parent_id, source_code, filename, nodes, edges, language)
            
            self._exit_scope()
            return
        
        # Process remaining children
        for child in ts_node.children:
            self._extract_cpg(child, parent_id if not graph_node else node_id, source_code, filename, nodes, edges, language)
    
    def _extract_function(self, ts_node: TSNode, node_id: str, source_code: str, filename: str, language: LanguageType) -> Optional[GraphNode]:
        """Extract function declaration"""
        name = self._find_child_text(ts_node, "identifier", source_code)
        
        # Check for async
        is_async = any(child.type == "async" for child in ts_node.children)
        
        # Check for generator
        is_generator = any(child.type == "*" for child in ts_node.children)
        
        metadata = NodeMetadata(
            language=language.value,
            scope_id=self.current_scope_id,
            symbol_name=name,
            is_async=is_async,
            is_generator=is_generator
        )
        
        # Register symbol
        if name:
            self._register_symbol(name, node_id, is_declaration=True)
        func_node = GraphNode(
            id=node_id,
            type=NodeType.ASYNC_FUNCTION if is_async else NodeType.FUNCTION,
            name=name or "anonymous",
            file=filename,
            line=ts_node.start_point[0] + 1,
            column=ts_node.start_point[1],
            source_code=self._slice_source(ts_node.start_byte, ts_node.end_byte, source_code)[:200],
            metadata=metadata
        )
        return func_node
    
    def _extract_arrow_function(self, ts_node: TSNode, node_id: str, source_code: str, filename: str, language: LanguageType) -> Optional[GraphNode]:
        """Extract arrow function"""
        # Arrow functions might not have names (anonymous)
        # Try to find parent variable declarator for name
        name = "anonymous"
        
        is_async = "async" in self._slice_source(ts_node.start_byte, ts_node.start_byte + 10, source_code)
        
        metadata = NodeMetadata(
            language=language.value,
            scope_id=self.current_scope_id,
            is_async=is_async
        )
        
        return GraphNode(
            id=node_id,
            type=NodeType.ARROW_FUNCTION,
            name=name,
            file=filename,
            line=ts_node.start_point[0] + 1,
            column=ts_node.start_point[1],
            source_code=self._slice_source(ts_node.start_byte, ts_node.end_byte, source_code)[:200],
            metadata=metadata
        )

    def _extract_generic_node(
        self,
        ts_node: TSNode,
        node_id: str,
        source_code: str,
        filename: str,
        language: LanguageType,
        node_type: NodeType,
        default_name: str
    ) -> Optional[GraphNode]:
        """Extract a typed generic node while preserving source text."""
        text = self._slice_source(ts_node.start_byte, ts_node.end_byte, source_code)
        metadata = NodeMetadata(
            language=language.value,
            scope_id=self.current_scope_id
        )
        return GraphNode(
            id=node_id,
            type=node_type,
            name=default_name,
            value=text[:200] if node_type in {NodeType.LITERAL, NodeType.SQL_QUERY} else None,
            file=filename,
            line=ts_node.start_point[0] + 1,
            column=ts_node.start_point[1],
            source_code=text[:500],
            metadata=metadata
        )

    def _extract_literal_or_string(self, ts_node: TSNode, node_id: str, source_code: str, filename: str, language: LanguageType) -> Optional[GraphNode]:
        """Extract string literals, upgrading f-strings and SQL-looking strings."""
        text = self._slice_source(ts_node.start_byte, ts_node.end_byte, source_code)
        stripped = text.lstrip()
        lowered = text.lower()
        if stripped.startswith(("f'", 'f"', "F'", 'F"')):
            node_type = NodeType.FSTRING
            name = "fstring"
        elif any(word in lowered for word in ("select ", "insert ", "update ", "delete ", "drop ", " where ")):
            node_type = NodeType.SQL_QUERY
            name = "sql"
        else:
            node_type = NodeType.LITERAL
            name = "string"
        return self._extract_generic_node(ts_node, node_id, source_code, filename, language, node_type, name)

    def _extract_string_or_binary(self, ts_node: TSNode, node_id: str, source_code: str, filename: str, language: LanguageType) -> Optional[GraphNode]:
        """Extract binary expressions, tagging string concatenation when likely."""
        text = self._slice_source(ts_node.start_byte, ts_node.end_byte, source_code)
        node_type = NodeType.STRING_CONCAT if "+" in text and any(q in text for q in ("'", '"', "`")) else NodeType.BINARY_OP
        name = "string_concat" if node_type == NodeType.STRING_CONCAT else "binary"
        return self._extract_generic_node(ts_node, node_id, source_code, filename, language, node_type, name)
    
    def _extract_class(self, ts_node: TSNode, node_id: str, source_code: str, filename: str, language: LanguageType) -> Optional[GraphNode]:
        """Extract class declaration"""
        name = self._find_child_text(ts_node, "identifier", source_code) or "AnonymousClass"
        
        metadata = NodeMetadata(
            language=language.value,
            scope_id=self.current_scope_id,
            symbol_name=name
        )
        
        if name:
            self._register_symbol(name, node_id, is_declaration=True)
        
        return GraphNode(
            id=node_id,
            type=NodeType.CLASS,
            name=name,
            file=filename,
            line=ts_node.start_point[0] + 1,
            column=ts_node.start_point[1],
            source_code=self._slice_source(ts_node.start_byte, ts_node.end_byte, source_code)[:200],
            metadata=metadata
        )
    
    def _extract_method(self, ts_node: TSNode, node_id: str, source_code: str, filename: str, language: LanguageType) -> Optional[GraphNode]:
        """Extract method definition"""
        name = self._find_child_text(ts_node, "property_identifier", source_code)
        
        is_async = any(child.type == "async" for child in ts_node.children)
        is_generator = any(child.type == "*" for child in ts_node.children)
        
        # Check visibility (TypeScript)
        visibility = None
        for child in ts_node.children:
            if child.type in ("public", "private", "protected"):
                visibility = child.type
                break
        
        metadata = NodeMetadata(
            language=language.value,
            scope_id=self.current_scope_id,
            symbol_name=name,
            is_async=is_async,
            is_generator=is_generator,
            visibility=visibility
        )
        
        return GraphNode(
            id=node_id,
            type=NodeType.FUNCTION,
            name=name or "method",
            file=filename,
            line=ts_node.start_point[0] + 1,
            column=ts_node.start_point[1],
            source_code=self._slice_source(ts_node.start_byte, ts_node.end_byte, source_code)[:200],
            metadata=metadata
        )
    
    def _extract_import(self, ts_node: TSNode, node_id: str, source_code: str, filename: str, language: LanguageType) -> Optional[GraphNode]:
        """Extract import statement"""
        import_text = self._slice_source(ts_node.start_byte, ts_node.end_byte, source_code)
        
        # Extract imported names
        imported_names = []
        for child in ts_node.children:
            if child.type in ("identifier", "import_clause"):
                name = self._slice_source(child.start_byte, child.end_byte, source_code)
                imported_names.append(name)
        
        metadata = NodeMetadata(
            language=language.value,
            scope_id=self.current_scope_id
        )
        
        return GraphNode(
            id=node_id,
            type=NodeType.IMPORT,
            name=", ".join(imported_names) if imported_names else "import",
            value=import_text[:100],
            file=filename,
            line=ts_node.start_point[0] + 1,
            column=ts_node.start_point[1],
            source_code=import_text,
            metadata=metadata
        )
    
    def _extract_export(self, ts_node: TSNode, node_id: str, source_code: str, filename: str, language: LanguageType) -> Optional[GraphNode]:
        """Extract export statement"""
        export_text = self._slice_source(ts_node.start_byte, ts_node.end_byte, source_code)
        
        metadata = NodeMetadata(
            language=language.value,
            scope_id=self.current_scope_id,
            is_exported=True
        )
        
        return GraphNode(
            id=node_id,
            type=NodeType.EXPRESSION,
            name="export",
            value=export_text[:100],
            file=filename,
            line=ts_node.start_point[0] + 1,
            column=ts_node.start_point[1],
            source_code=export_text,
            metadata=metadata
        )
    
    def _extract_call(self, ts_node: TSNode, node_id: str, source_code: str, filename: str, language: LanguageType) -> Optional[GraphNode]:
        """Extract call expression"""
        call_text = self._slice_source(ts_node.start_byte, ts_node.end_byte, source_code)
        
        # Extract function name
        func_name = None
        for child in ts_node.children:
            if child.type in ("identifier", "member_expression", "attribute"):
                func_name = self._slice_source(child.start_byte, child.end_byte, source_code)
                break
        
        metadata = NodeMetadata(
            language=language.value,
            scope_id=self.current_scope_id
        )
        
        call_type = NodeType.CALL_EXPRESSION
        lowered = call_text.lower()
        if any(token in lowered for token in ["eval(", "exec(", "function("]):
            call_type = NodeType.EVAL_CALL
        elif any(token in lowered for token in ["system(", "popen(", "subprocess.", "child_process"]):
            call_type = NodeType.SYSTEM_CALL
        elif any(token in lowered for token in ["fetch(", "axios.", "requests.", "http.", "https."]):
            call_type = NodeType.EXTERNAL_CALL
        elif any(token in lowered for token in ["execute(", ".query(", ".raw(", ".filter(", ".find(", ".aggregate("]):
            call_type = NodeType.ORM_QUERY

        return GraphNode(
            id=node_id,
            type=call_type,
            name=func_name or "call",
            value=call_text[:100],
            file=filename,
            line=ts_node.start_point[0] + 1,
            column=ts_node.start_point[1],
            source_code=call_text,
            metadata=metadata
        )

    def _extract_decorator(self, ts_node: TSNode, node_id: str, source_code: str, filename: str, language: LanguageType) -> Optional[GraphNode]:
        """Extract Python decorator (route/auth)."""
        decorator_text = self._slice_source(ts_node.start_byte, ts_node.end_byte, source_code)
        metadata = NodeMetadata(
            language=language.value,
            scope_id=self.current_scope_id
        )
        node_type = NodeType.ROUTE_DECORATOR if "route" in decorator_text or "router." in decorator_text else NodeType.EXPRESSION
        if any(tok in decorator_text for tok in ["login_required", "permission_required", "authorize", "is_authenticated"]):
            metadata.security_role = "sink"
            node_type = NodeType.AUTH_GUARD
        return GraphNode(
            id=node_id,
            type=node_type,
            name="decorator",
            value=decorator_text[:100],
            file=filename,
            line=ts_node.start_point[0] + 1,
            column=ts_node.start_point[1],
            source_code=decorator_text,
            metadata=metadata
        )
    
    def _extract_member_expression(self, ts_node: TSNode, node_id: str, source_code: str, filename: str, language: LanguageType) -> Optional[GraphNode]:
        """Extract member expression (obj.prop.method)"""
        member_text = self._slice_source(ts_node.start_byte, ts_node.end_byte, source_code)
        
        metadata = NodeMetadata(
            language=language.value,
            scope_id=self.current_scope_id
        )
        
        return GraphNode(
            id=node_id,
            type=NodeType.MEMBER_ACCESS,
            name=member_text[:50],
            value=member_text,
            file=filename,
            line=ts_node.start_point[0] + 1,
            column=ts_node.start_point[1],
            source_code=member_text,
            metadata=metadata
        )
    
    def _extract_variable_declaration(self, ts_node: TSNode, node_id: str, source_code: str, filename: str, language: LanguageType) -> Optional[GraphNode]:
        """Extract variable declaration"""
        var_text = self._slice_source(ts_node.start_byte, ts_node.end_byte, source_code)
        
        # Extract variable names
        var_names = []
        for child in ts_node.children:
            if child.type == "variable_declarator":
                for subchild in child.children:
                    if subchild.type == "identifier":
                        name = self._slice_source(subchild.start_byte, subchild.end_byte, source_code)
                        var_names.append(name)
                        self._register_symbol(name, node_id, is_declaration=True)
        
        metadata = NodeMetadata(
            language=language.value,
            scope_id=self.current_scope_id
        )
        
        return GraphNode(
            id=node_id,
            type=NodeType.ASSIGNMENT,
            name=", ".join(var_names) if var_names else "var",
            value=var_text[:100],
            file=filename,
            line=ts_node.start_point[0] + 1,
            column=ts_node.start_point[1],
            source_code=var_text,
            metadata=metadata
        )

    def _link_call_graph(self, nodes: List[GraphNode], edges: List[GraphEdge]):
        """Create CALL_GRAPH edges by name-based resolution (local scope)."""
        # Build index of functions/methods/classes by name
        name_to_node: Dict[str, List[str]] = {}
        for node in nodes:
            if node.type in {NodeType.FUNCTION, NodeType.ASYNC_FUNCTION, NodeType.METHOD, NodeType.CLASS}:
                if node.name:
                    name_to_node.setdefault(node.name, []).append(node.id)

        for call_node in self.call_nodes:
            callee = call_node.name or ""
            if not callee:
                continue
            # Normalize member access: obj.method -> method
            if "." in callee:
                callee = callee.split(".")[-1]
            targets = name_to_node.get(callee, [])
            for target_id in targets:
                edge = GraphEdge(
                    **{
                        "from": call_node.id,
                        "to": target_id,
                        "type": EdgeType.CALL_GRAPH
                    }
                )
                edge.metadata = {
                    "callee": callee,
                    "resolution": "local_symbol"
                }
                edges.append(edge)

    def _extract_assignment(self, ts_node: TSNode, node_id: str, source_code: str, filename: str, language: LanguageType) -> Optional[GraphNode]:
        """Extract assignment (Python and generic)"""
        assign_text = self._slice_source(ts_node.start_byte, ts_node.end_byte, source_code)
        var_names = []
        # Assignment operators -- anything at or after these is the RHS value, not a target.
        _ASSIGN_OPS = {
            "=", "+=", "-=", "*=", "/=", "//=", "%=", "**=",
            "&=", "|=", "^=", ">>=", "<<=", ":=",
        }
        for child in ts_node.children:
            if child.type in _ASSIGN_OPS:
                break  # everything after the operator is the value, not a target
            if child.type == "identifier":
                name = self._slice_source(child.start_byte, child.end_byte, source_code)
                var_names.append(name)
                self._register_symbol(name, node_id, is_declaration=True)
            elif child.type == "attribute":
                attr_text = self._slice_source(child.start_byte, child.end_byte, source_code)
                if attr_text:
                    var_names.append(attr_text)
        metadata = NodeMetadata(
            language=language.value,
            scope_id=self.current_scope_id
        )
        return GraphNode(
            id=node_id,
            type=NodeType.ASSIGNMENT,
            name=", ".join(var_names) if var_names else "assignment",
            value=assign_text[:100],
            file=filename,
            line=ts_node.start_point[0] + 1,
            column=ts_node.start_point[1],
            source_code=assign_text,
            metadata=metadata
        )
    
    def _extract_identifier(self, ts_node: TSNode, node_id: str, source_code: str, filename: str, language: LanguageType) -> Optional[GraphNode]:
        """Extract identifier (symbol reference)"""
        name = self._slice_source(ts_node.start_byte, ts_node.end_byte, source_code)
        
        # Register as symbol reference (use)
        self._register_symbol(name, node_id, is_declaration=False, is_read=True)
        
        metadata = NodeMetadata(
            language=language.value,
            scope_id=self.current_scope_id,
            symbol_name=name
        )
        
        return GraphNode(
            id=node_id,
            type=NodeType.IDENTIFIER,
            name=name,
            file=filename,
            line=ts_node.start_point[0] + 1,
            column=ts_node.start_point[1],
            source_code=name,
            metadata=metadata
        )

    def _extract_parameters(
        self,
        ts_node: TSNode,
        parent_id: str,
        source_code: str,
        filename: str,
        language: LanguageType
    ) -> List[GraphNode]:
        """Extract parameter nodes from a function/method/arrow function."""
        param_nodes: List[GraphNode] = []

        def collect_identifiers(node: TSNode, out: List[TSNode]):
            if node.type == "identifier":
                out.append(node)
                return
            for child in node.children:
                collect_identifiers(child, out)

        # Common parameter containers across languages
        param_containers = [c for c in ts_node.children if c.type in ("formal_parameters", "parameters", "parameter_list")]

        # Arrow function single-identifier parameter (e.g., x => x)
        if not param_containers:
            for child in ts_node.children:
                if child.type == "identifier":
                    param_containers.append(child)
                    break

        identifiers: List[TSNode] = []
        for container in param_containers:
            if container.type == "identifier":
                identifiers.append(container)
            else:
                collect_identifiers(container, identifiers)

        for ident_node in identifiers:
            name = self._slice_source(ident_node.start_byte, ident_node.end_byte, source_code)
            if not name:
                continue
            node_id = self._next_id()
            # Register symbol as declaration (parameter)
            self._register_symbol(name, node_id, is_declaration=True)
            metadata = NodeMetadata(
                language=language.value,
                scope_id=self.current_scope_id,
                symbol_name=name
            )
            param_nodes.append(
                GraphNode(
                    id=node_id,
                    type=NodeType.PARAMETER,
                    name=name,
                    file=filename,
                    line=ident_node.start_point[0] + 1,
                    column=ident_node.start_point[1],
                    source_code=name,
                    metadata=metadata
                )
            )

        return param_nodes
    
    # Helper methods
    
    def _should_skip(self, node_type: str) -> bool:
        """Check if node type should be skipped"""
        skip_types = {
            "program", "source_file",  # Root nodes
            "(", ")", "{", "}", "[", "]", ",", ";", ":",  # Punctuation
            "comment", "//", "/*", "*/",  # Comments
            # NOTE: "function" is deliberately NOT here — tree-sitter-javascript
            # uses that same type name for both the bare `function` keyword
            # token (a leaf, safe to skip) and actual function *expression*
            # nodes (e.g. `return function inner(y) {...}`, or a callback
            # literal passed as a call argument), which must NOT be skipped.
            # See the child_count guard in _extract_cpg where it's handled.
        }
        return node_type in skip_types
    
    def _find_child_text(self, ts_node: TSNode, child_type: str, source_code: str) -> Optional[str]:
        """Find text of first child with given type"""
        for child in ts_node.children:
            if child.type == child_type:
                return self._slice_source(child.start_byte, child.end_byte, source_code)
        return None
    
    def _enter_scope(self, scope_id: str, scope_type: str, ts_node: TSNode, name: str):
        """Enter a new lexical scope"""
        scope = ScopeInfo(
            scope_id=scope_id,
            scope_type=scope_type,
            parent_scope_id=self.current_scope_id,
            symbols={},
            start_line=ts_node.start_point[0] + 1,
            end_line=ts_node.end_point[0] + 1
        )
        self.scopes[scope_id] = scope
        self.current_scope_id = scope_id
        logger.debug(f"Entered {scope_type} scope '{name}' ({scope_id})")
    
    def _exit_scope(self):
        """Exit current scope"""
        if self.current_scope_id and self.current_scope_id in self.scopes:
            parent_id = self.scopes[self.current_scope_id].parent_scope_id
            logger.debug(f"Exiting scope {self.current_scope_id}")
            self.current_scope_id = parent_id
    
    def _register_symbol(self, symbol_name: str, node_id: str, is_declaration: bool = False, is_write: bool = False, is_read: bool = False):
        """Register a symbol reference"""
        if not symbol_name:
            return
        
        # Add to current scope if declaration
        if is_declaration and self.current_scope_id:
            if self.current_scope_id in self.scopes:
                self.scopes[self.current_scope_id].symbols[symbol_name] = node_id
        
        # Track reference
        ref = SymbolReference(
            symbol_name=symbol_name,
            node_id=node_id,
            scope_id=self.current_scope_id or "global",
            is_declaration=is_declaration,
            is_write=is_write,
            is_read=is_read
        )
        self.symbol_references.append(ref)
    
    def _next_id(self) -> str:
        """Generate unique node ID"""
        node_id = f"node_{self.node_counter}"
        self.node_counter += 1
        return node_id


# Example usage
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    
    # Example JavaScript code
    js_code = """
import { fetch } from 'node-fetch';

async function getUserData(userId) {
    const user = await fetch(`/api/users/${userId}`);
    return user.json();
}

class UserService {
    constructor(apiUrl) {
        this.apiUrl = apiUrl;
    }
    
    async authenticate(username, password) {
        const response = await fetch(this.apiUrl + '/auth', {
            method: 'POST',
            body: JSON.stringify({ username, password })
        });
        return response.json();
    }
}

export { getUserData, UserService };
"""
    
    parser = CPGParser()
    graph = parser.parse_code(js_code, LanguageType.JAVASCRIPT, "example.js")
    
    print(f"\nCPG Extraction Results:")
    print(f"Nodes: {len(graph.nodes)}")
    print(f"Edges: {len(graph.edges)}")
    print(f"Scopes: {len(graph.scopes)}")
    print(f"Symbols: {len(graph.symbol_table)}")
    
    print(f"\nFunction nodes:")
    for node in graph.nodes:
        if node.type in (NodeType.FUNCTION, NodeType.ASYNC_FUNCTION, NodeType.ARROW_FUNCTION):
            print(f"  - {node.name} (line {node.line}, scope: {node.metadata.scope_id if node.metadata else 'N/A'})")
    
    print(f"\nSymbol table:")
    for symbol, node_ids in graph.symbol_table.items():
        print(f"  {symbol}: {len(node_ids)} references")
