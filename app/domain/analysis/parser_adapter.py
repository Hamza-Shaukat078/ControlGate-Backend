"""
Adapter Module: StandardNode to GraphNode Conversion

This module provides seamless integration between the new UniversalParser 
(which outputs StandardNode) and the existing Vulcan graph infrastructure 
(which expects GraphNode).

It allows you to use the new Tree-sitter parser without breaking existing code.
"""

from typing import List, Tuple, Dict, Optional
from app.domain.analysis.universal_parser import StandardNode, UniversalParser, LanguageType
from app.schemas.graph import GraphNode, GraphEdge, SemanticGraph
from app.enums.node_type import NodeType
from app.enums.edge_type import EdgeType
import logging

logger = logging.getLogger(__name__)


class StandardToGraphAdapter:
    """
    Adapter that converts StandardNode trees to GraphNode/GraphEdge format.
    
    This maintains backward compatibility with existing Vulcan infrastructure
    while using the new Tree-sitter parser underneath.
    """
    
    # Mapping from tree-sitter node types to Vulcan NodeType enums
    NODE_TYPE_MAPPING = {
        # Python
        "function_definition": NodeType.FUNCTION,
        "async_function_definition": NodeType.ASYNC_FUNCTION,
        "class_definition": NodeType.CLASS,
        "import_statement": NodeType.IMPORT,
        "import_from_statement": NodeType.IMPORT,
        "call": NodeType.CALL_EXPRESSION,
        "assignment": NodeType.ASSIGNMENT,
        "if_statement": NodeType.IF_STATEMENT,
        "while_statement": NodeType.LOOP,
        "for_statement": NodeType.LOOP,
        "try_statement": NodeType.TRY_CATCH,
        "with_statement": NodeType.CONTEXT_MANAGER,
        "return_statement": NodeType.RETURN,
        "raise_statement": NodeType.RAISE,
        "assert_statement": NodeType.ASSERT,
        
        # JavaScript/TypeScript
        "function_declaration": NodeType.FUNCTION,
        "arrow_function": NodeType.ARROW_FUNCTION,
        "method_definition": NodeType.FUNCTION,
        "class_declaration": NodeType.CLASS,
        "import_statement": NodeType.IMPORT,
        "call_expression": NodeType.CALL_EXPRESSION,
        "variable_declaration": NodeType.ASSIGNMENT,
        "assignment_expression": NodeType.ASSIGNMENT,
        "if_statement": NodeType.IF_STATEMENT,
        "while_statement": NodeType.LOOP,
        "for_statement": NodeType.LOOP,
        "for_in_statement": NodeType.LOOP,
        "do_statement": NodeType.LOOP,
        "try_statement": NodeType.TRY_CATCH,
        "return_statement": NodeType.RETURN,
        "throw_statement": NodeType.RAISE,
        
        # Generic
        "expression_statement": NodeType.EXPRESSION,
        "identifier": NodeType.IDENTIFIER,
        "string": NodeType.LITERAL,
        "number": NodeType.LITERAL,
        "true": NodeType.LITERAL,
        "false": NodeType.LITERAL,
    }
    
    # Initialize counters and the StandardNode-to-GraphNode ID mapping table.
    def __init__(self):
        self.node_counter = 0
        self.node_id_map: Dict[int, str] = {}  # Map StandardNode id to GraphNode id
    
    def convert(self, root: StandardNode, filename: str) -> SemanticGraph:
        """
        Convert a StandardNode tree to GraphNode/GraphEdge format.
        
        Args:
            root: Root StandardNode from UniversalParser
            filename: Source filename
            
        Returns:
            SemanticGraph with GraphNode list and GraphEdge list
        """
        self.node_counter = 0
        self.node_id_map = {}
        
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
            column=0
        )
        nodes.append(file_node)
        
        # Convert tree recursively
        self._convert_node(root, file_node_id, filename, nodes, edges)
        
        return SemanticGraph(nodes=nodes, edges=edges)
    
    # Recursively walk the StandardNode tree, creating a GraphNode and AST_CHILD edge for each non-skipped node.
    def _convert_node(
        self,
        std_node: StandardNode,
        parent_id: str,
        filename: str,
        nodes: List[GraphNode],
        edges: List[GraphEdge]
    ):
        """Recursively convert StandardNode to GraphNode"""
        
        # Skip some node types that don't map well
        if self._should_skip_node(std_node):
            # Still process children
            for child in std_node.children:
                self._convert_node(child, parent_id, filename, nodes, edges)
            return
        
        # Create GraphNode
        node_id = self._next_id()
        node_type = self._map_node_type(std_node)
        
        graph_node = GraphNode(
            id=node_id,
            type=node_type,
            name=std_node.name or std_node.type,
            value=self._extract_value(std_node),
            file=filename,
            line=std_node.start_point[0] + 1,  # Convert to 1-indexed
            column=std_node.start_point[1],
            source_code=std_node.source_code[:200] if std_node.source_code else None  # Truncate long code
        )
        
        nodes.append(graph_node)
        
        # Create edge from parent
        edge = GraphEdge(
            from_node=parent_id,
            to_node=node_id,
            type=EdgeType.AST_CHILD
        )
        edges.append(edge)
        
        # Store mapping
        self.node_id_map[id(std_node)] = node_id
        
        # Process children
        for child in std_node.children:
            self._convert_node(child, node_id, filename, nodes, edges)
    
    # Map a tree-sitter node type string to the closest Vulcan NodeType enum value.
    def _map_node_type(self, std_node: StandardNode) -> NodeType:
        """Map StandardNode type to Vulcan NodeType"""
        node_type = std_node.type
        
        # Direct mapping
        if node_type in self.NODE_TYPE_MAPPING:
            return self.NODE_TYPE_MAPPING[node_type]
        
        # Fallback mappings
        if "function" in node_type.lower():
            return NodeType.FUNCTION
        elif "class" in node_type.lower():
            return NodeType.CLASS
        elif "import" in node_type.lower():
            return NodeType.IMPORT
        elif "call" in node_type.lower():
            return NodeType.CALL_EXPRESSION
        elif "assignment" in node_type.lower() or "declaration" in node_type.lower():
            return NodeType.ASSIGNMENT
        elif "if" in node_type.lower():
            return NodeType.IF_STATEMENT
        elif "loop" in node_type.lower() or "while" in node_type.lower() or "for" in node_type.lower():
            return NodeType.LOOP
        elif "try" in node_type.lower() or "catch" in node_type.lower():
            return NodeType.TRY_CATCH
        elif "return" in node_type.lower():
            return NodeType.RETURN
        
        # Default
        return NodeType.EXPRESSION
    
    # Return True for structural/punctuation nodes that add no semantic value to the graph.
    def _should_skip_node(self, std_node: StandardNode) -> bool:
        """Determine if a node should be skipped (not converted)"""
        skip_types = {
            "module",  # Python root
            "program",  # JS root
            "source_file",  # TS root
            "document",  # HTML root
            "comment",
            "block",
            "(",
            ")",
            "{",
            "}",
            "[",
            "]",
            ",",
            ";",
            ":",
        }
        return std_node.type in skip_types
    
    # Pull a short, meaningful string value from a node: literal source, identifier name, or brief source text.
    def _extract_value(self, std_node: StandardNode) -> Optional[str]:
        """Extract a meaningful value from the node"""
        # For literals, return the source code
        if "literal" in std_node.type.lower() or "string" in std_node.type.lower():
            return std_node.source_code
        
        # For identifiers, return the name
        if std_node.name:
            return std_node.name
        
        # For short nodes, return source
        if std_node.source_code and len(std_node.source_code) < 50:
            return std_node.source_code
        
        return None
    
    # Increment the internal counter and return a unique node ID string.
    def _next_id(self) -> str:
        """Generate unique node ID"""
        node_id = f"node_{self.node_counter}"
        self.node_counter += 1
        return node_id


class UniversalASTParser:
    """
    AST Parser using UniversalParser with Tree-sitter.
    
    Provides a consistent interface for parsing multiple languages
    into SemanticGraph format.
    
    Usage:
        parser = UniversalASTParser(language="python")
        graph = parser.parse(code, filename)
    """
    
    # Resolve the language string to a LanguageType and set up the UniversalParser and adapter.
    def __init__(self, language: str = "python"):
        self.language = language.lower()

        # Map language string to LanguageType
        lang_map = {
            "python": LanguageType.PYTHON,
            "javascript": LanguageType.JAVASCRIPT,
            "js": LanguageType.JAVASCRIPT,
            "typescript": LanguageType.TYPESCRIPT,
            "ts": LanguageType.TYPESCRIPT,
            "html": LanguageType.HTML,
            "json": LanguageType.JSON,
            "yaml": LanguageType.YAML,
        }
        
        self.lang_type = lang_map.get(self.language, LanguageType.PYTHON)
        self.parser = UniversalParser()
        self.adapter = StandardToGraphAdapter()
        logger.info(f"UniversalASTParser initialized with tree-sitter for {language}")
    
    def parse(self, code: str, filename: str = "unknown") -> SemanticGraph:
        """
        Parse source code into AST nodes and edges.
        
        Args:
            code: Source code string
            filename: Filename for context
            
        Returns:
            SemanticGraph with nodes and edges
        """
        try:
            # Parse with UniversalParser
            std_tree = self.parser.parse_code(code, self.lang_type, filename)
            
            if std_tree is None:
                logger.error(f"Failed to parse {filename}, returning empty graph")
                return SemanticGraph(nodes=[], edges=[])
            
            # Convert to GraphNode format
            graph = self.adapter.convert(std_tree, filename)
            
            logger.info(f"Parsed {filename}: {len(graph.nodes)} nodes, {len(graph.edges)} edges")
            
            return graph
            
        except Exception as e:
            logger.error(f"Error parsing {filename}: {e}")
            # Return empty graph on error
            return SemanticGraph(nodes=[], edges=[])


# Convenience function
def parse_code(code: str, language: str, filename: str = "unknown") -> SemanticGraph:
    """
    Quick parse function for one-off parsing.
    
    Args:
        code: Source code string
        language: Language name (python, javascript, typescript, etc.)
        filename: Optional filename
        
    Returns:
        SemanticGraph with nodes and edges
    """
    parser = UniversalASTParser(language=language)
    return parser.parse(code, filename)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    
    # Test with Python code
    python_code = """
def vulnerable_function(user_input):
    query = f"SELECT * FROM users WHERE name = '{user_input}'"
    return query
    
class MyClass:
    def __init__(self):
        self.value = 42
"""
    
    parser = UniversalASTParser(language="python")
    graph = parser.parse(python_code, "test.py")
    
    print(f"Nodes: {len(graph.nodes)}")
    print(f"Edges: {len(graph.edges)}")
    print("\nSample nodes:")
    for node in graph.nodes[:5]:
        print(f"  {node.type}: {node.name} at line {node.line}")
