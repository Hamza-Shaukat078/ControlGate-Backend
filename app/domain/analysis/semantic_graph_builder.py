"""
Semantic Graph Builder
======================

Uses tree-sitter based CPG parser + interprocedural DFG builder

Architecture:
1. CPG Parser (tree-sitter) - AST extraction with full language support
2. Interprocedural DFG - Data flow across function boundaries
3. Taint Engine - Vulnerability detection
"""

from app.schemas.graph import SemanticGraph, GraphNode, GraphEdge
from app.domain.analysis.cpg_parser import CPGParser
from app.domain.analysis.interprocedural_dfg import InterproceduralDFG
from app.domain.analysis.semantic_enricher import SemanticGraphEnricher
from app.domain.analysis.taint_engine import TaintEngine
from app.enums.node_type import NodeType
from app.enums.edge_type import EdgeType
from app.core.trace import trace_step


class SemanticGraphBuilder:
    """
    Orchestrates CPG parsing and interprocedural DFG construction
    to produce a unified semantic graph.
    
    NEW ARCHITECTURE:
    - Uses tree-sitter based CPG parser (supports Python, JS, TS, and more)
    - Interprocedural DFG with closure/callback/tuple unpacking support
    - Maintains backward compatibility with SemanticGraph schema
    """
    
    # Creates CPGParser and TaintEngine for the given language
    def __init__(self, language: str = "python"):
        self.language = language
        self.cpg_parser = CPGParser()
        self.taint_engine = TaintEngine()
    
    def build(self, code: str, filename: str = "source.py") -> SemanticGraph:
        trace_step("Graph builder: SemanticGraphBuilder.build() (app/domain/analysis/semantic_graph_builder.py)")
        """
        Build complete semantic graph from source code.
        
        Steps:
        1. Parse CPG with tree-sitter
        2. Build interprocedural DFG
        3. Run taint analysis
        4. Convert to SemanticGraph format (backward compatibility)
        
        Args:
            code: Source code to analyze
            filename: Filename for context
        
        Returns:
            SemanticGraph with nodes, edges, and analysis results
        """
        # Step 1: Parse CPG
        if not self.cpg_parser.has_language(self.language):
            raise RuntimeError(
                f"Missing tree-sitter grammar for '{self.language}'. "
                "Run: python setup_grammars.py"
            )
        trace_step("CPG: CPGParser.parse_code()")
        cpg = self.cpg_parser.parse_code(code, self.language, filename)
        
        # Step 2: Build interprocedural DFG
        trace_step("DFG: InterproceduralDFG.build()")
        dfg_builder = InterproceduralDFG(cpg)
        enhanced_cpg = dfg_builder.build()

        # Step 3: Append higher-level CPG relationships while preserving schema.
        trace_step("CPG: SemanticGraphEnricher.enrich()")
        enhanced_cpg = SemanticGraphEnricher(enhanced_cpg).enrich()
        
        # Step 4: Return enhanced CPG directly (already SemanticGraph-compatible)
        return enhanced_cpg
    
    def _cpg_to_semantic_graph(self, cpg) -> SemanticGraph:
        """
        Convert CPG to SemanticGraph format for backward compatibility
        
        Maps:
        - CPGNode -> GraphNode
        - CPGEdge -> GraphEdge
        - Preserves all metadata
        """
        nodes = []
        edges = []
        
        # Convert nodes
        for cpg_node in cpg.nodes:
            # Map CPG node type to legacy NodeType
            node_type = self._map_node_type(cpg_node.node_type)
            
            graph_node = GraphNode(
                id=cpg_node.id,
                type=node_type,
                name=cpg_node.name or "",
                code=cpg_node.code or "",
                file=cpg_node.file,
                line=cpg_node.line_start,
                column=cpg_node.column_start,
                metadata={
                    "node_type": cpg_node.node_type,
                    "language": cpg_node.language,
                    "line_end": cpg_node.line_end,
                    "column_end": cpg_node.column_end,
                    "scope_id": cpg_node.scope_id,
                    "is_async": getattr(cpg_node, "is_async", False),
                }
            )
            nodes.append(graph_node)
        
        # Convert edges
        for cpg_edge in cpg.edges:
            # Map CPG edge type to legacy EdgeType
            edge_type = cpg_edge.type if isinstance(cpg_edge.type, EdgeType) else self._map_edge_type(cpg_edge.type)
            
            graph_edge = GraphEdge(
                from_node=cpg_edge.from_node,
                to_node=cpg_edge.to_node,
                type=edge_type,
                metadata=cpg_edge.metadata or {}
            )
            edges.append(graph_edge)
        
        return SemanticGraph(nodes=nodes, edges=edges)
    
    def _map_node_type(self, cpg_type: str) -> NodeType:
        """Map CPG node type to legacy NodeType enum"""
        type_mapping = {
            "FUNCTION": NodeType.FUNCTION,
            "ASYNC_FUNCTION": NodeType.ASYNC_FUNCTION,
            "METHOD": NodeType.METHOD,
            "CLASS": NodeType.CLASS,
            "CALL": NodeType.CALL,
            "CALL_EXPRESSION": NodeType.CALL,
            "IDENTIFIER": NodeType.IDENTIFIER,
            "VARIABLE_DECLARATION": NodeType.VARIABLE,
            "PARAMETER": NodeType.PARAMETER,
            "RETURN": NodeType.RETURN_STMT,
            "RETURN_STATEMENT": NodeType.RETURN_STMT,
            "IF_STATEMENT": NodeType.IF_STMT,
            "FOR_STATEMENT": NodeType.FOR_STMT,
            "WHILE_STATEMENT": NodeType.WHILE_STMT,
            "TRY_STATEMENT": NodeType.TRY_STMT,
            "IMPORT": NodeType.IMPORT,
            "EXPRESSION": NodeType.EXPRESSION,
            "ASSIGNMENT": NodeType.ASSIGNMENT,
            "BINARY_EXPRESSION": NodeType.BINARY_OP,
            "STRING": NodeType.LITERAL,
            "NUMBER": NodeType.LITERAL,
        }
        
        return type_mapping.get(cpg_type, NodeType.UNKNOWN)
    
    def _map_edge_type(self, cpg_edge_type: str | EdgeType) -> EdgeType:
        """Map CPG edge type to legacy EdgeType enum"""
        if isinstance(cpg_edge_type, EdgeType):
            return cpg_edge_type
        type_mapping = {
            "AST_CHILD": EdgeType.AST_CHILD,
            "CONTROL_FLOW": EdgeType.CONTROL_FLOW,
            "DFG_ARG_PASS": EdgeType.DFG_PARAM_PASS,
            "DFG_RET": EdgeType.DFG_RET,
            "DFG_VAR_USE": EdgeType.DFG_FLOW,
            "DFG_CLOSURE": EdgeType.DFG_FLOW,
            "DFG_CALLBACK": EdgeType.DFG_FLOW,
            "DFG_TUPLE_UNPACK": EdgeType.DFG_FLOW,
            "DFG_UNCERTAIN": EdgeType.DFG_FLOW,
            "TAINT_FLOW": EdgeType.TAINT_FLOW,
        }
        return type_mapping.get(cpg_edge_type, EdgeType.DATA_FLOW)
