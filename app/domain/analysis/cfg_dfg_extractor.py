"""
Control Flow Graph (CFG) and Data Flow Graph (DFG) Extractor

This module builds CFG and DFG from the CPG for advanced analysis:
- Control flow edges (execution order, conditionals, loops)
- Data flow edges (variable definitions and uses)
- Reaching definitions
- Use-def chains

Compatible with Joern/CodeQL style analysis.
"""

from typing import List, Dict, Set, Tuple, Optional
from dataclasses import dataclass, field
from app.schemas.graph import SemanticGraph, GraphNode, GraphEdge
from app.enums.node_type import NodeType
from app.enums.edge_type import EdgeType
import logging

logger = logging.getLogger(__name__)


@dataclass
class CFGNode:
    """Control Flow Graph node"""
    node_id: str
    ast_node_id: str
    successors: List[str] = field(default_factory=list)
    predecessors: List[str] = field(default_factory=list)
    

@dataclass
class DFGEdge:
    """Data Flow edge (def-use)"""
    from_node_id: str  # Definition
    to_node_id: str    # Use
    variable: str
    

class CFGBuilder:
    """
    Control Flow Graph Builder
    
    Constructs CFG from AST/CPG:
    - Sequential execution edges
    - Conditional branches (if/else)
    - Loop edges (while/for)
    - Function call edges
    - Return edges
    """
    
    # Initializes empty CFG state: node registry, entry point, and exit node set.
    def __init__(self):
        self.cfg_nodes: Dict[str, CFGNode] = {}
        self.entry_node: Optional[str] = None
        self.exit_nodes: Set[str] = set()
    
    def build_cfg(self, graph: SemanticGraph) -> Tuple[Dict[str, CFGNode], List[GraphEdge]]:
        """
        Build CFG from SemanticGraph.
        
        Returns:
            (cfg_nodes, cfg_edges)
        """
        self.cfg_nodes = {}
        cfg_edges: List[GraphEdge] = []
        
        # Build CFG for each function
        function_nodes = [n for n in graph.nodes if n.type in (NodeType.FUNCTION, NodeType.ASYNC_FUNCTION, NodeType.ARROW_FUNCTION)]
        
        for func_node in function_nodes:
            logger.info(f"Building CFG for function: {func_node.name}")
            
            # Get function body nodes (children of function)
            body_nodes = self._get_function_body_nodes(func_node, graph)
            
            # Build sequential CFG
            prev_node_id = None
            for node in body_nodes:
                cfg_node = CFGNode(
                    node_id=f"cfg_{node.id}",
                    ast_node_id=node.id
                )
                self.cfg_nodes[cfg_node.node_id] = cfg_node
                
                # Add sequential edge
                if prev_node_id:
                    cfg_edges.append(GraphEdge(
                        from_node=prev_node_id,
                        to_node=cfg_node.node_id,
                        type=EdgeType.CONTROL_FLOW,
                        label="next"
                    ))
                
                # Handle conditionals
                if node.type == NodeType.IF_STATEMENT:
                    # Add conditional edges
                    true_branch, false_branch = self._extract_branches(node, graph)
                    if true_branch:
                        cfg_edges.append(GraphEdge(
                            from_node=cfg_node.node_id,
                            to_node=f"cfg_{true_branch}",
                            type=EdgeType.CONTROL_FLOW,
                            label="true"
                        ))
                    if false_branch:
                        cfg_edges.append(GraphEdge(
                            from_node=cfg_node.node_id,
                            to_node=f"cfg_{false_branch}",
                            type=EdgeType.CONTROL_FLOW,
                            label="false"
                        ))
                
                # Handle loops
                elif node.type in (NodeType.WHILE_STATEMENT, NodeType.FOR_STATEMENT):
                    # Loop back edge
                    loop_body = self._get_loop_body(node, graph)
                    if loop_body:
                        # Entry to loop
                        cfg_edges.append(GraphEdge(
                            from_node=cfg_node.node_id,
                            to_node=f"cfg_{loop_body[0].id}",
                            type=EdgeType.CONTROL_FLOW,
                            label="loop_enter"
                        ))
                        # Back edge from loop end
                        cfg_edges.append(GraphEdge(
                            from_node=f"cfg_{loop_body[-1].id}",
                            to_node=cfg_node.node_id,
                            type=EdgeType.CONTROL_FLOW,
                            label="loop_back"
                        ))
                
                # Handle returns
                elif node.type == NodeType.RETURN:
                    self.exit_nodes.add(cfg_node.node_id)
                
                prev_node_id = cfg_node.node_id
        
        return self.cfg_nodes, cfg_edges
    
    # Collects and sorts by line all graph nodes whose scope_id matches the function node's id.
    def _get_function_body_nodes(self, func_node: GraphNode, graph: SemanticGraph) -> List[GraphNode]:
        """Get all nodes in function body"""
        body_nodes = []
        
        # Find all nodes with this function in their scope
        if func_node.metadata and func_node.metadata.scope_id:
            for node in graph.nodes:
                if node.metadata and node.metadata.scope_id == func_node.id:
                    body_nodes.append(node)
        
        # Sort by line number
        body_nodes.sort(key=lambda n: n.line)
        
        return body_nodes
    
    # Returns the node ids of the true and false branch children of an if-statement node.
    def _extract_branches(self, if_node: GraphNode, graph: SemanticGraph) -> Tuple[Optional[str], Optional[str]]:
        """Extract true/false branches from if statement"""
        # Simplified - in reality, parse the AST children
        children = [n for n in graph.nodes if n.parent_id == if_node.id]
        
        true_branch = children[0].id if len(children) > 0 else None
        false_branch = children[1].id if len(children) > 1 else None
        
        return true_branch, false_branch
    
    # Returns the direct child nodes of a loop node sorted by line, representing the loop body.
    def _get_loop_body(self, loop_node: GraphNode, graph: SemanticGraph) -> List[GraphNode]:
        """Get loop body nodes"""
        body_nodes = []
        for node in graph.nodes:
            if node.parent_id == loop_node.id:
                body_nodes.append(node)
        body_nodes.sort(key=lambda n: n.line)
        return body_nodes


class DFGBuilder:
    """
    Data Flow Graph Builder
    
    Constructs DFG from CPG:
    - Variable definitions
    - Variable uses
    - Def-use chains
    - Reaching definitions
    """
    
    # Initializes empty DFG state: definitions map, uses map, and def-use edge list.
    def __init__(self):
        self.definitions: Dict[str, List[str]] = {}  # variable -> [def_node_ids]
        self.uses: Dict[str, List[str]] = {}  # variable -> [use_node_ids]
        self.def_use_edges: List[DFGEdge] = []
    
    def build_dfg(self, graph: SemanticGraph) -> List[GraphEdge]:
        """
        Build DFG from SemanticGraph.
        
        Returns:
            List of data flow edges
        """
        self.definitions = {}
        self.uses = {}
        self.def_use_edges = []
        dfg_edges: List[GraphEdge] = []
        
        # Extract definitions and uses from symbol table
        for symbol, node_ids in graph.symbol_table.items():
            for node_id in node_ids:
                node = self._find_node(node_id, graph)
                if not node:
                    continue
                
                # Check if it's a definition or use
                if node.type in (NodeType.ASSIGNMENT, NodeType.PARAMETER, NodeType.VARIABLE):
                    # Definition
                    if symbol not in self.definitions:
                        self.definitions[symbol] = []
                    self.definitions[symbol].append(node_id)
                else:
                    # Use
                    if symbol not in self.uses:
                        self.uses[symbol] = []
                    self.uses[symbol].append(node_id)
        
        # Create def-use edges
        for variable in self.definitions:
            if variable not in self.uses:
                continue
            
            defs = self.definitions[variable]
            uses = self.uses[variable]
            
            # For each use, find reaching definition
            for use_id in uses:
                use_node = self._find_node(use_id, graph)
                if not use_node:
                    continue
                
                # Find closest definition before this use
                reaching_def = self._find_reaching_definition(
                    variable, use_node, defs, graph
                )
                
                if reaching_def:
                    # Create DFG edge
                    dfg_edge = GraphEdge(
                        from_node=reaching_def,
                        to_node=use_id,
                        type=EdgeType.DATA_FLOW,
                        label=variable
                    )
                    dfg_edges.append(dfg_edge)
                    
                    self.def_use_edges.append(DFGEdge(
                        from_node_id=reaching_def,
                        to_node_id=use_id,
                        variable=variable
                    ))
        
        logger.info(f"Built DFG: {len(dfg_edges)} data flow edges")
        
        return dfg_edges
    
    # Scans graph nodes and returns the node matching the given id, or None.
    def _find_node(self, node_id: str, graph: SemanticGraph) -> Optional[GraphNode]:
        """Find node by ID"""
        for node in graph.nodes:
            if node.id == node_id:
                return node
        return None
    
    def _find_reaching_definition(
        self,
        variable: str,
        use_node: GraphNode,
        def_node_ids: List[str],
        graph: SemanticGraph
    ) -> Optional[str]:
        """
        Find reaching definition for a variable use.
        
        Returns closest definition before the use.
        """
        use_line = use_node.line
        use_scope = use_node.metadata.scope_id if use_node.metadata else None
        
        # Find all definitions before this use
        candidates = []
        for def_id in def_node_ids:
            def_node = self._find_node(def_id, graph)
            if not def_node:
                continue
            
            # Must be before use
            if def_node.line >= use_line:
                continue
            
            # Must be in same or enclosing scope
            def_scope = def_node.metadata.scope_id if def_node.metadata else None
            if not self._is_visible_scope(def_scope, use_scope, graph):
                continue
            
            candidates.append((def_id, def_node.line))
        
        if not candidates:
            return None
        
        # Return closest definition
        candidates.sort(key=lambda x: x[1], reverse=True)
        return candidates[0][0]
    
    # Returns True if def_scope is the same as or an ancestor of use_scope in the scope hierarchy.
    def _is_visible_scope(self, def_scope: Optional[str], use_scope: Optional[str], graph: SemanticGraph) -> bool:
        """Check if definition scope is visible from use scope"""
        if def_scope == use_scope:
            return True
        
        # Check if def_scope is an enclosing scope of use_scope
        if not use_scope or not def_scope:
            return True
        
        # Walk up scope hierarchy
        current_scope = use_scope
        while current_scope:
            if current_scope == def_scope:
                return True
            
            # Get parent scope
            if current_scope in graph.scopes:
                scope_info = graph.scopes[current_scope]
                current_scope = scope_info.get("parent")
            else:
                break
        
        return False


def extract_cfg_dfg(cpg: SemanticGraph) -> SemanticGraph:
    """
    Extract CFG and DFG from CPG and augment the graph.
    
    Args:
        cpg: Code Property Graph from CPGParser
        
    Returns:
        Enhanced SemanticGraph with CFG and DFG edges
    """
    logger.info("Extracting CFG and DFG...")
    
    # Build CFG
    cfg_builder = CFGBuilder()
    cfg_nodes, cfg_edges = cfg_builder.build_cfg(cpg)
    
    # Build DFG
    dfg_builder = DFGBuilder()
    dfg_edges = dfg_builder.build_dfg(cpg)
    
    # Augment CPG with CFG and DFG edges
    enhanced_cpg = SemanticGraph(
        nodes=cpg.nodes,
        edges=cpg.edges + cfg_edges + dfg_edges,
        symbol_table=cpg.symbol_table,
        scopes=cpg.scopes
    )
    
    logger.info(f"Enhanced CPG: {len(enhanced_cpg.edges)} total edges ({len(cfg_edges)} CFG + {len(dfg_edges)} DFG)")
    
    return enhanced_cpg


# Example usage
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    
    from app.domain.analysis.cpg_parser import CPGParser, LanguageType
    
    code = """
function processData(input) {
    let result = input.trim();
    
    if (result.length > 0) {
        result = result.toUpperCase();
        console.log(result);
    }
    
    return result;
}
"""
    
    # Parse to CPG
    parser = CPGParser()
    cpg = parser.parse_code(code, LanguageType.JAVASCRIPT, "example.js")
    
    # Extract CFG and DFG
    enhanced_cpg = extract_cfg_dfg(cpg)
    
    print(f"\nCFG/DFG Extraction:")
    print(f"Total edges: {len(enhanced_cpg.edges)}")
    print(f"Control flow edges: {len([e for e in enhanced_cpg.edges if e.type == EdgeType.CONTROL_FLOW])}")
    print(f"Data flow edges: {len([e for e in enhanced_cpg.edges if e.type == EdgeType.DATA_FLOW])}")
