"""
Interprocedural Data Flow Graph (DFG) Builder
==============================================

Tracks data flow across function boundaries with support for:
- Parameter-to-argument propagation (DFG_ARG_PASS)
- Return value propagation (DFG_RET)
- JavaScript closures and callbacks
- Python tuple unpacking and multiple returns
- Graceful degradation with uncertainty tracking

Integration:
- Works with CPG parser (Tree-sitter based AST)
- Extends existing CPG with interprocedural edges
- Supports Python and JavaScript
"""

import logging
from typing import Dict, List, Set, Optional, Tuple, Any
from dataclasses import dataclass, field
from enum import Enum
from app.schemas.graph import GraphNode, GraphEdge, SemanticGraph
from app.enums.node_type import NodeType
from app.enums.edge_type import EdgeType
from app.core.trace import trace_step
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)


class DFGEdgeType(str, Enum):
    """Data flow edge types for interprocedural analysis"""
    # Intraprocedural (within function)
    DFG_VAR_DEF = "DFG_VAR_DEF"           # Variable definition
    DFG_VAR_USE = "DFG_VAR_USE"           # Variable usage
    DFG_ASSIGN = "DFG_ASSIGN"             # Assignment flow
    
    # Interprocedural (across functions)
    DFG_ARG_PASS = "DFG_ARG_PASS"         # Argument → Parameter
    DFG_RET = "DFG_RET"                   # Return value → Call site
    DFG_CLOSURE = "DFG_CLOSURE"           # Closure capture
    DFG_CALLBACK = "DFG_CALLBACK"         # Callback invocation
    DFG_IMPORT = "DFG_IMPORT"             # Import -> Export linkage
    DFG_EXPORT = "DFG_EXPORT"             # Export -> Import usage
    
    # Python-specific
    DFG_TUPLE_UNPACK = "DFG_TUPLE_UNPACK" # Tuple unpacking flow
    DFG_MULTI_RET = "DFG_MULTI_RET"       # Multiple return values
    
    # Uncertainty tracking
    DFG_UNCERTAIN = "DFG_UNCERTAIN"       # Flow with uncertainty


class UncertaintyLevel(str, Enum):
    """Levels of uncertainty in data flow analysis"""
    CERTAIN = "certain"                    # Definite flow (e.g., x = y)
    LIKELY = "likely"                      # Probable flow (e.g., known callback pattern)
    POSSIBLE = "possible"                  # Possible flow (e.g., dynamic property access)
    UNKNOWN = "unknown"                    # Unknown flow (e.g., eval, dynamic imports)


class DFGMetadata(BaseModel):
    """Metadata for DFG edges"""
    edge_type: DFGEdgeType
    uncertainty: UncertaintyLevel = UncertaintyLevel.CERTAIN
    context: Optional[str] = None          # Additional context about the flow
    arg_position: Optional[int] = None     # For argument passing
    return_index: Optional[int] = None     # For tuple unpacking
    closure_scope: Optional[str] = None    # For closure captures
    confidence: float = 1.0                # Confidence score (0.0 - 1.0)


@dataclass
class CallSite:
    """Represents a function call site"""
    call_node_id: str
    caller_function: str
    callee_name: str
    arguments: List[str]                   # Argument node IDs
    line_number: int
    is_async: bool = False
    is_callback: bool = False
    callback_arg_pos: Optional[int] = None


@dataclass
class FunctionSignature:
    """Represents a function signature for interprocedural analysis"""
    function_name: str
    node_id: str
    parameters: List[str]                  # Parameter names
    param_node_ids: List[str]              # Parameter node IDs
    return_nodes: List[str]                # Return statement node IDs
    is_async: bool = False
    is_generator: bool = False
    captured_vars: Set[str] = field(default_factory=set)  # For closures
    parent_scope: Optional[str] = None     # For nested functions


@dataclass
class DataFlowPath:
    """Represents a complete interprocedural data flow path"""
    source_node_id: str
    sink_node_id: str
    path_edges: List[Tuple[str, str, DFGEdgeType]]
    uncertainty: UncertaintyLevel
    confidence: float
    description: str


class InterproceduralDFG:
    """
    Interprocedural Data Flow Graph Builder
    
    Builds comprehensive DFG with:
    1. Intraprocedural flows (within functions)
    2. Interprocedural flows (across function calls)
    3. JavaScript closure and callback tracking
    4. Python tuple unpacking and multi-return
    5. Uncertainty representation
    
    Usage:
        dfg_builder = InterproceduralDFG(cpg)
        dfg_builder.build()
        enhanced_cpg = dfg_builder.get_cpg()
    """
    
    def __init__(self, cpg: SemanticGraph):
        """
        Initialize interprocedural DFG builder
        
        Args:
            cpg: Code Property Graph from CPG parser
        """
        self.cpg = cpg
        self.dfg_edges: List[GraphEdge] = []
        
        # Analysis state
        self.functions: Dict[str, FunctionSignature] = {}
        self.call_sites: List[CallSite] = []
        self.variable_defs: Dict[str, List[str]] = {}  # var_name -> [node_ids]
        self.variable_uses: Dict[str, List[str]] = {}  # var_name -> [node_ids]
        
        # Closure tracking (JavaScript)
        self.closure_captures: Dict[str, Set[str]] = {}  # func_id -> {captured_vars}
        self.callback_bindings: Dict[str, str] = {}       # callback_id -> parent_func
        
        # Return value tracking
        self.return_values: Dict[str, List[str]] = {}     # func_name -> [return_node_ids]

        # Node type groups for compatibility with GraphNode.type (NodeType enum)
        self.function_types = {
            NodeType.FUNCTION,
            NodeType.ASYNC_FUNCTION,
            NodeType.METHOD,
            NodeType.ARROW_FUNCTION,
            NodeType.LAMBDA,
        }
        self.call_types = {
            NodeType.CALL_EXPRESSION,
            NodeType.EXTERNAL_CALL,
            NodeType.SYSTEM_CALL,
            NodeType.EVAL_CALL,
            NodeType.ORM_QUERY,
        }
        self.param_types = {NodeType.PARAMETER}
        self.assignment_types = {NodeType.ASSIGNMENT, NodeType.VARIABLE}
        self.identifier_types = {NodeType.IDENTIFIER}
        self.return_types = {NodeType.RETURN}
        
    def build(self) -> SemanticGraph:
        trace_step("DFG: InterproceduralDFG.build() (app/domain/analysis/interprocedural_dfg.py)")
        """
        Build interprocedural DFG
        
        Steps:
        1. Extract function signatures
        2. Identify call sites
        3. Build intraprocedural DFG (within functions)
        4. Build interprocedural edges (arg pass, return)
        5. Handle special cases (closures, callbacks, tuple unpacking)
        6. Add uncertainty annotations
        
        Returns:
            Enhanced CPG with DFG edges
        """
        logger.debug("Building Interprocedural DFG...")
        
        # Step 1: Extract function signatures
        self._extract_functions()

        # Step 2: Build intraprocedural DFG (defs/uses for callbacks/closures)
        self._build_intraprocedural_dfg()
        self._link_expression_flows()

        # Step 3: Extract call sites (needs variable defs)
        self._extract_call_sites()
        self._link_call_argument_flows()
        
        # Step 4: Build interprocedural edges
        self._build_argument_flows()
        self._build_return_flows()
        
        # Step 5: Handle language-specific features
        self._handle_closures()          # JavaScript
        self._handle_callbacks()         # JavaScript
        self._handle_tuple_unpacking()   # Python
        
        # Step 6: Add uncertainty annotations
        self._annotate_uncertainty()
        
        logger.debug("Built DFG with %d interprocedural edges", len(self.dfg_edges))
        
        return self.get_cpg()

    # Creates DFG_CALL_ARG edges from each argument node to its call expression node.
    def _link_call_argument_flows(self):
        """Create DFG edges from call arguments to call expressions."""
        for call_site in self.call_sites:
            for i, arg_id in enumerate(call_site.arguments):
                metadata = DFGMetadata(
                    edge_type=DFGEdgeType.DFG_ARG_PASS,
                    uncertainty=UncertaintyLevel.CERTAIN,
                    context=f"Arg {i} -> Call",
                    arg_position=i,
                    confidence=0.9
                )
                edge = GraphEdge(
                    **{
                        "from": arg_id,
                        "to": call_site.call_node_id,
                        "type": EdgeType.DFG_FLOW
                    }
                )
                if not edge.metadata:
                    edge.metadata = {}
                edge.metadata.update(metadata.model_dump())
                edge.metadata["dfg_edge_type"] = "DFG_CALL_ARG"
                self.dfg_edges.append(edge)

    # Adds DFG_EXPR_FLOW edges from identifier/literal/parameter children up to their parent expression nodes.
    def _link_expression_flows(self):
        """Link identifier/literal nodes to their parent expressions for forward flow."""
        node_map = {n.id: n for n in self.cpg.nodes}
        for edge in self.cpg.edges:
            if edge.type != EdgeType.AST_CHILD:
                continue
            parent = node_map.get(edge.from_node)
            child = node_map.get(edge.to_node)
            if not parent or not child:
                continue
            if child.type not in {NodeType.IDENTIFIER, NodeType.LITERAL, NodeType.PARAMETER}:
                continue
            if parent.type not in {NodeType.ASSIGNMENT, NodeType.CALL_EXPRESSION, NodeType.EXPRESSION, NodeType.MEMBER_ACCESS}:
                continue
            metadata = DFGMetadata(
                edge_type=DFGEdgeType.DFG_ASSIGN,
                uncertainty=UncertaintyLevel.CERTAIN,
                context="Expr flow",
                confidence=0.7
            )
            flow_edge = GraphEdge(
                **{
                    "from": child.id,
                    "to": parent.id,
                    "type": EdgeType.DFG_FLOW
                }
            )
            if not flow_edge.metadata:
                flow_edge.metadata = {}
            flow_edge.metadata.update(metadata.model_dump())
            flow_edge.metadata["dfg_edge_type"] = "DFG_EXPR_FLOW"
            self.dfg_edges.append(flow_edge)
    
    # Walks CPG nodes to build FunctionSignature records for every function-typed node.
    def _extract_functions(self):
        """Extract all function signatures from CPG"""
        for node in self.cpg.nodes:
            if node.type in self.function_types:
                # Find parameter nodes (children with PARAMETER type)
                params = self._find_parameters(node.id)
                
                # Find return statements
                returns = self._find_return_statements(node.id)
                
                # Check for closure captures (JavaScript)
                captured = self._detect_closure_captures(node.id)
                
                signature = FunctionSignature(
                    function_name=node.name or f"anonymous_{node.id}",
                    node_id=node.id,
                    parameters=[p.name for p in params],
                    param_node_ids=[p.id for p in params],
                    return_nodes=returns,
                    is_async=node.type == NodeType.ASYNC_FUNCTION,
                    captured_vars=captured,
                    parent_scope=self._get_parent_scope(node.id)
                )
                
                # Index by both name and node id to support anonymous callbacks
                if node.name:
                    self.functions[node.name] = signature
                self.functions[node.id] = signature
                
        logger.debug("  Extracted %d function signatures", len(self.functions))
    
    # Walks CPG nodes to collect CallSite records for every call-expression node.
    def _extract_call_sites(self):
        """Extract all function call sites"""
        for node in self.cpg.nodes:
            if node.type in self.call_types:
                # Find caller function
                caller = self._find_enclosing_function(node.id)
                
                # Find callee name
                callee = self._get_callee_name(node)
                
                # Find arguments
                args = self._find_arguments(node.id)
                
                # Check if callback
                is_callback, cb_pos = self._is_callback_invocation(node, args)
                
                call_site = CallSite(
                    call_node_id=node.id,
                    caller_function=caller,
                    callee_name=callee,
                    arguments=[arg.id for arg in args],
                    line_number=node.line,
                    is_async=node.type == NodeType.AWAIT,
                    is_callback=is_callback,
                    callback_arg_pos=cb_pos
                )
                
                self.call_sites.append(call_site)
        
        logger.debug("  Found %d call sites", len(self.call_sites))
    
    # Tracks variable definitions and uses within each function, then builds def-use chains.
    def _build_intraprocedural_dfg(self):
        """Build data flow within each function"""
        for func_sig in self.functions.values():
            # Get all nodes within this function
            func_nodes = self._get_function_body_nodes(func_sig.node_id)
            
            # Track variable definitions and uses
            for node in func_nodes:
                if node.type in self.assignment_types or node.type in self.identifier_types or node.type in self.param_types:
                    self._track_variable_flow(node, func_sig)
            
            # Build def-use chains
            self._build_def_use_chains(func_sig)
    
    # Creates DFG_ARG_PASS edges connecting each call-site argument to the matching callee parameter.
    def _build_argument_flows(self):
        """Build parameter-to-argument data flow edges"""
        for call_site in self.call_sites:
            # Find callee function
            callee_sig = self.functions.get(call_site.callee_name)
            
            if not callee_sig:
                # Unknown function - add uncertain edge
                self._add_uncertain_call(call_site)
                continue
            
            # Match arguments to parameters
            for i, arg_id in enumerate(call_site.arguments):
                if i < len(callee_sig.param_node_ids):
                    param_id = callee_sig.param_node_ids[i]
                    
                    # Create DFG_ARG_PASS edge
                    metadata = DFGMetadata(
                        edge_type=DFGEdgeType.DFG_ARG_PASS,
                        uncertainty=UncertaintyLevel.CERTAIN,
                        context=f"Arg {i} → Param '{callee_sig.parameters[i]}'",
                        arg_position=i,
                        confidence=1.0
                    )
                    
                    edge = GraphEdge(
                        **{
                            "from": arg_id,
                            "to": param_id,
                            "type": EdgeType.DFG_PARAM_PASS
                        }
                    )
                    if not edge.metadata:
                        edge.metadata = {}
                    edge.metadata.update(metadata.model_dump())
                    edge.metadata['dfg_edge_type'] = DFGEdgeType.DFG_ARG_PASS.value
                    
                    self.dfg_edges.append(edge)
    
    # Creates DFG_RET edges from each callee return value node back to the call site.
    def _build_return_flows(self):
        """Build return value to call site data flow edges"""
        for call_site in self.call_sites:
            callee_sig = self.functions.get(call_site.callee_name)
            
            if not callee_sig:
                continue
            
            # Connect each return statement to call site
            for return_node_id in callee_sig.return_nodes:
                # Get the actual return value node (child of return statement)
                return_value = self._get_return_value_node(return_node_id)
                
                if return_value:
                    metadata = DFGMetadata(
                        edge_type=DFGEdgeType.DFG_RET,
                        uncertainty=UncertaintyLevel.CERTAIN,
                        context=f"Return from '{callee_sig.function_name}'",
                        confidence=1.0
                    )
                    
                    edge = GraphEdge(
                        **{
                            "from": return_value,
                            "to": call_site.call_node_id,
                            "type": EdgeType.DFG_RET
                        }
                    )
                    if not edge.metadata:
                        edge.metadata = {}
                    edge.metadata.update(metadata.model_dump())
                    edge.metadata['dfg_edge_type'] = DFGEdgeType.DFG_RET.value
                    
                    self.dfg_edges.append(edge)
    
    def _handle_closures(self):
        """
        Handle JavaScript closures
        
        Example:
            function outer(x) {
                return function inner(y) {
                    return x + y;  // 'x' is captured from outer scope
                }
            }
        """
        for func_sig in self.functions.values():
            if not func_sig.captured_vars:
                continue
            
            # Find where captured variables are defined
            for captured_var in func_sig.captured_vars:
                # Find definition in parent scope
                parent_def_nodes = self._find_var_in_parent_scope(
                    captured_var,
                    func_sig.parent_scope
                )
                
                # Find uses in inner function
                inner_use_nodes = self._find_var_uses_in_function(
                    captured_var,
                    func_sig.node_id
                )
                
                # Create closure capture edges
                for def_node in parent_def_nodes:
                    for use_node in inner_use_nodes:
                        metadata = DFGMetadata(
                            edge_type=DFGEdgeType.DFG_CLOSURE,
                            uncertainty=UncertaintyLevel.CERTAIN,
                            context=f"Closure capture '{captured_var}'",
                            closure_scope=func_sig.parent_scope,
                            confidence=1.0
                        )
                        
                        edge = GraphEdge(
                            **{
                                "from": def_node,
                                "to": use_node,
                                "type": EdgeType.DFG_FLOW
                            }
                        )
                        if not edge.metadata:
                            edge.metadata = {}
                        edge.metadata.update(metadata.model_dump())
                        edge.metadata['dfg_edge_type'] = DFGEdgeType.DFG_CLOSURE.value
                        
                        self.dfg_edges.append(edge)
    
    def _handle_callbacks(self):
        """
        Handle JavaScript callback patterns
        
        Example:
            function processData(data, callback) {
                const result = transform(data);
                callback(result);  // Track flow from result to callback param
            }
            
            processData(input, function(output) {
                console.log(output);  // output receives result
            });
        """
        for call_site in self.call_sites:
            if not call_site.is_callback:
                continue
            
            # Find callback function argument
            if call_site.callback_arg_pos is not None:
                callback_arg_id = call_site.arguments[call_site.callback_arg_pos]
                
                # Find the callback function node
                callback_func = self._resolve_callback_function(callback_arg_id)
                
                if callback_func:
                    # Find where callback is invoked inside callee
                    callee_sig = self.functions.get(call_site.callee_name)
                    if callee_sig:
                        callback_invocations = self._find_callback_invocations(
                            callee_sig.node_id,
                            callee_sig.parameters[call_site.callback_arg_pos]
                        )
                        
                        # Connect callback invocation arguments to callback parameters
                        for invocation in callback_invocations:
                            self._connect_callback_flow(
                                invocation,
                                callback_func
                            )
    
    def _handle_tuple_unpacking(self):
        """
        Handle Python tuple unpacking
        
        Example:
            def get_user():
                return name, age, email  # Multiple returns
            
            user_name, user_age, user_email = get_user()  # Unpacking
        """
        for node in self.cpg.nodes:
            if node.type == NodeType.ASSIGNMENT and self._is_tuple_unpack(node):
                
                # Find the call expression on RHS
                call_node = self._find_call_in_assignment(node.id)
                
                if call_node:
                    callee_sig = self.functions.get(self._get_callee_name_from_node(call_node))
                    
                    if callee_sig:
                        # Find unpacking targets (LHS variables)
                        unpack_targets = self._find_unpack_targets(node.id)
                        
                        # Find return tuple elements
                        return_elements = self._find_return_tuple_elements(callee_sig)
                        
                        # Connect each return element to corresponding unpack target
                        for i, (return_elem, target) in enumerate(
                            zip(return_elements, unpack_targets)
                        ):
                            metadata = DFGMetadata(
                                edge_type=DFGEdgeType.DFG_TUPLE_UNPACK,
                                uncertainty=UncertaintyLevel.CERTAIN,
                                context=f"Tuple unpack position {i}",
                                return_index=i,
                                confidence=1.0
                            )
                            
                            edge = GraphEdge(
                                **{
                                    "from": return_elem,
                                    "to": target,
                                    "type": EdgeType.DFG_FLOW
                                }
                            )
                            if not edge.metadata:
                                edge.metadata = {}
                            edge.metadata.update(metadata.model_dump())
                            edge.metadata['dfg_edge_type'] = DFGEdgeType.DFG_TUPLE_UNPACK.value
                            
                            self.dfg_edges.append(edge)
    
    def _annotate_uncertainty(self):
        """
        Add uncertainty annotations for flows that cannot be determined statically
        
        Cases:
        - Dynamic property access: obj[computed_key]
        - Dynamic imports: require(variable_path)
        - eval/exec calls
        - Reflection APIs
        """
        for node in self.cpg.nodes:
            is_dynamic = False
            if node.type in {NodeType.SUBSCRIPT, NodeType.MEMBER_ACCESS}:
                if node.source_code and "[" in node.source_code:
                    is_dynamic = True
            if node.type == NodeType.EVAL_CALL:
                is_dynamic = True
            if node.type == NodeType.EXTERNAL_CALL and node.name and "import" in node.name.lower():
                is_dynamic = True
            if not is_dynamic:
                continue
            # Add uncertain DFG edge
            metadata = DFGMetadata(
                edge_type=DFGEdgeType.DFG_UNCERTAIN,
                uncertainty=UncertaintyLevel.UNKNOWN,
                context="Dynamic operation",
                confidence=0.3  # Low confidence
            )

            # Find potential sources and sinks
            sources = self._find_potential_sources(node.id)
            sinks = self._find_potential_sinks(node.id)

            for source in sources:
                for sink in sinks:
                    edge = GraphEdge(
                        **{
                            "from": source,
                            "to": sink,
                            "type": EdgeType.DFG_FLOW
                        }
                    )
                    if not edge.metadata:
                        edge.metadata = {}
                    edge.metadata.update(metadata.model_dump())
                    edge.metadata['dfg_edge_type'] = DFGEdgeType.DFG_UNCERTAIN.value
                    
                    self.dfg_edges.append(edge)
    
    # =========================
    # Helper Methods
    # =========================
    
    # Returns all PARAMETER-typed child nodes of the given function node.
    def _find_parameters(self, func_node_id: str) -> List[GraphNode]:
        """Find parameter nodes of a function"""
        params = []
        for edge in self.cpg.edges:
            if edge.from_node == func_node_id and edge.type == EdgeType.AST_CHILD:
                param_node = self._get_node_by_id(edge.to_node)
                if param_node and param_node.type == NodeType.PARAMETER:
                    params.append(param_node)
        return params
    
    # Collects node IDs of all RETURN-typed nodes found in the function body.
    def _find_return_statements(self, func_node_id: str) -> List[str]:
        """Find all return statement node IDs in a function"""
        returns = []
        func_nodes = self._get_function_body_nodes(func_node_id)
        for node in func_nodes:
            if node.type == NodeType.RETURN:
                returns.append(node.id)
        return returns
    
    def _detect_closure_captures(self, func_node_id: str) -> Set[str]:
        """
        Detect variables captured by closure
        
        A variable is captured if:
        1. It's used inside the function
        2. It's not defined in the function
        3. It's defined in an enclosing scope
        """
        captured = set()
        
        func_nodes = self._get_function_body_nodes(func_node_id)
        used_vars = set()
        defined_vars = set()
        
        # Find all variables used and defined
        for node in func_nodes:
            if node.type == NodeType.IDENTIFIER:
                used_vars.add(node.name)
            if node.type in {NodeType.ASSIGNMENT, NodeType.VARIABLE, NodeType.PARAMETER}:
                defined_vars.add(node.name)
        
        # Captured = used but not defined locally
        captured = used_vars - defined_vars
        
        return captured
    
    # Walks up AST_CHILD edges to find the nearest enclosing function node id.
    def _get_parent_scope(self, node_id: str) -> Optional[str]:
        """Find parent scope (enclosing function) of a node"""
        # Walk up AST_CHILD edges
        current = node_id
        while current:
            # Find parent
            parent_edge = next(
                (edge for edge in self.cpg.edges
                 if edge.to_node == current and edge.type == EdgeType.AST_CHILD),
                None
            )
            
            if not parent_edge:
                break
            
            parent_node = self._get_node_by_id(parent_edge.from_node)
            if parent_node and parent_node.type in self.function_types:
                return parent_node.id
            
            current = parent_edge.from_node
        
        return "global"
    
    # Returns the name of the function that contains the given node, or a sentinel string.
    def _find_enclosing_function(self, node_id: str) -> str:
        """Find the function containing this node"""
        scope = self._get_parent_scope(node_id)
        if scope == "global":
            return "__global__"
        
        func_node = self._get_node_by_id(scope)
        return func_node.name if func_node else "__unknown__"
    
    # Extracts the callee name from a call node's own name or its identifier/member-access child.
    def _get_callee_name(self, call_node: GraphNode) -> str:
        """Extract callee function name from call node"""
        # Look for function name in call expression
        # Check node's name or find child with function identifier
        if call_node.name:
            return call_node.name
        
        # Find function identifier child
        for edge in self.cpg.edges:
            if edge.from_node == call_node.id and edge.type == EdgeType.AST_CHILD:
                child = self._get_node_by_id(edge.to_node)
                if child and child.type in {NodeType.IDENTIFIER, NodeType.MEMBER_ACCESS}:
                    return child.name or child.source_code
        
        return "__unknown__"
    
    # Returns AST child nodes of a call expression that represent its arguments (excluding the callee).
    def _find_arguments(self, call_node_id: str) -> List[GraphNode]:
        """Find argument nodes of a call"""
        args = []
        callee_node = self._get_callee_node(call_node_id)
        for edge in self.cpg.edges:
            if edge.from_node == call_node_id and edge.type == EdgeType.AST_CHILD:
                arg_node = self._get_node_by_id(edge.to_node)
                if not arg_node:
                    continue
                if callee_node and arg_node.id == callee_node.id:
                    continue
                if arg_node.type in (
                    {NodeType.EXPRESSION, NodeType.IDENTIFIER, NodeType.LITERAL, NodeType.MEMBER_ACCESS}
                    | self.function_types
                ):
                    args.append(arg_node)
        return args
    
    def _is_callback_invocation(self, call_node: GraphNode, args: List[GraphNode]) -> Tuple[bool, Optional[int]]:
        """
        Detect if this call passes a callback function
        
        Returns: (is_callback, callback_argument_position)
        """
        for i, arg in enumerate(args):
            if arg.type in self.function_types:
                return True, i
            if arg.type == NodeType.IDENTIFIER:
                scope_id = arg.metadata.scope_id if arg.metadata else None
                resolved = self._resolve_identifier_to_function(arg.name, scope_id)
                if resolved:
                    return True, i
        
        return False, None
    
    # Recursively collects all descendant nodes of a function via AST_CHILD edges.
    def _get_function_body_nodes(self, func_node_id: str) -> List[GraphNode]:
        """Get all nodes in function body (recursive traversal)"""
        visited = set()
        result = []
        
        def traverse(node_id: str):
            if node_id in visited:
                return
            visited.add(node_id)
            
            node = self._get_node_by_id(node_id)
            if node:
                result.append(node)
            
            # Traverse children
            for edge in self.cpg.edges:
                if edge.from_node == node_id and edge.type == EdgeType.AST_CHILD:
                    traverse(edge.to_node)
        
        traverse(func_node_id)
        return result
    
    # Records the node id in variable_defs or variable_uses depending on whether it is a definition or identifier use.
    def _track_variable_flow(self, node: GraphNode, func_sig: FunctionSignature):
        """Track variable definitions and uses"""
        if node.type in {NodeType.ASSIGNMENT, NodeType.VARIABLE, NodeType.PARAMETER}:
            # This is a definition
            if node.name:
                if node.name not in self.variable_defs:
                    self.variable_defs[node.name] = []
                self.variable_defs[node.name].append(node.id)
        
        elif node.type == NodeType.IDENTIFIER:
            # This is a use
            if node.name:
                if node.name not in self.variable_uses:
                    self.variable_uses[node.name] = []
                self.variable_uses[node.name].append(node.id)
    
    # Connects each variable definition to subsequent uses within the same function via DFG_VAR_USE edges.
    def _build_def_use_chains(self, func_sig: FunctionSignature):
        """Build def-use chains within a function"""
        # For each variable, connect defs to uses
        func_nodes = self._get_function_body_nodes(func_sig.node_id)
        func_node_ids = {n.id for n in func_nodes}
        
        for var_name in self.variable_defs.keys():
            if var_name not in self.variable_uses:
                continue
            
            # Filter to only nodes in this function
            defs = [d for d in self.variable_defs[var_name] if d in func_node_ids]
            uses = [u for u in self.variable_uses[var_name] if u in func_node_ids]
            
            # Connect each def to subsequent uses
            for def_id in defs:
                for use_id in uses:
                    # Check if use comes after def (simplistic check)
                    def_node = self._get_node_by_id(def_id)
                    use_node = self._get_node_by_id(use_id)
                    
                    if def_node and use_node and def_node.line <= use_node.line:
                        metadata = DFGMetadata(
                            edge_type=DFGEdgeType.DFG_VAR_USE,
                            uncertainty=UncertaintyLevel.CERTAIN,
                            context=f"Variable '{var_name}'",
                            confidence=1.0
                        )
                        
                        edge = GraphEdge(
                            **{
                                "from": def_id,
                                "to": use_id,
                                "type": EdgeType.DFG_FLOW
                            }
                        )
                        if not edge.metadata:
                            edge.metadata = {}
                        edge.metadata.update(metadata.model_dump())
                        edge.metadata['dfg_edge_type'] = DFGEdgeType.DFG_VAR_USE.value
                        
                        self.dfg_edges.append(edge)
    
    # Marks a call site with DFG_UNCERTAIN metadata when the callee cannot be resolved.
    def _add_uncertain_call(self, call_site: CallSite):
        """Add uncertain edges for unknown function calls"""
        metadata = DFGMetadata(
            edge_type=DFGEdgeType.DFG_UNCERTAIN,
            uncertainty=UncertaintyLevel.UNKNOWN,
            context=f"Unknown function '{call_site.callee_name}'",
            confidence=0.0
        )
        
        # Mark call site as uncertain
        # (Could be refined with heuristics or external info)
    
    # Returns the first AST child node id of a return statement, representing the returned value.
    def _get_return_value_node(self, return_stmt_id: str) -> Optional[str]:
        """Get the actual value being returned"""
        for edge in self.cpg.edges:
            if edge.from_node == return_stmt_id and edge.type == EdgeType.AST_CHILD:
                return edge.to_node
        return None
    
    # Looks up definition node ids for a variable restricted to the specified parent scope.
    def _find_var_in_parent_scope(self, var_name: str, parent_scope: Optional[str]) -> List[str]:
        """Find variable definition in parent scope"""
        if not parent_scope or parent_scope == "global":
            # Search global scope
            return [d for d in self.variable_defs.get(var_name, [])]
        
        # Search in specific parent function
        parent_nodes = self._get_function_body_nodes(parent_scope)
        parent_node_ids = {n.id for n in parent_nodes}
        
        return [d for d in self.variable_defs.get(var_name, []) if d in parent_node_ids]
    
    # Returns use node ids for a variable that are contained within the given function body.
    def _find_var_uses_in_function(self, var_name: str, func_id: str) -> List[str]:
        """Find variable uses within a specific function"""
        func_nodes = self._get_function_body_nodes(func_id)
        func_node_ids = {n.id for n in func_nodes}
        
        return [u for u in self.variable_uses.get(var_name, []) if u in func_node_ids]
    
    # Resolves a callback argument node to its FunctionSignature, handling direct functions and identifier references.
    def _resolve_callback_function(self, callback_arg_id: str) -> Optional[FunctionSignature]:
        """Resolve callback argument to actual function"""
        callback_node = self._get_node_by_id(callback_arg_id)
        
        if callback_node and callback_node.type in {NodeType.ARROW_FUNCTION, NodeType.FUNCTION, NodeType.METHOD}:
            # Direct callback function
            return self.functions.get(callback_node.id)
        if callback_node and callback_node.type == NodeType.IDENTIFIER and callback_node.name:
            scope_id = callback_node.metadata.scope_id if callback_node.metadata else None
            func_id = self._resolve_identifier_to_function(callback_node.name, scope_id)
            if func_id:
                return self.functions.get(func_id)
        
        # Could be a variable reference - would need more analysis
        return None
    
    # Finds call-expression nodes inside a function where the callee matches the callback parameter name.
    def _find_callback_invocations(self, func_id: str, callback_param_name: str) -> List[GraphNode]:
        """Find where callback parameter is invoked"""
        invocations = []
        func_nodes = self._get_function_body_nodes(func_id)
        
        for node in func_nodes:
            if node.type == NodeType.CALL_EXPRESSION:
                callee_name = self._get_callee_name(node)
                if callee_name == callback_param_name:
                    invocations.append(node)
        
        return invocations
    
    # Creates DFG_CALLBACK edges from each argument of a callback invocation to the callback's parameters.
    def _connect_callback_flow(self, invocation_node: GraphNode, callback_func: FunctionSignature):
        """Connect callback invocation to callback function parameters"""
        # Find arguments to callback invocation
        args = self._find_arguments(invocation_node.id)
        
        # Connect to callback parameters
        for i, arg_id in enumerate([a.id for a in args]):
            if i < len(callback_func.param_node_ids):
                param_id = callback_func.param_node_ids[i]
                
                metadata = DFGMetadata(
                    edge_type=DFGEdgeType.DFG_CALLBACK,
                    uncertainty=UncertaintyLevel.LIKELY,  # Callbacks have some uncertainty
                    context=f"Callback arg {i}",
                    arg_position=i,
                    confidence=0.8
                )
                
                edge = GraphEdge(
                    **{
                        "from": arg_id,
                        "to": param_id,
                        "type": EdgeType.DFG_FLOW
                    }
                )
                if not edge.metadata:
                    edge.metadata = {}
                edge.metadata.update(metadata.model_dump())
                edge.metadata['dfg_edge_type'] = DFGEdgeType.DFG_CALLBACK.value
                
                self.dfg_edges.append(edge)
    
    # Heuristically detects tuple-unpacking assignments by looking for a comma in the source code.
    def _is_tuple_unpack(self, node: GraphNode) -> bool:
        """Check if assignment is tuple unpacking"""
        # Look for tuple pattern on LHS or multiple assignment targets
        return "," in (node.source_code or "")  # Simplistic check
    
    # Returns the first CALL_EXPRESSION child of an assignment node, representing the RHS call.
    def _find_call_in_assignment(self, assignment_id: str) -> Optional[GraphNode]:
        """Find call expression on RHS of assignment"""
        for edge in self.cpg.edges:
            if edge.from_node == assignment_id and edge.type == EdgeType.AST_CHILD:
                child = self._get_node_by_id(edge.to_node)
                if child and child.type == NodeType.CALL_EXPRESSION:
                    return child
        return None
    
    # Delegates to _get_callee_name to extract the callee name from a call node.
    def _get_callee_name_from_node(self, call_node: GraphNode) -> str:
        """Get callee name from call node"""
        return self._get_callee_name(call_node)

    # Returns the identifier or member-access child of a call expression that names the callee.
    def _get_callee_node(self, call_node_id: str) -> Optional[GraphNode]:
        """Get callee node for a call expression."""
        for edge in self.cpg.edges:
            if edge.from_node == call_node_id and edge.type == EdgeType.AST_CHILD:
                child = self._get_node_by_id(edge.to_node)
                if child and child.type in {NodeType.IDENTIFIER, NodeType.MEMBER_ACCESS}:
                    return child
        return None

    # Walks the lexical scope chain to find the function node id that an identifier name resolves to.
    def _resolve_identifier_to_function(self, identifier: Optional[str], scope_id: Optional[str]) -> Optional[str]:
        """Resolve identifier to a function node id via scope-aware symbol table."""
        if not identifier:
            return None
        # Walk up lexical scopes for nearest symbol definition
        current_scope = scope_id or "global"
        while current_scope:
            scope_info = self.cpg.scopes.get(current_scope, {})
            symbols = scope_info.get("symbols", {})
            if identifier in symbols:
                symbol_node_id = symbols[identifier]
                resolved = self._resolve_symbol_node_to_function(symbol_node_id)
                if resolved:
                    return resolved
            current_scope = scope_info.get("parent")

        # Fallback: check assignment defs for function expressions
        for def_id in self.variable_defs.get(identifier, []):
            resolved = self._resolve_symbol_node_to_function(def_id)
            if resolved:
                return resolved
        return None

    # Checks if a symbol node is itself a function or has a function child, returning its node id.
    def _resolve_symbol_node_to_function(self, symbol_node_id: str) -> Optional[str]:
        """Resolve a symbol node to an underlying function node."""
        symbol_node = self._get_node_by_id(symbol_node_id)
        if not symbol_node:
            return None
        if symbol_node.type in self.function_types:
            return symbol_node.id
        # Check if the symbol node has a function child (assignment/variable)
        for edge in self.cpg.edges:
            if edge.from_node == symbol_node_id and edge.type == EdgeType.AST_CHILD:
                child = self._get_node_by_id(edge.to_node)
                if child and child.type in self.function_types:
                    return child.id
        return None
    
    # Returns node ids of identifier children of a tuple-unpacking assignment (the LHS targets).
    def _find_unpack_targets(self, assignment_id: str) -> List[str]:
        """Find unpacking target variable IDs"""
        targets = []
        for edge in self.cpg.edges:
            if edge.from_node == assignment_id and edge.type == EdgeType.AST_CHILD:
                child = self._get_node_by_id(edge.to_node)
                if child and child.type == NodeType.IDENTIFIER:
                    targets.append(child.id)
        return targets
    
    # Locates the individual element node ids within tuple expressions returned by a function.
    def _find_return_tuple_elements(self, func_sig: FunctionSignature) -> List[str]:
        """Find elements of returned tuple"""
        elements = []
        for return_id in func_sig.return_nodes:
            # Find tuple expression
            for edge in self.cpg.edges:
                if edge.from_node == return_id and edge.type == EdgeType.AST_CHILD:
                    child = self._get_node_by_id(edge.to_node)
                    if child and child.source_code and "," in child.source_code:
                        # Find tuple elements
                        for e2 in self.cpg.edges:
                            if e2.from_node == child.id and e2.type == EdgeType.AST_CHILD:
                                elements.append(e2.to_node)
        return elements
    
    # Returns node ids that have an incoming edge to the given node, used as potential taint sources.
    def _find_potential_sources(self, node_id: str) -> List[str]:
        """Find potential data sources for uncertain flow"""
        # For uncertain nodes, look at incoming edges
        sources = []
        for edge in self.cpg.edges:
            if edge.to_node == node_id:
                sources.append(edge.from_node)
        return sources
    
    # Returns node ids that have an outgoing edge from the given node, used as potential taint sinks.
    def _find_potential_sinks(self, node_id: str) -> List[str]:
        """Find potential data sinks for uncertain flow"""
        # For uncertain nodes, look at outgoing edges
        sinks = []
        for edge in self.cpg.edges:
            if edge.from_node == node_id:
                sinks.append(edge.to_node)
        return sinks
    
    # Looks up and returns a CPG node by its id, or None if not found.
    def _get_node_by_id(self, node_id: str) -> Optional[GraphNode]:
        """Helper to get node by ID"""
        return next((n for n in self.cpg.nodes if n.id == node_id), None)
    
    # Returns a new SemanticGraph combining the original CPG edges with all accumulated DFG edges.
    def get_cpg(self) -> SemanticGraph:
        """Return CPG with DFG edges added"""
        all_edges = list(self.cpg.edges) + self.dfg_edges
        return SemanticGraph(
            nodes=self.cpg.nodes,
            edges=all_edges,
            symbol_table=self.cpg.symbol_table,
            scopes=self.cpg.scopes,
        )
    
    def extract_interprocedural_paths(
        self,
        source_node_id: str,
        sink_node_id: str,
        max_depth: int = 10
    ) -> List[DataFlowPath]:
        """
        Extract all interprocedural data flow paths from source to sink
        
        Args:
            source_node_id: Starting node ID
            sink_node_id: Target node ID
            max_depth: Maximum path length
        
        Returns:
            List of data flow paths with uncertainty info
        """
        paths = []
        visited = set()
        
        def dfs(current: str, target: str, path: List[Tuple[str, str, DFGEdgeType]], depth: int):
            if depth > max_depth:
                return
            
            if current == target:
                # Found a path
                uncertainty = self._compute_path_uncertainty(path)
                confidence = self._compute_path_confidence(path)
                
                paths.append(DataFlowPath(
                    source_node_id=source_node_id,
                    sink_node_id=sink_node_id,
                    path_edges=list(path),
                    uncertainty=uncertainty,
                    confidence=confidence,
                    description=self._describe_path(path)
                ))
                return
            
            if current in visited:
                return
            
            visited.add(current)
            
            # Follow DFG edges
            for edge in self.dfg_edges:
                if edge.from_node == current:
                    edge_type_value = None
                    if edge.metadata:
                        edge_type_value = edge.metadata.get("dfg_edge_type")
                    if not edge_type_value:
                        if edge.type == EdgeType.DFG_PARAM_PASS:
                            edge_type_value = DFGEdgeType.DFG_ARG_PASS.value
                        elif edge.type == EdgeType.DFG_RET:
                            edge_type_value = DFGEdgeType.DFG_RET.value
                        else:
                            edge_type_value = DFGEdgeType.DFG_VAR_USE.value
                    try:
                        edge_type = DFGEdgeType(edge_type_value)
                    except Exception:
                        edge_type = DFGEdgeType.DFG_VAR_USE
                    path.append((edge.from_node, edge.to_node, edge_type))
                    dfs(edge.to_node, target, path, depth + 1)
                    path.pop()
            
            visited.remove(current)
        
        dfs(source_node_id, sink_node_id, [], 0)
        return paths
    
    # Determines the highest uncertainty level among all edge types in a data flow path.
    def _compute_path_uncertainty(self, path: List[Tuple[str, str, DFGEdgeType]]) -> UncertaintyLevel:
        """Compute overall uncertainty of a path"""
        if any(edge_type == DFGEdgeType.DFG_UNCERTAIN for _, _, edge_type in path):
            return UncertaintyLevel.UNKNOWN
        
        if any(edge_type == DFGEdgeType.DFG_CALLBACK for _, _, edge_type in path):
            return UncertaintyLevel.LIKELY
        
        return UncertaintyLevel.CERTAIN
    
    # Averages the confidence metadata of each edge in the path to produce an overall score.
    def _compute_path_confidence(self, path: List[Tuple[str, str, DFGEdgeType]]) -> float:
        """Compute confidence score for a path"""
        if not path:
            return 0.0
        
        # Average confidence of all edges
        confidences = []
        for source, target, edge_type in path:
            edge = next((e for e in self.dfg_edges 
                        if e.from_node == source and e.to_node == target), None)
            if edge and edge.metadata:
                confidences.append(edge.metadata.get("confidence", 1.0))
        
        return sum(confidences) / len(confidences) if confidences else 0.0
    
    # Formats a data flow path as a human-readable arrow-separated string of node names and edge types.
    def _describe_path(self, path: List[Tuple[str, str, DFGEdgeType]]) -> str:
        """Generate human-readable path description"""
        steps = []
        for source, target, edge_type in path:
            source_node = self._get_node_by_id(source)
            target_node = self._get_node_by_id(target)
            
            src_name = source_node.name if source_node else source
            tgt_name = target_node.name if target_node else target
            
            steps.append(f"{src_name} --[{edge_type.value}]--> {tgt_name}")
        
        return " → ".join(steps)
    
    # Returns a summary dict of function count, call site count, edge counts by type, and uncertain edge count.
    def get_statistics(self) -> Dict[str, Any]:
        """Get DFG statistics"""
        stats = {
            "total_functions": len(self.functions),
            "total_call_sites": len(self.call_sites),
            "total_dfg_edges": len(self.dfg_edges),
            "edge_types": {},
            "uncertain_edges": 0,
            "closure_captures": sum(len(c) for c in self.closure_captures.values()),
        }
        
        # Count edge types
        for edge in self.dfg_edges:
            edge_type = edge.type
            stats["edge_types"][edge_type] = stats["edge_types"].get(edge_type, 0) + 1
            
            if edge.metadata and edge.metadata.get("uncertainty") != "certain":
                stats["uncertain_edges"] += 1
        
        return stats
