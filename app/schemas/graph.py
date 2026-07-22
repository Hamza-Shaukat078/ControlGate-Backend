from typing import Optional, Any, Literal
from pydantic import BaseModel, Field
from app.enums.node_type import NodeType
from app.enums.edge_type import EdgeType


class NodeMetadata(BaseModel):
    """Enhanced metadata for CPG nodes"""
    language: Optional[Literal["python", "javascript", "typescript"]] = None
    framework: Optional[Literal["django", "fastapi", "react", "node"]] = None
    is_tainted: bool = False
    security_role: Optional[Literal["source", "sink", "sanitizer"]] = None
    
    # CPG-specific fields
    scope_id: Optional[str] = None
    symbol_name: Optional[str] = None
    is_exported: bool = False
    is_async: bool = False
    is_generator: bool = False
    visibility: Optional[Literal["public", "private", "protected"]] = None
    
    # Source location (for precise tracking)
    start_byte: Optional[int] = None
    end_byte: Optional[int] = None
    end_line: Optional[int] = None
    end_column: Optional[int] = None


class GraphNode(BaseModel):
    """Enhanced graph node for Code Property Graph"""
    id: str
    type: NodeType
    name: Optional[str] = None
    value: Optional[Any] = None
    file: str
    line: int
    column: int
    metadata: Optional[NodeMetadata] = None
    source_code: Optional[str] = None  # Original source code snippet
    
    # Parent/child relationships (for AST traversal)
    parent_id: Optional[str] = None
    # very imp to define list[str] as default_factory to avoid mutable default argument issues
    child_ids: list[str] = Field(default_factory=list)



class GraphEdge(BaseModel):
    """Enhanced graph edge with CPG support"""
    from_node: str = Field(alias="from")
    to_node: str = Field(alias="to")
    type: EdgeType
    metadata: Optional[dict[str, Any]] = None
    
    # Edge properties for control/data flow
    label: Optional[str] = None  # Edge label (e.g., "true", "false" for conditions)
    order: Optional[int] = None  # Order of execution/arguments

# changed from populate_by_name to validate_by_name 
    model_config = {"validate_by_name": True}


class SemanticGraph(BaseModel):
    """Code Property Graph representation"""
    nodes: list[GraphNode]
    edges: list[GraphEdge]
    
    # Symbol table for the entire graph
    symbol_table: dict[str, list[str]] = Field(default_factory=dict)  # symbol_name -> [node_ids]
    
    # Scope hierarchy
    scopes: dict[str, dict[str, Any]] = Field(default_factory=dict)  # scope_id -> scope_info
