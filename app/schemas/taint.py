from typing import Literal
from pydantic import BaseModel
from app.enums.node_type import NodeType
from app.schemas.graph import GraphNode


class TaintMatchPattern(BaseModel):
    node_type: NodeType
    patterns: list[str]


class TaintSource(BaseModel):
    id: str
    description: str
    match: TaintMatchPattern


class TaintSink(BaseModel):
    id: str
    description: str
    match: TaintMatchPattern


class TaintResult(BaseModel):
    source_node: GraphNode
    sink_node: GraphNode
    flow_path: list[GraphNode]
    severity: Literal["low", "medium", "high", "critical"]


class VulnerabilityCandidate(BaseModel):
    flow_path: list[GraphNode]
    code_snippet: str
    source_description: str
    sink_description: str


class LLMAnalysisResult(BaseModel):
    is_vulnerability: bool
    explanation: str
    recommended_fix: str | None = None
