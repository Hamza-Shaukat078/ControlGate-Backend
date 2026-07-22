from pydantic import BaseModel, Field
from typing import Literal, Optional


class AnalyzeRequest(BaseModel):
    code: str = Field(..., description="Source code to analyze")
    language: Literal["python", "javascript", "typescript"] = Field(default="python")
    filename: Optional[str] = Field(default="source.py", description="Filename for context")


class FindingNode(BaseModel):
    id: str
    name: Optional[str]
    file: str
    line: int


class FindingItem(BaseModel):
    source: FindingNode
    sink: FindingNode
    severity: Literal["low", "medium", "high", "critical"]
    flow_path: list[dict]
    code_snippet: str
    explanation: str
    recommended_fix: Optional[str]
    patch: Optional[str]


class AnalyzeResponse(BaseModel):
    graph: dict
    vulnerabilities: list[FindingItem]
