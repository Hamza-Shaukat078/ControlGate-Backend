"""Loads queries/dynamic_queries.json — the DAST-engine analog of
semantic_engine/query_store/loader.py's QueryStore. Kept deliberately flat:
each rule's Python check function (checks.py) owns its own control flow, the
JSON only carries per-rule metadata and check-specific parameters (candidate
param names, payload templates) so new payload checks can be added without
touching code that doesn't need to change.
"""
import json
from pathlib import Path
from typing import Dict, List, Optional

from pydantic import BaseModel, Field


class DynamicQueryRule(BaseModel):
    rule_id: str
    check_type: str  # "payload" | "scenario" (scenario checks land in Phase 2B)
    asvs_controls: List[str] = Field(default_factory=list)
    owasp: str = ""
    cwe: Optional[str] = None
    severity: str = "medium"
    description: str = ""
    # Gates checks with side effects (e.g. request smuggling can genuinely
    # desync a real proxy chain) behind the same active_mode flag Scenario
    # uses — same vocabulary, same reason: nothing with side effects runs
    # unless the scan explicitly authorized it.
    requires_active_mode: bool = False

    model_config = {"extra": "allow"}


def _default_path() -> Path:
    project_root = Path(__file__).parent.parent.parent.parent.parent
    return project_root / "queries" / "dynamic_queries.json"


def load_dynamic_queries(path: Optional[Path] = None) -> Dict[str, DynamicQueryRule]:
    path = path or _default_path()
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)

    rules: Dict[str, DynamicQueryRule] = {}
    for rule_id, rule_data in data.items():
        rules[rule_id] = DynamicQueryRule(rule_id=rule_id, **rule_data)
    return rules
