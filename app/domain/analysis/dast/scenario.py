"""Scenario schema for Phase 2B — multi-step, stateful DAST checks.

Deliberately small: named steps + extractors + assertions, not a general
DSL. Step-skipping-type scenarios (V2.3.1) are app-specific by nature — the
step list has to come from scan config, since there's no way to generically
discover "the business-logic steps" of an unknown app. The one scenario this
phase ships that IS built automatically (LOGOUT_INVALIDATES_SESSION, see
logout_discovery.py) still produces one of these Scenario objects; it just
fills in the URLs itself instead of asking for them.
"""
from dataclasses import dataclass, field
from typing import Any, Optional


@dataclass
class Assertion:
    type: str  # "status_in" | "status_not_in" | "body_contains" | "redirect_location_contains" | "any_of" | "all_of"
    expected: Any = None
    of: Optional[list["Assertion"]] = None


@dataclass
class Extractor:
    """Pulls a value out of a step's response into the scenario context, so
    later steps can reference it via "{var}" interpolation in their url/
    params/data/headers."""

    var: str
    source: str  # "header" | "cookie" | "regex" | "json_path"
    name: Optional[str] = None  # header/cookie name
    pattern: Optional[str] = None  # regex pattern; group 1 is captured
    path: Optional[str] = None  # dotted JSON path, e.g. "data.token"


@dataclass
class Step:
    method: str
    url: str  # may contain "{var}" placeholders filled from prior steps' extract()
    session: str = "primary"  # "primary" | "secondary" — which DastSession to use
    params: Optional[dict] = None
    data: Optional[dict] = None
    json_body: Optional[dict] = None
    headers: Optional[dict] = None
    follow_redirects: bool = False
    extract: list = field(default_factory=list)  # list[Extractor]
    assertions: list = field(default_factory=list)  # list[Assertion]


@dataclass
class Scenario:
    scenario_id: str
    asvs_controls: list
    requires_active_mode: bool = False
    severity: str = "medium"
    description: str = ""
    steps: list = field(default_factory=list)  # list[Step]
