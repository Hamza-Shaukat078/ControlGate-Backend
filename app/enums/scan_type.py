from enum import Enum


class ScanType(str, Enum):
    """Which engine(s) a scan runs. Orthogonal to ScanMode (static-analysis depth)."""

    STATIC = "static"
    DYNAMIC = "dynamic"
    HYBRID = "hybrid"
