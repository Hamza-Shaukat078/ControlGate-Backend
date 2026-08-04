from enum import Enum


class ScanMode(str, Enum):
    """Static-analysis scan depth. Orthogonal to ScanType (static/dynamic/hybrid)."""

    QUICK = "QUICK"
    DEEP = "DEEP"
    FULL = "FULL"
