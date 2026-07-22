from enum import Enum


class ScanMode(str, Enum):
    QUICK = "QUICK"
    DEEP = "DEEP"
    CUSTOM = "CUSTOM"
