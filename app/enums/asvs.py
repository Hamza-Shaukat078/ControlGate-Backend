from enum import Enum


class ASVSLevel(str, Enum):
    L1 = "L1"
    L2 = "L2"
    L3 = "L3"


class EvidenceSource(str, Enum):
    STATIC_CODE = "static_code"
    CONFIG_INSPECTION = "config_inspection"
    DEPENDENCY_SCAN = "dependency_scan"
    DYNAMIC_PROBE = "dynamic_probe"
    MANUAL_ATTESTATION = "manual_attestation"


class ControlVerdict(str, Enum):
    PASS = "pass"
    FAIL = "fail"
    N_A = "n_a"
    MANUAL_REVIEW = "manual_review"
    NOT_TESTED = "not_tested"
