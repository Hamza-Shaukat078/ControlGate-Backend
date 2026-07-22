"""
LLM Classifier — AI-powered vulnerability validation (detection role).

Delegates all provider management, fallback, and quota tracking to
RoleAwareLLMPool with the 'detection' role:

  Llama-4-Scout → gpt-4o-mini → Phi-4 → Mistral-Small → Groq Llama-3.3 → OpenAI gpt-4o-mini

High-volume role: runs on every candidate finding, so uses fast low-tier
models with 150 req/day each — quota is distributed across 4 independent
model pools before any paid provider is touched.
"""
from __future__ import annotations

import json
import logging
import os
import re
from enum import Enum
from pathlib import Path
from typing import Dict, Optional

from pydantic import BaseModel

from semantic_engine.classifier.llm_pool import RoleAwareLLMPool

logger = logging.getLogger(__name__)


def _safe_json_loads(text: str) -> dict:
    """Parse JSON tolerantly, stripping invalid backslash escapes from LLM output."""
    try:
        return json.loads(text, strict=False)
    except json.JSONDecodeError:
        cleaned = re.sub(
            r'\\([^"\\bfnrtu/\n\r])',
            lambda m: '\\\\' + m.group(1),
            text,
        )
        return json.loads(cleaned, strict=False)


def _extract_json_payload(text: str) -> str:
    """Extract the most likely JSON object from LLM output."""
    stripped = text.strip()

    # Strip opening code fence without requiring a matching closing fence.
    # Requiring a closing ``` causes non-greedy regex to mis-match when the
    # response is truncated or contains backtick snippets inside field values.
    fence_open = re.match(r"```(?:json)?\s*", stripped, re.IGNORECASE)
    if fence_open:
        stripped = stripped[fence_open.end():].strip()
        # Remove trailing closing fence if present
        stripped = re.sub(r"\s*```\s*$", "", stripped).strip()

    start = stripped.find("{")
    end = stripped.rfind("}")
    if start < 0 or end <= start:
        raise ValueError("No JSON in response")
    return stripped[start:end + 1]


class Classification(str, Enum):
    SAFE             = "SAFE"
    VULNERABLE       = "VULNERABLE"
    LIKELY_VULNERABLE = "LIKELY_VULNERABLE"
    UNKNOWN          = "UNKNOWN"


class LLMClassificationResult(BaseModel):
    classification:     Classification
    explanation:        str
    severity:           str        # critical | high | medium | low
    exploitability_score: float    # 0.0 – 1.0
    remediation:        str
    cwe:                Optional[str] = None
    owasp:              Optional[str] = None
    confidence:         float          # 0.0 – 1.0


class LLMService:
    """
    Vulnerability classification service — detection role.
    Thin wrapper around RoleAwareLLMPool('detection') that adds:
      • response caching (prompt hash → result)
      • prompt construction
      • structured JSON response parsing
    """

    # Initializes detection role LLM pool, response cache, and logs service startup
    def __init__(self) -> None:
        self._pool = RoleAwareLLMPool(
            role="detection",
            timeout=int(os.getenv("LLM_CLASSIFIER_TIMEOUT", "20")),
            system_prompt=self._load_system_prompt(),
            min_interval_ms=int(os.getenv("LLM_MIN_INTERVAL_MS", "500")),
        )
        self._response_cache: Dict[str, LLMClassificationResult] = {}
        logger.info("LLMService (detection) initialized")

    # ── System prompt ─────────────────────────────────────────────────────────

    # Reads detection system prompt from file, falling back to a default string
    def _load_system_prompt(self) -> str:
        try:
            p = Path(__file__).parent.parent.parent / "app" / "LLM-prompts" / "detect-system-prompt.txt"
            if p.exists():
                return p.read_text(encoding="utf-8").strip()
        except Exception as exc:
            logger.warning(f"Could not load system prompt: {exc}")
        return "You are a security vulnerability analyzer."

    # ── Public API ────────────────────────────────────────────────────────────

    async def classify_code_slice(
        self,
        code_snippet:     str,
        rule_name:        str,
        rule_description: str,
        source_label:     str,
        sink_label:       str,
        owasp:            str,
        cwe:              Optional[str],
    ) -> LLMClassificationResult:
        """
        Classify a code slice as SAFE / VULNERABLE / LIKELY_VULNERABLE.
        Results are cached by prompt hash for the lifetime of the service.
        """
        if not code_snippet or not code_snippet.strip():
            return self._get_fallback_result(rule_name, owasp, cwe)

        prompt    = self._build_prompt(code_snippet, rule_name, rule_description,
                                       source_label, sink_label, owasp, cwe)
        cache_key = str(hash(prompt))
        if cached := self._response_cache.get(cache_key):
            return cached

        if not self._pool.is_available:
            return self._get_fallback_result(rule_name, owasp, cwe)

        raw = await self._pool.call(
            messages=[{"role": "user", "content": prompt}],
            max_tokens=1000,
            temperature=0.1,
        )
        if not raw:
            return self._get_fallback_result(rule_name, owasp, cwe)

        result = self._parse_response(raw, rule_name, owasp, cwe)
        self._response_cache[cache_key] = result
        return result

    # ── Prompt builder ────────────────────────────────────────────────────────

    # Builds the user prompt JSON with code snippet, source/sink context, and OWASP info
    def _build_prompt(
        self,
        code_snippet:     str,
        rule_name:        str,
        rule_description: str,
        source_label:     str,
        sink_label:       str,
        owasp:            str,
        cwe:              Optional[str],
    ) -> str:
        language = self._detect_language(code_snippet)
        context  = {
            "language":    language,
            "framework":   "FastAPI/Django/Generic",
            "source":      source_label,
            "sink":        sink_label,
            "description": f"{rule_name}: {rule_description}",
            "owasp":       owasp,
            "cwe":         cwe or "N/A",
        }
        return (
            "Analyze this code slice for security vulnerabilities.\n\n"
            "**Input Data:**\n"
            f"```json\n{json.dumps({'code': code_snippet, 'context': context}, indent=2)}\n```\n\n"
            f"The taint engine detected a suspicious dataflow from source '{source_label}' "
            f"to sink '{sink_label}'.\n\n"
            "Output this exact JSON (no other text):\n"
            "{\n"
            '    "vulnerable": true | false,\n'
            '    "type": "Vulnerability name or None",\n'
            '    "severity": "Low / Medium / High / Critical",\n'
            '    "explanation": "Why this is or is not a vulnerability.",\n'
            '    "recommendation": "Specific fix."\n'
            "}\n\n"
            "Only mark vulnerable if the code is actually exploitable."
        )

    # Heuristically identifies Python, JS, or TS from code token patterns
    def _detect_language(self, code: str) -> str:
        code_lower = code.lower()
        ts_score     = sum(1 for p in (": string", ": number", ": boolean", "interface ", "type ") if p in code)
        js_ts_score  = sum(1 for p in ("const ", "let ", "var ", "=>", "require(", "export ", ".then(") if p in code_lower)
        python_score = sum(1 for p in ("def ", "import ", "class ", "self.", "print(", "async def") if p in code_lower)
        if ts_score > 0 and js_ts_score > 0:
            return "typescript"
        if js_ts_score > python_score and js_ts_score >= 2:
            return "javascript"
        return "python"

    # ── Response parser ───────────────────────────────────────────────────────

    # Parses LLM JSON response into LLMClassificationResult, handling both format variants
    def _parse_response(
        self, response: str, rule_name: str, owasp: str, cwe: Optional[str]
    ) -> LLMClassificationResult:
        try:
            payload = _extract_json_payload(response)
            data = _safe_json_loads(payload)

            # Vulcan-LLM format (has "vulnerable" field)
            if "vulnerable" in data:
                is_vuln  = bool(data.get("vulnerable", False))
                vtype    = data.get("type", "Unknown")
                severity = data.get("severity", "Medium").lower()
                if is_vuln and vtype != "None":
                    cls, conf, expl = Classification.VULNERABLE, 0.9, 0.8
                elif not is_vuln:
                    cls, conf, expl = Classification.SAFE, 0.9, 0.0
                else:
                    cls, conf, expl = Classification.UNKNOWN, 0.5, 0.3
                return LLMClassificationResult(
                    classification=cls,
                    explanation=data.get("explanation", ""),
                    severity=severity,
                    exploitability_score=expl,
                    remediation=data.get("recommendation", "Review code."),
                    cwe=cwe, owasp=owasp, confidence=conf,
                )

            # Legacy format (has "classification" field)
            return LLMClassificationResult(
                classification=Classification(data.get("classification", "UNKNOWN")),
                explanation=data.get("explanation", ""),
                severity=data.get("severity", "medium"),
                exploitability_score=float(data.get("exploitability_score", 0.5)),
                remediation=data.get("remediation", "Review code."),
                cwe=cwe, owasp=owasp,
                confidence=float(data.get("confidence", 0.5)),
            )

        except Exception as exc:
            logger.error(f"[detection] parse failed: {exc} | response[:200]={response[:200]}")
            return self._get_fallback_result(rule_name, owasp, cwe)

    # ── Fallback ──────────────────────────────────────────────────────────────

    # Returns a LIKELY_VULNERABLE result used when LLM is unavailable
    def _get_fallback_result(
        self,
        rule_name: str = "Unknown",
        owasp:     str = "Unknown",
        cwe:       Optional[str] = None,
    ) -> LLMClassificationResult:
        return LLMClassificationResult(
            classification=Classification.LIKELY_VULNERABLE,
            explanation="LLM unavailable — pattern-based detection only",
            severity="medium",
            exploitability_score=0.5,
            remediation="Manual review recommended",
            cwe=cwe, owasp=owasp, confidence=0.5,
        )


# ── Singleton ─────────────────────────────────────────────────────────────────

_llm_service_instance: Optional[LLMService] = None


# Returns or creates the global LLMService singleton
def get_llm_service() -> LLMService:
    global _llm_service_instance
    if _llm_service_instance is None:
        _llm_service_instance = LLMService()
    return _llm_service_instance
