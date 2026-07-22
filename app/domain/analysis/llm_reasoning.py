from typing import Optional
from app.schemas.taint import VulnerabilityCandidate, LLMAnalysisResult


class LLMReasoning:
    """
    LLM-based vulnerability analysis and patch generation.
    For MVP, uses rule-based heuristics. Can integrate with OpenAI/Anthropic later.
    """
    
    # Store the optional API key and set a flag to switch between LLM and heuristic analysis.
    def __init__(self, llm_api_key: Optional[str] = None):
        self.llm_api_key = llm_api_key
        self.use_llm = bool(llm_api_key)
    
    def analyze(self, candidate: VulnerabilityCandidate) -> LLMAnalysisResult:
        """
        Analyze if a taint flow represents a real vulnerability.
        
        Args:
            candidate: Vulnerability candidate with flow path and code
        
        Returns:
            Analysis result with explanation and fix
        """
        if self.use_llm:
            return self._analyze_with_llm(candidate)
        else:
            return self._analyze_heuristic(candidate)
    
    def _analyze_with_llm(self, candidate: VulnerabilityCandidate) -> LLMAnalysisResult:
        """
        Call LLM API for analysis (placeholder for future integration).
        """
        # TODO: Integrate with OpenAI/Anthropic/etc
        # For now, fall back to heuristic
        return self._analyze_heuristic(candidate)
    
    def _analyze_heuristic(self, candidate: VulnerabilityCandidate) -> LLMAnalysisResult:
        """
        Rule-based vulnerability analysis.
        """
        source_desc = candidate.source_description.lower()
        sink_desc = candidate.sink_description.lower()
        code = candidate.code_snippet.lower()
        
        # SQL Injection detection
        if "sql" in sink_desc or "execute" in sink_desc or "query" in sink_desc:
            if "request" in source_desc or "input" in source_desc:
                if "escape" not in code and "sanitize" not in code and "parameterized" not in code:
                    return LLMAnalysisResult(
                        is_vulnerability=True,
                        explanation=(
                            "Potential SQL Injection vulnerability detected. "
                            "User input flows directly to a SQL query without sanitization or parameterization. "
                            "This allows attackers to inject malicious SQL commands."
                        ),
                        recommended_fix=(
                            "Use parameterized queries or prepared statements. "
                            "For example: `cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))` "
                            "or use an ORM with built-in escaping."
                        )
                    )
        
        # Command Injection detection
        if any(cmd in sink_desc for cmd in ["system", "exec", "subprocess", "popen"]):
            if "request" in source_desc or "input" in source_desc:
                if "shell=true" in code or "shell=false" not in code:
                    return LLMAnalysisResult(
                        is_vulnerability=True,
                        explanation=(
                            "Potential Command Injection vulnerability detected. "
                            "User input flows to system command execution. "
                            "Attackers can inject shell commands to execute arbitrary code on the server."
                        ),
                        recommended_fix=(
                            "Avoid using shell=True in subprocess calls. "
                            "Validate and sanitize all user input. "
                            "Use allowlists for permitted commands and arguments."
                        )
                    )
        
        # Path Traversal detection
        if "file" in sink_desc and ("read" in sink_desc or "write" in sink_desc or "open" in sink_desc):
            if "request" in source_desc or "input" in source_desc:
                if ".." not in code and "os.path.abspath" not in code:
                    return LLMAnalysisResult(
                        is_vulnerability=True,
                        explanation=(
                            "Potential Path Traversal vulnerability detected. "
                            "User input is used to construct file paths without validation. "
                            "Attackers can access files outside the intended directory using '../' sequences."
                        ),
                        recommended_fix=(
                            "Validate file paths using os.path.abspath() and ensure they stay within allowed directories. "
                            "Use allowlists for permitted filenames."
                        )
                    )
        
        # XSS detection (if we add HTML rendering sinks)
        if "render" in sink_desc or "template" in sink_desc:
            if "request" in source_desc:
                if "escape" not in code and "safe" in code:
                    return LLMAnalysisResult(
                        is_vulnerability=True,
                        explanation=(
                            "Potential Cross-Site Scripting (XSS) vulnerability detected. "
                            "User input is rendered in HTML without escaping. "
                            "Attackers can inject malicious JavaScript to steal user data."
                        ),
                        recommended_fix=(
                            "Use template auto-escaping (enabled by default in most frameworks). "
                            "Avoid marking user input as 'safe' unless properly sanitized."
                        )
                    )
        
        # If no specific pattern matched, it's likely a false positive
        return LLMAnalysisResult(
            is_vulnerability=False,
            explanation=(
                "Taint flow detected but does not match known vulnerability patterns. "
                "This may be a false positive or require manual review."
            ),
            recommended_fix=None
        )
    
    # Produce a textual fix suggestion annotated with the vulnerable code snippet, or empty string if not a real vulnerability.
    def generate_patch(self, candidate: VulnerabilityCandidate, analysis: LLMAnalysisResult) -> str:
        """
        Generate a code patch to fix the vulnerability.
        """
        if not analysis.is_vulnerability or not analysis.recommended_fix:
            return ""
        
        # For now, return the recommended fix as a comment/suggestion
        # Future: parse code and generate actual diffs
        return f"# SUGGESTED FIX:\n# {analysis.recommended_fix}\n\n# VULNERABLE CODE:\n{candidate.code_snippet}"
