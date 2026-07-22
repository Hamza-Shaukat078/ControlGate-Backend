"""
Query Store - Static Security Rule Management
Loads and manages predefined semantic security queries from JSON configuration.
Replaces LLM-based query generation with static, maintainable rules.
"""
import json
import os
from typing import Dict, List, Optional
from pathlib import Path
from pydantic import BaseModel, Field
import logging

logger = logging.getLogger(__name__)


class QueryRule(BaseModel):
    """Represents a single security detection rule."""
    rule_id: str
    name: str
    owasp: str
    cwe: Optional[str] = None
    description: str
    severity: str
    sources: List[str] = Field(default_factory=list)
    sinks: List[str] = Field(default_factory=list)
    patterns: List[str] = Field(default_factory=list)
    sanitizers: List[str] = Field(default_factory=list)
    required_guards: List[str] = Field(default_factory=list)
    blacklisted_algos: List[str] = Field(default_factory=list)
    regex_patterns: List[str] = Field(default_factory=list)
    dangerous_settings: List[str] = Field(default_factory=list)
    dangerous_values: List[str] = Field(default_factory=list)
    dangerous_comparisons: List[str] = Field(default_factory=list)
    required_functions: List[str] = Field(default_factory=list)
    required_settings: List[str] = Field(default_factory=list)
    confidence: str = "medium"
    asvs_controls: List[str] = Field(default_factory=list)  # e.g. ["V1.2.4"] — ASVS 5.0.0 control IDs this rule evaluates
    finding_polarity: str = "vulnerable"  # "vulnerable" (default: a match = a problem) | "compliant" (a match = evidence the control is satisfied)
    
    model_config = {"extra": "allow"}


class QueryStore:
    """
    Manages static security detection rules.
    Loads from YAML, provides query access, supports hot reload.
    """
    
    def __init__(self, queries_path: Optional[str] = None):
        """
        Initialize Query Store.
        
        Args:
            queries_path: Path to queries.json file. If None, uses default location.
        """
        if queries_path is None:
            # Default to queries/queries.json in project root
            project_root = Path(__file__).parent.parent.parent
            queries_path = project_root / "queries" / "queries.json"
        
        self.queries_path = Path(queries_path)
        self.queries: Dict[str, QueryRule] = {}
        self.last_modified: Optional[float] = None
        
        # Load queries on initialization
        self.load_queries()
        logger.info(f"QueryStore initialized with {len(self.queries)} rules from {self.queries_path}")
    
    def load_queries(self) -> None:
        """Load security queries from JSON file."""
        try:
            if not self.queries_path.exists():
                logger.error(f"Queries file not found: {self.queries_path}")
                return
            
            with open(self.queries_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            if not data:
                logger.warning("Empty queries file")
                return
            
            # Parse each rule
            self.queries = {}
            for rule_id, rule_data in data.items():
                # Add rule_id to data if not present
                if 'rule_id' not in rule_data:
                    rule_data['rule_id'] = rule_id
                
                try:
                    query_rule = QueryRule(**rule_data)
                    self.queries[rule_id] = query_rule
                except Exception as e:
                    logger.error(f"Failed to parse rule {rule_id}: {e}")
                    continue
            
            # Update last modified time
            self.last_modified = os.path.getmtime(self.queries_path)
            
            logger.info(f"Loaded {len(self.queries)} query rules")
            
        except Exception as e:
            logger.error(f"Failed to load queries: {e}")
            raise
    
    def reload(self) -> bool:
        """
        Reload queries if file has been modified.
        
        Returns:
            True if reloaded, False if no changes
        """
        try:
            current_mtime = os.path.getmtime(self.queries_path)
            if self.last_modified is None or current_mtime > self.last_modified:
                logger.info("Queries file modified, reloading...")
                self.load_queries()
                return True
            return False
        except Exception as e:
            logger.error(f"Failed to reload queries: {e}")
            return False
    
    def get_all_queries(self) -> List[QueryRule]:
        """
        Get all loaded query rules.
        
        Returns:
            List of all QueryRule objects
        """
        return list(self.queries.values())
    
    def get_query(self, rule_id: str) -> Optional[QueryRule]:
        """
        Get a specific query rule by ID.
        
        Args:
            rule_id: Rule identifier (e.g., 'SQL_INJECTION')
        
        Returns:
            QueryRule if found, None otherwise
        """
        return self.queries.get(rule_id)
    
    def get_queries_by_category(self, owasp_category: str) -> List[QueryRule]:
        """
        Get all queries for a specific OWASP category.
        
        Args:
            owasp_category: OWASP category (e.g., 'A03', 'A01')
        
        Returns:
            List of matching QueryRule objects
        """
        return [
            rule for rule in self.queries.values()
            if rule.owasp == owasp_category
        ]
    
    def get_queries_by_severity(self, severity: str) -> List[QueryRule]:
        """
        Get all queries of a specific severity level.
        
        Args:
            severity: Severity level ('critical', 'high', 'medium', 'low')
        
        Returns:
            List of matching QueryRule objects
        """
        return [
            rule for rule in self.queries.values()
            if rule.severity.lower() == severity.lower()
        ]
    
    def get_queries_by_cwe(self, cwe: str) -> List[QueryRule]:
        """
        Get all queries for a specific CWE.
        
        Args:
            cwe: CWE identifier (e.g., 'CWE-89')
        
        Returns:
            List of matching QueryRule objects
        """
        return [
            rule for rule in self.queries.values()
            if rule.cwe == cwe
        ]
    
    def search_queries(self, keyword: str) -> List[QueryRule]:
        """
        Search queries by keyword in name or description.
        
        Args:
            keyword: Search term
        
        Returns:
            List of matching QueryRule objects
        """
        keyword_lower = keyword.lower()
        return [
            rule for rule in self.queries.values()
            if keyword_lower in rule.name.lower() or 
               keyword_lower in rule.description.lower()
        ]
    
    def get_stats(self) -> Dict:
        """
        Get statistics about loaded queries.
        
        Returns:
            Dictionary with query statistics
        """
        total = len(self.queries)
        by_severity = {}
        by_owasp = {}
        
        for rule in self.queries.values():
            # Count by severity
            sev = rule.severity
            by_severity[sev] = by_severity.get(sev, 0) + 1
            
            # Count by OWASP
            owasp = rule.owasp
            by_owasp[owasp] = by_owasp.get(owasp, 0) + 1
        
        return {
            "total_rules": total,
            "by_severity": by_severity,
            "by_owasp": by_owasp,
            "last_modified": self.last_modified
        }


# Global query store instance (singleton pattern)
_query_store_instance: Optional[QueryStore] = None


def get_query_store(queries_path: Optional[str] = None) -> QueryStore:
    """
    Get the global QueryStore instance (singleton).
    
    Args:
        queries_path: Optional path to queries file (only used on first call)
    
    Returns:
        QueryStore instance
    """
    global _query_store_instance
    
    if _query_store_instance is None:
        _query_store_instance = QueryStore(queries_path)
    
    return _query_store_instance


def reload_query_store() -> bool:
    """
    Reload the global query store.
    
    Returns:
        True if reloaded, False if no changes
    """
    store = get_query_store()
    return store.reload()
