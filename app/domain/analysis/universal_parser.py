"""
Production-Grade Universal Parser using Tree-sitter
Supports: Python, JavaScript, TypeScript, HTML, JSON, and YAML

This module provides a unified interface for parsing multiple languages into a standardized AST format.
It replaces regex-based parsers with proper Tree-sitter grammars for reliable, scope-aware parsing.
"""

from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any, Tuple
from pathlib import Path
from enum import Enum
import logging

try:
    import tree_sitter
    from tree_sitter import Language, Parser, Node
    TREE_SITTER_AVAILABLE = True
except ImportError:
    TREE_SITTER_AVAILABLE = False
    logging.warning("tree-sitter not installed. Install with: pip install tree-sitter")


# Configure logging
logger = logging.getLogger(__name__)


class LanguageType(Enum):
    """Supported programming languages"""
    PYTHON = "python"
    JAVASCRIPT = "javascript"
    TYPESCRIPT = "typescript"
    HTML = "html"
    JSON = "json"
    YAML = "yaml"
    UNKNOWN = "unknown"


@dataclass
class StandardNode:
    """
    Unified AST node representation across all languages.
    
    This standardized format ensures consistent analysis regardless of source language.
    """
    type: str  # Node type (e.g., 'function_definition', 'class_declaration', 'call_expression')
    name: Optional[str] = None  # Identifier name (function name, variable name, etc.)
    start_point: Tuple[int, int] = (0, 0)  # (line, column) - 0-indexed
    end_point: Tuple[int, int] = (0, 0)  # (line, column) - 0-indexed
    source_code: str = ""  # Original source text for this node
    
    # Additional metadata
    parent: Optional['StandardNode'] = None
    children: List['StandardNode'] = field(default_factory=list)
    
    # Language-specific attributes (stored as dict for flexibility)
    attributes: Dict[str, Any] = field(default_factory=dict)
    
    # Scope information
    scope_id: Optional[str] = None
    
    # Return a compact debug string showing node type, optional name, and source location.
    def __repr__(self) -> str:
        name_str = f" '{self.name}'" if self.name else ""
        return f"<StandardNode {self.type}{name_str} at {self.start_point[0]}:{self.start_point[1]}>"
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert node to dictionary for serialization"""
        return {
            "type": self.type,
            "name": self.name,
            "start_point": self.start_point,
            "end_point": self.end_point,
            "source_code": self.source_code,
            "attributes": self.attributes,
            "scope_id": self.scope_id,
            "children": [child.to_dict() for child in self.children]
        }


class UniversalParser:
    """
    Production-grade parser using Tree-sitter for multiple languages.
    
    Features:
    - Supports Python, JavaScript, TypeScript, HTML, JSON, YAML
    - Gracefully handles syntax errors
    - Provides unified StandardNode output
    - Thread-safe parser instances
    - Automatic language detection from file extensions
    
    Usage:
        parser = UniversalParser()
        tree = parser.parse_file("app.py")
        # or
        tree = parser.parse_code(code_string, language=LanguageType.JAVASCRIPT)
    """
    
    # Language file extension mappings
    EXTENSION_MAP = {
        '.py': LanguageType.PYTHON,
        '.pyw': LanguageType.PYTHON,
        '.js': LanguageType.JAVASCRIPT,
        '.jsx': LanguageType.JAVASCRIPT,
        '.mjs': LanguageType.JAVASCRIPT,
        '.cjs': LanguageType.JAVASCRIPT,
        '.ts': LanguageType.TYPESCRIPT,
        '.tsx': LanguageType.TYPESCRIPT,
        '.html': LanguageType.HTML,
        '.htm': LanguageType.HTML,
        '.json': LanguageType.JSON,
        '.yaml': LanguageType.YAML,
        '.yml': LanguageType.YAML,
    }
    
    def __init__(self, grammar_path: Optional[Path] = None):
        """
        Initialize the Universal Parser.
        
        Args:
            grammar_path: Optional path to directory containing compiled .so grammar files.
                         If None, searches in default locations.
        """
        if not TREE_SITTER_AVAILABLE:
            raise RuntimeError(
                "tree-sitter is not installed. Install it with:\n"
                "pip install tree-sitter\n\n"
                "Then build the language grammars. See setup instructions."
            )
        
        self.grammar_path = grammar_path or self._find_grammar_path()
        self.languages: Dict[LanguageType, Language] = {}
        self.parsers: Dict[LanguageType, Parser] = {}
        
        # Load all supported languages
        self._load_languages()
    
    def _find_grammar_path(self) -> Path:
        """
        Find the directory containing compiled grammar files.
        
        Searches in order:
        1. ./build/ (development)
        2. ./tree-sitter-grammars/
        3. ~/.tree-sitter/
        """
        candidates = [
            Path.cwd() / "build",
            Path.cwd() / "tree-sitter-grammars",
            Path.home() / ".tree-sitter",
        ]
        
        for path in candidates:
            if path.exists() and path.is_dir():
                logger.info(f"Found grammar path: {path}")
                return path
        
        # Default to ./build and create if doesn't exist
        default_path = Path.cwd() / "build"
        default_path.mkdir(exist_ok=True)
        logger.warning(f"No grammar files found. Creating directory: {default_path}")
        logger.warning("You need to build language grammars. See setup_grammars.py")
        return default_path
    
    def _load_languages(self):
        """Load all language grammars using tree-sitter 0.22+ package API."""
        import tree_sitter_python as _tspy
        import tree_sitter_javascript as _tsjs
        import tree_sitter_typescript as _tsts
        import tree_sitter_html as _tshtml
        import tree_sitter_json as _tsjson
        import tree_sitter_yaml as _tsyaml

        lang_capsules = {
            LanguageType.PYTHON:     _tspy.language(),
            LanguageType.JAVASCRIPT: _tsjs.language(),
            LanguageType.TYPESCRIPT: _tsts.language_typescript(),
            LanguageType.HTML:       _tshtml.language(),
            LanguageType.JSON:       _tsjson.language(),
            LanguageType.YAML:       _tsyaml.language(),
        }

        for lang_type, capsule in lang_capsules.items():
            try:
                language = Language(capsule)
                self.languages[lang_type] = language
                self.parsers[lang_type] = Parser(language)
                logger.info(f"Loaded {lang_type.value} grammar successfully")
            except Exception as e:
                logger.error(f"Failed to load {lang_type.value} grammar: {e}")
    
    def detect_language(self, filepath: str) -> LanguageType:
        """
        Detect language from file extension.
        
        Args:
            filepath: Path to the source file
            
        Returns:
            Detected LanguageType or UNKNOWN
        """
        ext = Path(filepath).suffix.lower()
        return self.EXTENSION_MAP.get(ext, LanguageType.UNKNOWN)
    
    def parse_file(self, filepath: str) -> Optional[StandardNode]:
        """
        Parse a source file into a StandardNode tree.
        
        Args:
            filepath: Path to the source file
            
        Returns:
            Root StandardNode or None if parsing fails
        """
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                code = f.read()
        except Exception as e:
            logger.error(f"Failed to read file {filepath}: {e}")
            return None
        
        language = self.detect_language(filepath)
        
        if language == LanguageType.UNKNOWN:
            logger.warning(f"Unknown file type: {filepath}")
            return None
        
        return self.parse_code(code, language, filename=filepath)
    
    def parse_code(
        self, 
        code: str, 
        language: LanguageType,
        filename: str = "unknown"
    ) -> Optional[StandardNode]:
        """
        Parse source code into a StandardNode tree.
        
        Args:
            code: Source code string
            language: Language type
            filename: Optional filename for error reporting
            
        Returns:
            Root StandardNode or None if parsing fails
        """
        if language not in self.parsers:
            logger.error(f"No parser available for {language.value}")
            logger.error("Make sure the language grammar is properly built")
            return None
        
        try:
            # Parse with tree-sitter
            parser = self.parsers[language]
            tree = parser.parse(bytes(code, "utf8"))
            
            # Check for syntax errors
            if tree.root_node.has_error:
                logger.warning(f"Syntax errors found in {filename}, but continuing...")
                # Tree-sitter still produces a partial tree, which is useful
            
            # Convert to StandardNode
            root = self._convert_to_standard_node(
                tree.root_node, 
                code, 
                language
            )
            
            return root
            
        except Exception as e:
            logger.error(f"Failed to parse {filename}: {e}")
            return None
    
    def _convert_to_standard_node(
        self, 
        ts_node: 'Node', 
        source_code: str,
        language: LanguageType
    ) -> StandardNode:
        """
        Convert tree-sitter Node to StandardNode recursively.
        
        This is where the magic happens - we normalize different language ASTs
        into our unified StandardNode format.
        """
        # Extract node information
        node_type = ts_node.type
        start_point = ts_node.start_point
        end_point = ts_node.end_point
        
        # Extract source text for this node
        start_byte = ts_node.start_byte
        end_byte = ts_node.end_byte
        node_source = source_code[start_byte:end_byte]
        
        # Extract name (identifier) - language-specific
        name = self._extract_node_name(ts_node, source_code, language)
        
        # Create StandardNode
        std_node = StandardNode(
            type=node_type,
            name=name,
            start_point=start_point,
            end_point=end_point,
            source_code=node_source,
            attributes={
                "language": language.value,
                "is_named": ts_node.is_named,
                "has_error": ts_node.has_error,
            }
        )
        
        # Recursively convert children
        for child in ts_node.children:
            child_node = self._convert_to_standard_node(child, source_code, language)
            child_node.parent = std_node
            std_node.children.append(child_node)
        
        return std_node
    
    def _extract_node_name(
        self, 
        ts_node: 'Node', 
        source_code: str,
        language: LanguageType
    ) -> Optional[str]:
        """
        Extract identifier/name from a tree-sitter node.
        
        Different node types have different ways of storing names:
        - function_definition: look for 'name' child
        - class_declaration: look for 'identifier' child
        - variable_declaration: look for 'identifier' child
        """
        # Common identifier node types
        identifier_types = {'identifier', 'name', 'property_identifier', 'type_identifier'}
        
        # Check if this node itself is an identifier
        if ts_node.type in identifier_types:
            start = ts_node.start_byte
            end = ts_node.end_byte
            return source_code[start:end]
        
        # For named nodes, look for identifier children
        for child in ts_node.children:
            if child.type in identifier_types:
                start = child.start_byte
                end = child.end_byte
                return source_code[start:end]
        
        return None
    
    def get_available_languages(self) -> List[LanguageType]:
        """Get list of currently loaded languages"""
        return list(self.languages.keys())

    # Return True if a grammar was successfully loaded for the given language.
    def is_language_supported(self, language: LanguageType) -> bool:
        """Check if a language is currently supported"""
        return language in self.languages


# Convenience functions
def parse_file(filepath: str) -> Optional[StandardNode]:
    """
    Quick parse function - creates parser instance and parses file.
    
    For one-off parsing. If parsing multiple files, create a UniversalParser
    instance and reuse it for better performance.
    """
    parser = UniversalParser()
    return parser.parse_file(filepath)


def parse_code(code: str, language: LanguageType) -> Optional[StandardNode]:
    """
    Quick parse function - creates parser instance and parses code.
    
    For one-off parsing. If parsing multiple files, create a UniversalParser
    instance and reuse it for better performance.
    """
    parser = UniversalParser()
    return parser.parse_code(code, language)


# Example usage and testing
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    
    # Example: Parse Python code
    python_code = """
def hello(name):
    print(f"Hello, {name}!")
    
class MyClass:
    def __init__(self):
        self.value = 42
"""
    
    parser = UniversalParser()
    print(f"Available languages: {parser.get_available_languages()}")
    
    if parser.is_language_supported(LanguageType.PYTHON):
        tree = parser.parse_code(python_code, LanguageType.PYTHON, "example.py")
        if tree:
            print(f"\nParsed tree:")
            print(f"Root: {tree}")
            print(f"Children: {len(tree.children)}")
            for child in tree.children:
                print(f"  - {child}")
