"""
Multi-File Repository Graph Linking
====================================

Extends CPG engine to support multi-file and multi-module analysis.

Features:
- Global symbol table for entire repository
- Import/export resolution (Python and JavaScript)
- Cross-file graph edges (IMPORT_CALL, EXPORT_RET, MODULE_REF)
- Inter-file data flow path traversal
- Name-based resolution (no full type inference required)
- Scalable to large repositories

Architecture:
1. RepositoryScanner - Discovers all source files
2. GlobalSymbolTable - Tracks exports/imports across files
3. ImportExportResolver - Resolves module references
4. CrossFileLinker - Creates inter-file edges
5. MultiFileDFG - Extends interprocedural DFG across files
"""

from typing import Dict, List, Set, Optional, Tuple, Any
from pathlib import Path
from dataclasses import dataclass, field
from enum import Enum
import re
from collections import defaultdict
import os
import hashlib
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock

from app.schemas.graph import GraphNode, GraphEdge, SemanticGraph, NodeMetadata
from app.enums.edge_type import EdgeType
from app.enums.node_type import NodeType
from app.domain.analysis.cpg_parser import CPGParser
from app.core.trace import trace_step
from app.domain.analysis.html_parser import HTMLParser
from app.domain.analysis.html_backend_linker import HTMLBackendLinker
from app.domain.analysis.interprocedural_dfg import InterproceduralDFG, DFGEdgeType
from app.domain.analysis.semantic_enricher import SemanticGraphEnricher
from pydantic import BaseModel


class CrossFileEdgeType(str, Enum):
    """Edge types for cross-file relationships"""
    IMPORT_CALL = "IMPORT_CALL"       # Import statement → Exported symbol
    EXPORT_RET = "EXPORT_RET"         # Exported symbol → Import usage
    MODULE_REF = "MODULE_REF"         # Module reference edge
    FILE_CONTAINS = "FILE_CONTAINS"   # File → Node (containment)


class ImportType(str, Enum):
    """Types of import statements"""
    # Python
    PYTHON_IMPORT = "import"           # import module
    PYTHON_FROM = "from"               # from module import name
    PYTHON_IMPORT_AS = "import_as"     # import module as alias
    
    # JavaScript
    JS_ES6_IMPORT = "es6_import"       # import { x } from 'module'
    JS_ES6_DEFAULT = "es6_default"     # import x from 'module'
    JS_REQUIRE = "require"             # const x = require('module')
    JS_DYNAMIC = "dynamic_import"      # import('module')


@dataclass
class ExportedSymbol:
    """Represents an exported symbol from a module"""
    name: str
    node_id: str
    file_path: str
    export_type: str                   # "function", "class", "variable", "default"
    is_default: bool = False
    alias: Optional[str] = None


@dataclass
class ImportedSymbol:
    """Represents an imported symbol"""
    name: str
    node_id: str
    file_path: str
    source_module: str                 # Module path or name
    import_type: ImportType
    alias: Optional[str] = None
    is_wildcard: bool = False          # For import *


@dataclass
class ModuleDefinition:
    """Represents a module/file in the repository"""
    file_path: str
    module_name: str                   # Computed module name
    language: str                      # "python" or "javascript"
    module_node_id: Optional[str] = None
    reexport_modules: List[str] = field(default_factory=list)
    exports: List[ExportedSymbol] = field(default_factory=list)
    imports: List[ImportedSymbol] = field(default_factory=list)
    cpg: Optional[SemanticGraph] = None


class GlobalSymbolTable:
    """
    Global symbol table for entire repository
    
    Tracks:
    - All exported symbols from each module
    - All imported symbols in each module
    - Module-to-file mappings
    - Symbol-to-location mappings
    """
    
    # Initializes empty dicts for modules, symbols, file mappings, and import cache
    def __init__(self):
        # Module name → ModuleDefinition
        self.modules: Dict[str, ModuleDefinition] = {}
        
        # Symbol name → List[ExportedSymbol] (can have duplicates across files)
        self.exported_symbols: Dict[str, List[ExportedSymbol]] = defaultdict(list)
        
        # File path → ModuleDefinition
        self.file_to_module: Dict[str, ModuleDefinition] = {}
        self.file_to_module_node: Dict[str, str] = {}
        
        # Import resolution cache: (file, module_name) → resolved_file
        self.import_cache: Dict[Tuple[str, str], Optional[str]] = {}
    
    def add_module(self, module: ModuleDefinition):
        """Register a module in the global symbol table"""
        self.modules[module.module_name] = module
        self.file_to_module[module.file_path] = module
        if module.module_node_id:
            self.file_to_module_node[module.file_path] = module.module_node_id
        
        # Index exports
        for export in module.exports:
            self.exported_symbols[export.name].append(export)

    def expand_reexports(self):
        """Expand export * from 'module' into current module exports (name-based)."""
        changed = True
        while changed:
            changed = False
            for module in list(self.modules.values()):
                if not module.reexport_modules:
                    continue
                for reexport in module.reexport_modules:
                    target_file = self.resolve_import(module.file_path, reexport)
                    if not target_file:
                        continue
                    target_module = self.file_to_module.get(target_file)
                    if not target_module:
                        continue
                    for export in target_module.exports:
                        if any(e.name == export.name for e in module.exports):
                            continue
                        new_export = ExportedSymbol(
                            name=export.name,
                            node_id=export.node_id,
                            file_path=module.file_path,
                            export_type="reexport",
                            is_default=export.is_default,
                            alias=export.alias
                        )
                        module.exports.append(new_export)
                        self.exported_symbols[new_export.name].append(new_export)
                        changed = True
    
    def find_export(
        self,
        symbol_name: str,
        from_file: Optional[str] = None
    ) -> List[ExportedSymbol]:
        """
        Find exported symbols by name
        
        Args:
            symbol_name: Name to search for
            from_file: Optional file path to prioritize local exports
        
        Returns:
            List of matching exported symbols
        """
        matches = self.exported_symbols.get(symbol_name, [])
        
        if from_file and matches:
            # Prioritize exports from the same file (for relative imports)
            same_file = [e for e in matches if e.file_path == from_file]
            if same_file:
                return same_file
        
        return matches
    
    def resolve_import(
        self,
        importing_file: str,
        module_path: str,
        symbol_name: Optional[str] = None
    ) -> Optional[str]:
        """
        Resolve an import to a file path
        
        Args:
            importing_file: File doing the import
            module_path: Module being imported (e.g., "./utils", "requests")
            symbol_name: Specific symbol being imported
        
        Returns:
            Resolved file path or None if not found
        """
        cache_key = (importing_file, module_path)
        if cache_key in self.import_cache:
            return self.import_cache[cache_key]
        
        resolved = self._resolve_import_internal(importing_file, module_path)
        self.import_cache[cache_key] = resolved
        return resolved
    
    def _resolve_import_internal(
        self,
        importing_file: str,
        module_path: str
    ) -> Optional[str]:
        """Internal import resolution logic"""
        # Relative import (./file, ../file)
        if module_path.startswith('.'):
            base_dir = Path(importing_file).parent
            resolved = self._resolve_relative_import(base_dir, module_path)
            if resolved:
                return str(resolved)
        
        # Absolute module name
        # Try exact match first
        if module_path in self.modules:
            return self.modules[module_path].file_path
        
        # Try converting module path to file path
        # Python: package.module → package/module.py
        # JavaScript: 'utils/helper' → utils/helper.js
        for module_def in self.modules.values():
            if self._module_matches(module_def.module_name, module_path):
                return module_def.file_path
        
        return None
    
    def _resolve_relative_import(
        self,
        base_dir: Path,
        relative_path: str
    ) -> Optional[Path]:
        """Resolve relative import path"""
        # Remove leading dots and convert to path
        path_parts = relative_path.lstrip('.').lstrip('/').split('/')
        
        # Count leading dots for parent directory traversal
        parent_levels = len(relative_path) - len(relative_path.lstrip('.'))
        
        current = base_dir
        for _ in range(parent_levels - 1):
            current = current.parent
        
        target = current / '/'.join(path_parts)
        
        # Try with extensions
        for ext in ['.py', '.js', '.ts', '/index.js', '/index.py', '']:
            candidate = Path(str(target) + ext)
            if str(candidate) in self.file_to_module:
                return candidate
        
        return None
    
    def _module_matches(self, module_name: str, import_path: str) -> bool:
        """Check if module name matches import path"""
        # Convert both to normalized form
        normalized_module = module_name.replace('.', '/').replace('\\', '/')
        normalized_import = import_path.replace('.', '/').replace('\\', '/')
        
        return normalized_module.endswith(normalized_import) or \
               normalized_import.endswith(normalized_module)


class RepositoryScanner:
    """
    Scans repository to discover all source files
    
    Supports:
    - Python (.py)
    - JavaScript (.js, .jsx)
    - TypeScript (.ts, .tsx)
    - HTML/templates (.html, .htm, .jinja, .j2, .ejs, .hbs, .handlebars, .mustache, .pug)
    """
    
    # Sets repo path and default exclusion patterns
    def __init__(self, repo_path: str, exclude_patterns: Optional[List[str]] = None):
        self.repo_path = Path(repo_path)
        self.exclude_patterns = exclude_patterns or [
            'node_modules',
            'venv',
            '__pycache__',
            '.git',
            '.vulcan_cache',
            'dist',
            'build',
            '*.pyc',
            '*.min.js'
        ]
    
    def scan(self) -> List[Path]:
        """
        Scan repository and return list of source files
        
        Returns:
            List of Path objects for source files
        """
        source_files = []
        
        # Supported extensions
        extensions = {
            '.py', '.js', '.jsx', '.ts', '.tsx',
            '.html', '.htm', '.jinja', '.j2', '.ejs',
            '.hbs', '.handlebars', '.mustache', '.pug'
        }
        
        for file_path in self.repo_path.rglob('*'):
            if not file_path.is_file():
                continue
            
            if file_path.suffix not in extensions:
                continue
            
            # Check exclusion patterns
            if self._should_exclude(file_path):
                continue
            
            source_files.append(file_path)
        
        return sorted(source_files)
    
    def _should_exclude(self, file_path: Path) -> bool:
        """Check if file should be excluded"""
        file_str = str(file_path)
        
        for pattern in self.exclude_patterns:
            if '*' in pattern:
                # Glob pattern
                if file_path.match(pattern):
                    return True
            else:
                # Simple substring match
                if pattern in file_str:
                    return True
        
        return False


class GraphCache:
    """On-disk cache for per-file graphs keyed by content hash."""

    # Sets up on-disk cache directory and size/entry limits
    def __init__(self, repo_path: str):
        self.cache_dir = Path(repo_path) / ".vulcan_cache" / "graphs"
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.max_entries = int(os.getenv("VULCAN_CACHE_MAX_FILES", "5000"))
        self.max_mb = int(os.getenv("VULCAN_CACHE_MAX_MB", "200"))

    # Returns SHA-256 hash of file content + language for cache keying
    def _hash(self, content: str, language: str) -> str:
        h = hashlib.sha256()
        h.update(language.encode("utf-8"))
        h.update(b":")
        h.update(content.encode("utf-8", errors="ignore"))
        return h.hexdigest()

    # Loads and deserializes a cached SemanticGraph if available
    def get(self, file_path: Path, content: str, language: str) -> Optional[SemanticGraph]:
        key = self._hash(content, language)
        cache_file = self.cache_dir / f"{key}.json"
        if not cache_file.exists():
            return None
        try:
            data = json.loads(cache_file.read_text(encoding="utf-8"))
            graph_data = data.get("graph")
            if not graph_data:
                return None
            try:
                return SemanticGraph.model_validate(graph_data)  # pydantic v2
            except Exception:
                return SemanticGraph.parse_obj(graph_data)  # pydantic v1 fallback
        except Exception:
            return None

    # Serializes and writes a SemanticGraph to the cache, then prunes
    def set(self, file_path: Path, content: str, language: str, graph: SemanticGraph):
        key = self._hash(content, language)
        cache_file = self.cache_dir / f"{key}.json"
        try:
            graph_payload = graph.model_dump(by_alias=True)
        except Exception:
            graph_payload = graph.dict(by_alias=True)
        payload = {
            "file": str(file_path),
            "language": language,
            "hash": key,
            "graph": graph_payload
        }
        cache_file.write_text(json.dumps(payload), encoding="utf-8")
        self._prune()

    def _prune(self):
        """Trim cache by entry count and total size."""
        try:
            files = list(self.cache_dir.glob("*.json"))
        except Exception:
            return
        if not files:
            return

        try:
            files.sort(key=lambda p: p.stat().st_mtime)
        except Exception:
            return

        total_size = 0
        sizes = []
        for f in files:
            try:
                size = f.stat().st_size
            except Exception:
                size = 0
            sizes.append((f, size))
            total_size += size

        max_bytes = self.max_mb * 1024 * 1024
        while (len(sizes) > self.max_entries) or (total_size > max_bytes):
            f, size = sizes.pop(0)
            try:
                f.unlink(missing_ok=True)
            except Exception:
                pass
            total_size -= size


class ImportExportResolver:
    """
    Resolves imports and exports for Python and JavaScript
    
    Extracts:
    - Python: import, from...import, __all__
    - JavaScript: import, export, require, module.exports
    """
    
    # Stores CPG, file path, language, and re-export module list
    def __init__(self, cpg: SemanticGraph, file_path: str, language: str):
        self.cpg = cpg
        self.file_path = file_path
        self.language = language.lower()
        self.reexport_modules: List[str] = []

    def get_reexport_modules(self) -> List[str]:
        """Return modules referenced by export * from 'module'."""
        return list(self.reexport_modules)
    
    def extract_exports(self) -> List[ExportedSymbol]:
        """Extract all exported symbols from CPG"""
        if self.language == "python":
            return self._extract_python_exports()
        elif self.language in ("javascript", "typescript"):
            return self._extract_javascript_exports()
        return []
    
    def extract_imports(self) -> List[ImportedSymbol]:
        """Extract all imported symbols from CPG"""
        if self.language == "python":
            return self._extract_python_imports()
        elif self.language in ("javascript", "typescript"):
            return self._extract_javascript_imports()
        return []
    
    # ======================
    # Python Export/Import
    # ======================
    
    def _extract_python_exports(self) -> List[ExportedSymbol]:
        """
        Extract Python exports
        
        In Python, exports are:
        1. Top-level function definitions
        2. Top-level class definitions
        3. Top-level variable assignments
        4. Symbols listed in __all__
        """
        exports = []
        
        # Find top-level definitions
        for node in self.cpg.nodes:
            # Top-level = no parent function or class
            if self._is_top_level(node.id):
                if node.type in {NodeType.FUNCTION, NodeType.ASYNC_FUNCTION}:
                    exports.append(ExportedSymbol(
                        name=node.name,
                        node_id=node.id,
                        file_path=self.file_path,
                        export_type="function"
                    ))
                elif node.type == NodeType.CLASS:
                    exports.append(ExportedSymbol(
                        name=node.name,
                        node_id=node.id,
                        file_path=self.file_path,
                        export_type="class"
                    ))
                elif node.type in {NodeType.ASSIGNMENT, NodeType.VARIABLE}:
                    exports.append(ExportedSymbol(
                        name=node.name,
                        node_id=node.id,
                        file_path=self.file_path,
                        export_type="variable"
                    ))
        
        # Check for __all__ definition (explicit exports)
        all_exports = self._find_python_all_exports()
        if all_exports:
            # Filter exports to only those in __all__
            exports = [e for e in exports if e.name in all_exports]
        
        return exports
    
    def _extract_python_imports(self) -> List[ImportedSymbol]:
        """
        Extract Python imports
        
        Patterns:
        1. import module
        2. import module as alias
        3. from module import name
        4. from module import name as alias
        5. from module import *
        """
        imports = []
        
        for node in self.cpg.nodes:
            if node.type == NodeType.IMPORT:
                code = node.source_code or ""
                
                if code.startswith("from "):
                    # from module import ...
                    imports.extend(self._parse_python_from_import(node))
                elif code.startswith("import "):
                    # import module
                    imports.extend(self._parse_python_import(node))
        
        return imports
    
    def _parse_python_from_import(self, node: GraphNode) -> List[ImportedSymbol]:
        """Parse 'from module import name' statements"""
        code = node.source_code or ""
        imports = []
        
        # Pattern: from <module> import <names>
        match = re.match(r'from\s+([\w.]+)\s+import\s+(.+)', code)
        if match:
            module = match.group(1)
            imports_str = match.group(2)
            
            # Handle wildcard
            if imports_str.strip() == '*':
                imports.append(ImportedSymbol(
                    name="*",
                    node_id=node.id,
                    file_path=self.file_path,
                    source_module=module,
                    import_type=ImportType.PYTHON_FROM,
                    is_wildcard=True
                ))
            else:
                # Parse individual imports
                for item in imports_str.split(','):
                    item = item.strip()
                    
                    # Handle 'as' alias
                    if ' as ' in item:
                        name, alias = item.split(' as ')
                        name = name.strip()
                        alias = alias.strip()
                    else:
                        name = item
                        alias = None
                    
                    imports.append(ImportedSymbol(
                        name=name,
                        node_id=node.id,
                        file_path=self.file_path,
                        source_module=module,
                        import_type=ImportType.PYTHON_FROM,
                        alias=alias
                    ))
        
        return imports
    
    def _parse_python_import(self, node: GraphNode) -> List[ImportedSymbol]:
        """Parse 'import module' statements"""
        code = node.source_code or ""
        imports = []
        
        # Pattern: import <module> [as <alias>]
        code = code.replace("import ", "").strip()
        
        for item in code.split(','):
            item = item.strip()
            
            if ' as ' in item:
                module, alias = item.split(' as ')
                module = module.strip()
                alias = alias.strip()
            else:
                module = item
                alias = None
            
            imports.append(ImportedSymbol(
                name=module,
                node_id=node.id,
                file_path=self.file_path,
                source_module=module,
                import_type=ImportType.PYTHON_IMPORT,
                alias=alias
            ))
        
        return imports
    
    def _find_python_all_exports(self) -> Optional[Set[str]]:
        """Find symbols listed in __all__"""
        for node in self.cpg.nodes:
            if node.name == "__all__" and node.type in {NodeType.ASSIGNMENT, NodeType.VARIABLE}:
                # Parse __all__ = ['name1', 'name2', ...]
                code = node.source_code or ""
                match = re.search(r'__all__\s*=\s*\[(.*?)\]', code)
                if match:
                    items_str = match.group(1)
                    items = [
                        item.strip().strip("'\"")
                        for item in items_str.split(',')
                        if item.strip()
                    ]
                    return set(items)
        return None
    
    # ======================
    # JavaScript Export/Import
    # ======================
    
    def _extract_javascript_exports(self) -> List[ExportedSymbol]:
        """
        Extract JavaScript exports
        
        Patterns:
        1. export function name() {}
        2. export class Name {}
        3. export const name = ...
        4. export { name1, name2 }
        5. export default ...
        6. module.exports = ...
        """
        exports = []
        
        for node in self.cpg.nodes:
            code = (node.source_code or "").strip()

            # re-exports: export { a as b } from 'module', export * from 'module'
            if code.startswith("export ") and " from " in code:
                module = self._extract_module_path(code)
                if module and "export *" in code:
                    self.reexport_modules.append(module)
                    # export * as name from 'module'
                    match = re.search(r'export\s+\*\s+as\s+(\w+)\s+from', code)
                    if match:
                        exports.append(ExportedSymbol(
                            name=match.group(1),
                            node_id=node.id,
                            file_path=self.file_path,
                            export_type="reexport_namespace"
                        ))
                elif module and "export {" in code:
                    match = re.search(r'\{([^}]+)\}', code)
                    if match:
                        names_str = match.group(1)
                        for item in names_str.split(','):
                            item = item.strip()
                            if ' as ' in item:
                                name, alias = item.split(' as ')
                                name = name.strip()
                                alias = alias.strip()
                            else:
                                name = item
                                alias = None
                            exports.append(ExportedSymbol(
                                name=alias or name,
                                node_id=node.id,
                                file_path=self.file_path,
                                export_type="reexport",
                                alias=alias
                            ))
                continue

            if code.startswith("export "):
                # export default ...
                if "export default" in code:
                    exported_name = self._extract_default_export_name(node)
                    # Try to pick named default export
                    match = re.search(r'export\s+default\s+(?:async\s+)?function\s+([A-Za-z0-9_$]+)', code)
                    if match:
                        exported_name = match.group(1)
                    else:
                        match = re.search(r'export\s+default\s+class\s+([A-Za-z0-9_$]+)', code)
                        if match:
                            exported_name = match.group(1)
                        else:
                            match = re.search(r'export\s+default\s+([A-Za-z0-9_$]+)', code)
                            if match:
                                exported_name = match.group(1)
                    exports.append(ExportedSymbol(
                        name=exported_name or "default",
                        node_id=node.id,
                        file_path=self.file_path,
                        export_type="default",
                        is_default=True
                    ))
                    continue

                # export { a, b as c }
                match = re.search(r'export\s+\{([^}]+)\}', code)
                if match:
                    names_str = match.group(1)
                    for item in names_str.split(','):
                        item = item.strip()
                        if not item:
                            continue
                        if ' as ' in item:
                            name, alias = item.split(' as ')
                            name = name.strip()
                            alias = alias.strip()
                        else:
                            name = item
                            alias = None
                        exports.append(ExportedSymbol(
                            name=alias or name,
                            node_id=node.id,
                            file_path=self.file_path,
                            export_type="named",
                            alias=alias
                        ))
                    continue

                # export function name() {}
                match = re.search(r'export\s+(?:async\s+)?function\s+([A-Za-z0-9_$]+)', code)
                if match:
                    exports.append(ExportedSymbol(
                        name=match.group(1),
                        node_id=node.id,
                        file_path=self.file_path,
                        export_type="function"
                    ))
                    continue

                # export class Name {}
                match = re.search(r'export\s+class\s+([A-Za-z0-9_$]+)', code)
                if match:
                    exports.append(ExportedSymbol(
                        name=match.group(1),
                        node_id=node.id,
                        file_path=self.file_path,
                        export_type="class"
                    ))
                    continue

                # export const/let/var name = ...
                match = re.search(r'export\s+(?:const|let|var)\s+([A-Za-z0-9_$]+)', code)
                if match:
                    exports.append(ExportedSymbol(
                        name=match.group(1),
                        node_id=node.id,
                        file_path=self.file_path,
                        export_type="variable"
                    ))
                    continue

                # export = (TypeScript)
                if re.search(r'\bexport\s*=\s*', code):
                    exports.append(ExportedSymbol(
                        name="default",
                        node_id=node.id,
                        file_path=self.file_path,
                        export_type="ts_export_equals",
                        is_default=True
                    ))
                    continue
            
            # module.exports = ...
            elif "module.exports" in code:
                # CommonJS export
                func_match = re.search(r'module\.exports\s*=\s*function\s+([A-Za-z0-9_$]+)', code)
                if func_match:
                    exports.append(ExportedSymbol(
                        name=func_match.group(1),
                        node_id=node.id,
                        file_path=self.file_path,
                        export_type="commonjs",
                        is_default=True
                    ))
                    continue
                ident_match = re.search(r'module\.exports\s*=\s*([A-Za-z0-9_$]+)', code)
                if ident_match:
                    exports.append(ExportedSymbol(
                        name=ident_match.group(1),
                        node_id=node.id,
                        file_path=self.file_path,
                        export_type="commonjs",
                        is_default=True
                    ))
                    continue
                match = re.search(r'module\.exports\s*=\s*\{([^}]+)\}', code)
                if match:
                    items = match.group(1)
                    for item in items.split(','):
                        item = item.strip()
                        if not item:
                            continue
                        if ':' in item:
                            name, _alias = item.split(':', 1)
                            name = name.strip()
                        else:
                            name = item
                        exports.append(ExportedSymbol(
                            name=name,
                            node_id=node.id,
                            file_path=self.file_path,
                            export_type="commonjs"
                        ))
                else:
                    exported_name = node.name or "default"
                    exports.append(ExportedSymbol(
                        name=exported_name,
                        node_id=node.id,
                        file_path=self.file_path,
                        export_type="commonjs",
                        is_default=True
                    ))

            # exports = ...
            elif re.search(r'^\s*exports\s*=', code):
                exports.append(ExportedSymbol(
                    name="default",
                    node_id=node.id,
                    file_path=self.file_path,
                    export_type="commonjs",
                    is_default=True
                ))

            # exports.foo = ...
            elif code.startswith("exports.") or "exports." in code:
                match = re.search(r'exports\.([A-Za-z0-9_$]+)', code)
                if match:
                    exports.append(ExportedSymbol(
                        name=match.group(1),
                        node_id=node.id,
                        file_path=self.file_path,
                        export_type="commonjs"
                    ))

            # export namespace (TypeScript)
            elif code.startswith("export namespace"):
                match = re.search(r'export\s+namespace\s+([A-Za-z0-9_$]+)', code)
                if match:
                    exports.append(ExportedSymbol(
                        name=match.group(1),
                        node_id=node.id,
                        file_path=self.file_path,
                        export_type="namespace"
                    ))

            # export = (TypeScript)
            elif re.search(r'\bexport\s*=\s*', code):
                exports.append(ExportedSymbol(
                    name="default",
                    node_id=node.id,
                    file_path=self.file_path,
                    export_type="ts_export_equals",
                    is_default=True
                ))
        
        return exports
    
    def _extract_javascript_imports(self) -> List[ImportedSymbol]:
        """
        Extract JavaScript imports
        
        Patterns:
        1. import { name } from 'module'
        2. import name from 'module'
        3. import * as name from 'module'
        4. const name = require('module')
        5. import('module') - dynamic
        """
        imports = []
        
        for node in self.cpg.nodes:
            code = (node.source_code or "").strip()

            # re-exports should also count as imports
            if code.startswith("export ") and " from " in code:
                module = self._extract_module_path(code)
                if not module:
                    continue
                if "export *" in code:
                    imports.append(ImportedSymbol(
                        name="*",
                        node_id=node.id,
                        file_path=self.file_path,
                        source_module=module,
                        import_type=ImportType.JS_ES6_IMPORT,
                        is_wildcard=True
                    ))
                else:
                    match = re.search(r'\{([^}]+)\}', code)
                    if match:
                        names_str = match.group(1)
                        for item in names_str.split(','):
                            item = item.strip()
                            if ' as ' in item:
                                name, alias = item.split(' as ')
                                name = name.strip()
                                alias = alias.strip()
                            else:
                                name = item
                                alias = None
                            imports.append(ImportedSymbol(
                                name=name,
                                node_id=node.id,
                                file_path=self.file_path,
                                source_module=module,
                                import_type=ImportType.JS_ES6_IMPORT,
                                alias=alias
                            ))
                continue
            
            if code.startswith("import "):
                # TS import equals: import x = require('module')
                ts_import_match = re.match(r'import\s+([A-Za-z0-9_$]+)\s*=\s*require\([\'"]([^\'"]+)[\'"]\)', code)
                if ts_import_match:
                    alias = ts_import_match.group(1)
                    module = ts_import_match.group(2)
                    imports.append(ImportedSymbol(
                        name="default",
                        node_id=node.id,
                        file_path=self.file_path,
                        source_module=module,
                        import_type=ImportType.JS_REQUIRE,
                        alias=alias
                    ))
                    continue
                imports.extend(self._parse_javascript_es6_import(node))
            elif "require(" in code:
                imports.extend(self._parse_javascript_require(node))
            elif code.startswith("import("):
                # Dynamic import
                module = self._extract_module_path(code)
                if module:
                    imports.append(ImportedSymbol(
                        name=module,
                        node_id=node.id,
                        file_path=self.file_path,
                        source_module=module,
                        import_type=ImportType.JS_DYNAMIC
                    ))
        
        return imports
    
    def _parse_javascript_es6_import(self, node: GraphNode) -> List[ImportedSymbol]:
        """Parse ES6 import statements"""
        code = node.source_code or ""
        imports = []
        
        # Extract module path
        module = self._extract_module_path(code)
        if not module:
            return []
        
        # import { name1, name2 } from 'module'
        if '{' in code:
            match = re.search(r'\{([^}]+)\}', code)
            if match:
                names_str = match.group(1)
                for item in names_str.split(','):
                    item = item.strip()
                    
                    if ' as ' in item:
                        name, alias = item.split(' as ')
                        name = name.strip()
                        alias = alias.strip()
                    else:
                        name = item
                        alias = None
                    
                    imports.append(ImportedSymbol(
                        name=name,
                        node_id=node.id,
                        file_path=self.file_path,
                        source_module=module,
                        import_type=ImportType.JS_ES6_IMPORT,
                        alias=alias
                    ))
        
        # import * as name from 'module'
        elif '* as ' in code:
            match = re.search(r'\*\s+as\s+(\w+)', code)
            if match:
                alias = match.group(1)
                imports.append(ImportedSymbol(
                    name="*",
                    node_id=node.id,
                    file_path=self.file_path,
                    source_module=module,
                    import_type=ImportType.JS_ES6_IMPORT,
                    alias=alias,
                    is_wildcard=True
                ))
        
        # import name from 'module' (default import)
        else:
            match = re.match(r'import\s+(\w+)\s+from', code)
            if match:
                name = match.group(1)
                imports.append(ImportedSymbol(
                    name="default",
                    node_id=node.id,
                    file_path=self.file_path,
                    source_module=module,
                    import_type=ImportType.JS_ES6_DEFAULT,
                    alias=name
                ))
        
        return imports
    
    def _parse_javascript_require(self, node: GraphNode) -> List[ImportedSymbol]:
        """Parse CommonJS require() statements"""
        code = node.source_code or ""
        imports = []

        # const { a, b: c } = require('module')
        destruct_match = re.match(r'(?:const|let|var)\s+\{([^}]+)\}\s*=\s*require\(', code)
        if destruct_match:
            module = self._extract_module_path(code)
            if module:
                items = destruct_match.group(1)
                for item in items.split(','):
                    item = item.strip()
                    if not item:
                        continue
                    if ':' in item:
                        name, alias = item.split(':', 1)
                        name = name.strip()
                        alias = alias.strip()
                    else:
                        name = item
                        alias = None
                    imports.append(ImportedSymbol(
                        name=name,
                        node_id=node.id,
                        file_path=self.file_path,
                        source_module=module,
                        import_type=ImportType.JS_REQUIRE,
                        alias=alias
                    ))
            return imports
        
        # const name = require('module')
        match = re.search(r'require\([\'"]([^\'"]+)[\'"]\)', code)
        if match:
            module = match.group(1)
            
            # Extract variable name
            var_match = re.match(r'(?:const|let|var)\s+(\w+)', code)
            alias = var_match.group(1) if var_match else None
            
            imports.append(ImportedSymbol(
                name="default",
                node_id=node.id,
                file_path=self.file_path,
                source_module=module,
                import_type=ImportType.JS_REQUIRE,
                alias=alias
            ))
        
        return imports
    
    # ======================
    # Helper Methods
    # ======================
    
    def _is_top_level(self, node_id: str) -> bool:
        """Check if node is at top level (not inside function/class)"""
        # Walk up AST_CHILD edges to check if inside function/class
        current = node_id
        visited = set()
        
        while current and current not in visited:
            visited.add(current)
            
            # Find parent
            parent_edge = next(
                (e for e in self.cpg.edges
                 if e.to_node == current and e.type == EdgeType.AST_CHILD),
                None
            )
            
            if not parent_edge:
                return True  # Reached root
            
            parent_node = next(
                (n for n in self.cpg.nodes if n.id == parent_edge.from_node),
                None
            )
            
            if parent_node and parent_node.type in [
                NodeType.FUNCTION, NodeType.ASYNC_FUNCTION, NodeType.CLASS, NodeType.METHOD
            ]:
                return False  # Inside function/class
            
            current = parent_edge.from_node
        
        return True
    
    def _extract_default_export_name(self, node: GraphNode) -> Optional[str]:
        """Extract name from export default statement"""
        # Could be: export default function name() {}
        #           export default class Name {}
        #           export default name
        if node.name:
            return node.name
        
        code = node.source_code or ""
        match = re.search(r'export\s+default\s+(\w+)', code)
        return match.group(1) if match else None
    
    def _extract_module_path(self, code: str) -> Optional[str]:
        """Extract module path from import/require statement"""
        # Look for quoted string
        match = re.search(r'[\'"]([^\'"]+)[\'"]', code)
        return match.group(1) if match else None


class CrossFileLinker:
    """
    Creates cross-file graph edges
    
    Edge types:
    - IMPORT_CALL: Import statement → Exported symbol
    - EXPORT_RET: Exported symbol → Import usage
    - MODULE_REF: Module reference edge
    """
    
    # Stores symbol table reference and empty cross-file edge list
    def __init__(self, global_symbol_table: GlobalSymbolTable):
        self.symbol_table = global_symbol_table
        self.cross_file_edges: List[GraphEdge] = []

    def link_imports_to_exports(self):
        """Create edges from imports to their exported definitions"""
        for module in self.symbol_table.modules.values():
            for imported in module.imports:
                # Resolve import to file
                target_file = self.symbol_table.resolve_import(
                    module.file_path,
                    imported.source_module,
                    imported.name
                )
                
                if not target_file:
                    # External dependency or unresolved
                    continue
                
                target_module = self.symbol_table.file_to_module.get(target_file)
                if not target_module:
                    continue
                
                # Find matching export
                if imported.is_wildcard:
                    # Import * - link to all exports
                    for export in target_module.exports:
                        self._create_import_edge(imported, export)
                elif imported.name == "default":
                    # Default import
                    default_exports = [e for e in target_module.exports if e.is_default]
                    for export in default_exports:
                        self._create_import_edge(imported, export)
                else:
                    # Named import
                    matching_exports = [
                        e for e in target_module.exports
                        if e.name == imported.name
                    ]
                    for export in matching_exports:
                        self._create_import_edge(imported, export)

    def link_module_refs(self):
        """Create MODULE_REF edges from import statements to module nodes."""
        for module in self.symbol_table.modules.values():
            for imported in module.imports:
                target_file = self.symbol_table.resolve_import(
                    module.file_path,
                    imported.source_module,
                    imported.name
                )
                if not target_file:
                    continue
                module_node_id = self.symbol_table.file_to_module_node.get(target_file)
                if not module_node_id:
                    continue
                edge = GraphEdge(
                    **{
                        "from": imported.node_id,
                        "to": module_node_id,
                        "type": EdgeType.IMPORTS
                    }
                )
                if edge.metadata is None:
                    edge.metadata = {}
                edge.metadata.update({
                    "source_file": imported.file_path,
                    "target_file": target_file,
                    "module": imported.source_module,
                    "cross_file_edge_type": "MODULE_REF"
                })
                self.cross_file_edges.append(edge)
    
    def _create_import_edge(
        self,
        imported: ImportedSymbol,
        exported: ExportedSymbol
    ):
        """Create IMPORT_CALL edge"""
        edge = GraphEdge(
            **{
                "from": imported.node_id,
                "to": exported.node_id,
                "type": EdgeType.IMPORTS
            }
        )
        if edge.metadata is None:
            edge.metadata = {}
        edge.metadata.update({
            "source_file": imported.file_path,
            "target_file": exported.file_path,
            "symbol_name": exported.name,
            "import_type": imported.import_type.value if hasattr(imported.import_type, 'value') else imported.import_type,
            "alias": imported.alias,
            "cross_file_edge_type": "IMPORT_CALL"
        })
        self.cross_file_edges.append(edge)
    
    def link_export_to_usages(self):
        """Create edges from exports to their usages in importing files"""
        # For each export, find all imports that reference it
        for module in self.symbol_table.modules.values():
            for exported in module.exports:
                # Find all imports that reference this export
                for importing_module in self.symbol_table.modules.values():
                    if importing_module.file_path == module.file_path:
                        continue  # Skip same file
                    
                    for imported in importing_module.imports:
                        # Check if this import references our export
                        if self._import_references_export(imported, exported, importing_module):
                            # Find usages of the imported symbol in the importing file
                            usages = self._find_symbol_usages(
                                imported,
                                importing_module.cpg
                            )
                            
                            for usage_node_id in usages:
                                self._create_export_ret_edge(
                                    exported,
                                    usage_node_id,
                                    importing_module.file_path
                                )
                                self._create_import_call_edge(
                                    exported,
                                    usage_node_id,
                                    importing_module.cpg
                                )
    
    def _import_references_export(
        self,
        imported: ImportedSymbol,
        exported: ExportedSymbol,
        importing_module: ModuleDefinition
    ) -> bool:
        """Check if import references this export"""
        # Resolve import to file
        target_file = self.symbol_table.resolve_import(
            importing_module.file_path,
            imported.source_module
        )
        
        if target_file != exported.file_path:
            return False
        
        # Check name match
        if imported.is_wildcard:
            return True
        if imported.name == "default" and exported.is_default:
            return True
        if imported.name == exported.name:
            return True
        
        return False
    
    def _find_symbol_usages(
        self,
        imported: ImportedSymbol,
        cpg: SemanticGraph
    ) -> List[str]:
        """Find all nodes that use the imported symbol"""
        usages = []
        
        # The symbol is used with its alias (if any) or original name
        symbol_name = imported.alias or imported.name
        
        for node in cpg.nodes:
            if node.type == NodeType.IDENTIFIER and node.name == symbol_name:
                # Skip the import statement itself
                if node.id != imported.node_id:
                    usages.append(node.id)
        
        return usages
    
    def _create_export_ret_edge(
        self,
        exported: ExportedSymbol,
        usage_node_id: str,
        usage_file: str
    ):
        """Create EXPORT_RET edge"""
        edge = GraphEdge(
            **{
                "from": exported.node_id,
                "to": usage_node_id,
                "type": EdgeType.DFG_FLOW
            }
        )
        if edge.metadata is None:
            edge.metadata = {}
        edge.metadata.update({
            "source_file": exported.file_path,
            "target_file": usage_file,
            "symbol_name": exported.name,
            "cross_file_edge_type": "EXPORT_RET"
        })
        self.cross_file_edges.append(edge)

    def _create_import_call_edge(
        self,
        exported: ExportedSymbol,
        usage_node_id: str,
        cpg: SemanticGraph
    ):
        """If imported identifier is used as callee, add CALL_GRAPH edge."""
        for edge in cpg.edges:
            if edge.to_node == usage_node_id and edge.type == EdgeType.AST_CHILD:
                parent = next((n for n in cpg.nodes if n.id == edge.from_node), None)
                if parent and parent.type == NodeType.CALL_EXPRESSION:
                    call_edge = GraphEdge(
                        **{
                            "from": parent.id,
                            "to": exported.node_id,
                            "type": EdgeType.CALL_GRAPH
                        }
                    )
                    if call_edge.metadata is None:
                        call_edge.metadata = {}
                    call_edge.metadata.update({
                        "source_file": parent.file,
                        "target_file": exported.file_path,
                        "symbol_name": exported.name,
                        "resolution": "imported_symbol"
                    })
                    self.cross_file_edges.append(call_edge)


class MultiFileRepositoryGraph:
    """
    Main class for multi-file repository analysis
    
    Orchestrates:
    1. Repository scanning
    2. Per-file CPG parsing
    3. Global symbol table construction
    4. Import/export resolution
    5. Cross-file edge linking
    6. Multi-file DFG construction
    """
    
    # Sets up scanner, symbol table, parser, cache, and shared node/edge lists
    def __init__(
        self,
        repo_path: str,
        exclude_patterns: Optional[List[str]] = None,
        allowed_files: Optional[set] = None,
    ):
        self.repo_path = repo_path
        self.allowed_files = allowed_files  # repo-relative paths (forward slashes)
        self.scanner = RepositoryScanner(repo_path, exclude_patterns)
        self.symbol_table = GlobalSymbolTable()
        self.cpg_parser = CPGParser()
        self.cache = GraphCache(repo_path)
        self._lock = Lock()
        
        # All CPGs combined
        self.all_nodes: List[GraphNode] = []
        self.all_edges: List[GraphEdge] = []
    
    def build(self) -> Dict[str, Any]:
        trace_step("Repo graph: MultiFileRepositoryGraph.build() (app/domain/analysis/multi_file_repo_graph.py)")
        """
        Build multi-file repository graph
        
        Returns:
            Dict with:
            - modules: List of ModuleDefinition
            - global_cpg: Combined CPG with cross-file edges
            - symbol_table: GlobalSymbolTable
            - statistics: Analysis stats
        """
        print(f"Scanning repository: {self.repo_path}")
        
        # Step 1: Scan repository
        trace_step("Repo graph step: scanner.scan() (RepositoryScanner)")
        source_files = self.scanner.scan()
        if self.allowed_files:
            repo_root = Path(self.repo_path).resolve()
            source_files = [
                f for f in source_files
                if str(f.resolve().relative_to(repo_root)).replace("\\", "/") in self.allowed_files
            ]
        code_files = [p for p in source_files if not self._is_html_file(p)]
        html_files = [p for p in source_files if self._is_html_file(p)]
        print(f"  Found {len(source_files)} source files")
        
        # Step 2: Parse each file
        trace_step("Repo graph step: parse files (ThreadPoolExecutor -> _parse_file)")
        print("\nParsing files...")
        max_workers = min(8, os.cpu_count() or 4)
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {
                executor.submit(self._parse_file, file_path): file_path
                for file_path in code_files
            }
            for i, future in enumerate(as_completed(futures), 1):
                file_path = futures[future]
                try:
                    future.result()
                except Exception as exc:
                    print(f"  [WARN] Failed parsing {file_path}: {exc}")
                if i % 10 == 0 or i == len(code_files):
                    print(f"  Progress: {i}/{len(code_files)} files")
        
        print(f"  Parsed {len(self.symbol_table.modules)} modules")

        # Step 2b: Expand re-exports (export * from 'module')
        self.symbol_table.expand_reexports()
        
        # Step 3: Link imports to exports
        trace_step("Repo graph step: CrossFileLinker.link_*()")
        print("\nLinking cross-file references...")
        linker = CrossFileLinker(self.symbol_table)
        linker.link_imports_to_exports()
        linker.link_export_to_usages()
        linker.link_module_refs()

        print(f"  Created {len(linker.cross_file_edges)} cross-file edges")
        
        # Step 4: Combine all edges
        self.all_edges.extend(linker.cross_file_edges)

        # Step 4b: Propagate cross-file DFG edges from import/export links
        self._propagate_cross_file_dfg(linker.cross_file_edges)
        
        # Step 5: Build global CPG
        global_cpg = SemanticGraph(
            nodes=self.all_nodes,
            edges=self.all_edges
        )

        # Step 5b: Link call graph across repository (name-based)
        self._link_call_graph(global_cpg)

        # Step 5b2: Propagate taint through cross-file function arguments
        self._propagate_cross_file_arg_taint(global_cpg)

        # Step 5c: Link route decorators to handlers and auth guards
        self._link_routes_and_guards(global_cpg)

        # Step 5d: Append CPG-style semantic edge families not owned by
        # import/export linking. This keeps the existing schema stable.
        global_cpg = SemanticGraphEnricher(global_cpg).enrich()
        self.all_edges = global_cpg.edges

        # Step 6: Parse HTML/templates and link to backend graph
        if html_files:
            print(f"\n[INFO] Parsing HTML/templates...")
            for html_path in html_files:
                try:
                    html_content = html_path.read_text(encoding="utf-8", errors="ignore")
                    cached_html = self.cache.get(html_path, html_content, "html")
                    if cached_html:
                        html_graph = cached_html
                    else:
                        html_graph = HTMLParser(str(html_path), html_content).parse()
                        self.cache.set(html_path, html_content, "html", html_graph)
                    self.all_nodes.extend(html_graph.nodes)
                    self.all_edges.extend(html_graph.edges)

                    linker = HTMLBackendLinker(
                        html_graph=html_graph,
                        backend_graph=global_cpg,
                        html_file=str(html_path),
                        backend_files=[m.file_path for m in self.symbol_table.modules.values()]
                    )
                    html_edges = linker.link()
                    self.all_edges.extend(html_edges)
                except Exception:
                    continue

            # Refresh global graph with HTML nodes/edges
            global_cpg = SemanticGraph(nodes=self.all_nodes, edges=self.all_edges)
            global_cpg = SemanticGraphEnricher(global_cpg).enrich()
            self.all_edges = global_cpg.edges
        
        stats = self._compute_statistics()
        
        print("\nRepository graph complete!")
        print(f"  Modules: {stats['total_modules']}")
        print(f"  Total nodes: {stats['total_nodes']}")
        print(f"  Total edges: {stats['total_edges']}")
        print(f"  Cross-file edges: {stats['cross_file_edges']}")
        print(f"  Exported symbols: {stats['total_exports']}")
        print(f"  Imported symbols: {stats['total_imports']}")
        
        return {
            "modules": list(self.symbol_table.modules.values()),
            "global_cpg": global_cpg,
            "symbol_table": self.symbol_table,
            "statistics": stats
        }
    
    def _parse_file(self, file_path: Path):
        trace_step(f"Repo graph: _parse_file({file_path}) (app/domain/analysis/multi_file_repo_graph.py)")
        """Parse a single file and add to global symbol table"""
        # Determine language
        language = self._detect_language(file_path)

        content = file_path.read_text(encoding="utf-8", errors="ignore")
        cached = self.cache.get(file_path, content, language)
        if cached:
            cpg = cached
        else:
            # Parse CPG
            parser = CPGParser()
            cpg = parser.parse_file(str(file_path), language)
            # Enrich with interprocedural DFG
            try:
                dfg_builder = InterproceduralDFG(cpg)
                cpg = dfg_builder.build()
            except Exception:
                # Keep base CPG if DFG enrichment fails
                pass
            # Ensure node IDs are unique across files
            self._namespace_graph_ids(cpg, file_path)
            self.cache.set(file_path, content, language, cpg)
        
        # Extract imports and exports
        resolver = ImportExportResolver(cpg, str(file_path), language)
        exports = resolver.extract_exports()
        imports = resolver.extract_imports()
        reexport_modules = resolver.get_reexport_modules()

        # Compute module name and node
        module_name = self._compute_module_name(file_path)
        module_node = self._create_module_node(file_path, module_name, language)
        
        # Create module definition
        module = ModuleDefinition(
            file_path=str(file_path),
            module_name=module_name,
            language=language,
            module_node_id=module_node.id,
            reexport_modules=reexport_modules,
            exports=exports,
            imports=imports,
            cpg=cpg
        )
        
        # Add to global symbol table and collections (thread-safe)
        with self._lock:
            self.symbol_table.add_module(module)
            self.all_nodes.append(module_node)
            self.all_nodes.extend(cpg.nodes)
            self.all_edges.extend(cpg.edges)

    def _create_module_node(self, file_path: Path, module_name: str, language: str) -> GraphNode:
        """Create a module node for a file."""
        node_id = f"module_{hashlib.sha1(str(file_path).encode('utf-8')).hexdigest()[:12]}"
        metadata = NodeMetadata(language=language)
        return GraphNode(
            id=node_id,
            type=NodeType.MODULE,
            name=module_name,
            value=str(file_path),
            file=str(file_path),
            line=1,
            column=1,
            metadata=metadata,
            source_code=None
        )

    def _namespace_graph_ids(self, cpg: SemanticGraph, file_path: Path) -> None:
        """Prefix node IDs with file hash to avoid collisions across modules."""
        prefix = hashlib.sha1(str(file_path).encode("utf-8")).hexdigest()[:8]
        id_map = {node.id: f"{prefix}_{node.id}" for node in cpg.nodes}

        for node in cpg.nodes:
            node.id = id_map.get(node.id, node.id)
            if node.metadata and getattr(node.metadata, "scope_id", None):
                scope_id = node.metadata.scope_id
                if scope_id in id_map:
                    node.metadata.scope_id = id_map[scope_id]

        for edge in cpg.edges:
            edge.from_node = id_map.get(edge.from_node, edge.from_node)
            edge.to_node = id_map.get(edge.to_node, edge.to_node)
    
    def _detect_language(self, file_path: Path) -> str:
        """Detect language from file extension"""
        ext = file_path.suffix.lower()
        if ext == '.py':
            return "python"
        elif ext in ('.js', '.jsx'):
            return "javascript"
        elif ext in ('.ts', '.tsx'):
            return "typescript"
        elif ext in ('.html', '.htm', '.jinja', '.j2', '.ejs', '.hbs', '.handlebars', '.mustache', '.pug'):
            return "html"
        return "unknown"

    def _is_html_file(self, file_path: Path) -> bool:
        """Return True if file is HTML/template."""
        return self._detect_language(file_path) == "html"
    
    def _compute_module_name(self, file_path: Path) -> str:
        """Compute module name from file path"""
        # Relative to repo root
        relative = file_path.relative_to(self.repo_path)
        
        # Remove extension
        module_path = str(relative.with_suffix(''))
        
        # Convert path separators to dots (Python) or keep as-is (JS)
        # For simplicity, use path notation
        return module_path.replace('\\', '/')
    
    def _compute_statistics(self) -> Dict[str, Any]:
        """Compute statistics about the repository graph"""
        total_exports = sum(
            len(m.exports)
            for m in self.symbol_table.modules.values()
        )
        
        total_imports = sum(
            len(m.imports)
            for m in self.symbol_table.modules.values()
        )
        
        cross_file_edges = sum(
            1 for e in self.all_edges
            if e.metadata and e.metadata.get("cross_file_edge_type") in [t.value for t in CrossFileEdgeType]
        )
        
        return {
            "total_modules": len(self.symbol_table.modules),
            "total_nodes": len(self.all_nodes),
            "total_edges": len(self.all_edges),
            "cross_file_edges": cross_file_edges,
            "total_exports": total_exports,
            "total_imports": total_imports,
            "python_modules": sum(
                1 for m in self.symbol_table.modules.values()
                if m.language == "python"
            ),
            "javascript_modules": sum(
                1 for m in self.symbol_table.modules.values()
                if m.language in ("javascript", "typescript")
            )
        }

    def _link_call_graph(self, graph: SemanticGraph):
        """Create CALL_GRAPH edges by name-based resolution across repo."""
        name_to_targets: Dict[str, List[str]] = {}
        for node in graph.nodes:
            if node.type in {NodeType.FUNCTION, NodeType.ASYNC_FUNCTION, NodeType.METHOD, NodeType.CLASS}:
                if node.name:
                    name_to_targets.setdefault(node.name, []).append(node.id)

        existing = {(e.from_node, e.to_node, e.type) for e in graph.edges}
        for node in graph.nodes:
            if node.type not in {NodeType.CALL_EXPRESSION, NodeType.EXTERNAL_CALL, NodeType.SYSTEM_CALL, NodeType.EVAL_CALL, NodeType.ORM_QUERY}:
                continue
            callee = node.name or ""
            if not callee:
                continue
            if "." in callee:
                callee = callee.split(".")[-1]
            targets = name_to_targets.get(callee, [])
            for target_id in targets:
                edge_key = (node.id, target_id, EdgeType.CALL_GRAPH)
                if edge_key in existing:
                    continue
                edge = GraphEdge(
                    **{
                        "from": node.id,
                        "to": target_id,
                        "type": EdgeType.CALL_GRAPH
                    }
                )
                edge.metadata = {"callee": callee, "resolution": "repo_symbol"}
                graph.edges.append(edge)
                self.all_edges.append(edge)
                existing.add(edge_key)

    def _propagate_cross_file_arg_taint(self, graph: SemanticGraph):
        """
        Create DFG_PARAM_PASS edges for cross-file function calls.

        _link_call_graph() already resolved CALL_EXPRESSION → FUNCTION edges
        by name across the repo.  We use those CALL_GRAPH edges to drive
        argument→parameter taint propagation: for each cross-file call, zip
        the argument nodes at the call site with the parameter nodes inside
        the callee function and emit DFG_PARAM_PASS edges so PathDiscovery
        can follow taint through cross-file function boundaries.

        Same-file arg→param edges were already created by the per-file
        InterproceduralDFG pass; we skip those here to avoid duplicates.
        """
        node_map: Dict[str, GraphNode] = {n.id: n for n in graph.nodes}

        _PARAM_TYPE = {NodeType.PARAMETER}
        _ARG_TYPES = {
            NodeType.EXPRESSION, NodeType.IDENTIFIER, NodeType.LITERAL,
            NodeType.MEMBER_ACCESS, NodeType.CALL_EXPRESSION,
            NodeType.FUNCTION, NodeType.ASYNC_FUNCTION,
            NodeType.ARROW_FUNCTION, NodeType.METHOD, NodeType.LAMBDA,
        }
        _CALLEE_TYPES = {NodeType.IDENTIFIER, NodeType.MEMBER_ACCESS}

        # ── 1. Build function → ordered param node IDs ────────────────────────
        func_params: Dict[str, List[str]] = {}
        for edge in graph.edges:
            if edge.type != EdgeType.AST_CHILD:
                continue
            child = node_map.get(edge.to_node)
            if child and child.type in _PARAM_TYPE:
                func_params.setdefault(edge.from_node, []).append(child.id)

        # ── 2. Build call → callee child (to exclude from arg list) ──────────
        call_callee_child: Dict[str, str] = {}
        for edge in graph.edges:
            if edge.type != EdgeType.AST_CHILD:
                continue
            parent = node_map.get(edge.from_node)
            if not parent or parent.type not in {NodeType.CALL_EXPRESSION, NodeType.EXTERNAL_CALL, NodeType.SYSTEM_CALL, NodeType.EVAL_CALL, NodeType.ORM_QUERY}:
                continue
            child = node_map.get(edge.to_node)
            if child and child.type in _CALLEE_TYPES:
                call_callee_child.setdefault(edge.from_node, child.id)

        # ── 3. Build call → ordered arg node IDs (excluding callee child) ────
        call_args: Dict[str, List[str]] = {}
        for edge in graph.edges:
            if edge.type != EdgeType.AST_CHILD:
                continue
            parent = node_map.get(edge.from_node)
            if not parent or parent.type not in {NodeType.CALL_EXPRESSION, NodeType.EXTERNAL_CALL, NodeType.SYSTEM_CALL, NodeType.EVAL_CALL, NodeType.ORM_QUERY}:
                continue
            child = node_map.get(edge.to_node)
            if not child:
                continue
            if call_callee_child.get(edge.from_node) == child.id:
                continue  # skip the callee identifier
            if child.type in _ARG_TYPES:
                call_args.setdefault(edge.from_node, []).append(child.id)

        # ── 4. Walk CALL_GRAPH edges → emit DFG_PARAM_PASS for cross-file ────
        existing = {(e.from_node, e.to_node, e.type) for e in graph.edges}
        new_edges: List[GraphEdge] = []

        for edge in graph.edges:
            if edge.type != EdgeType.CALL_GRAPH:
                continue
            call_id = edge.from_node
            func_id = edge.to_node

            args   = call_args.get(call_id, [])
            params = func_params.get(func_id, [])
            if not args or not params:
                continue

            call_node = node_map.get(call_id)
            func_node = node_map.get(func_id)

            # Skip same-file calls — per-file InterproceduralDFG already handled them
            if call_node and func_node and call_node.file == func_node.file:
                continue

            for i, (arg_id, param_id) in enumerate(zip(args, params)):
                key = (arg_id, param_id, EdgeType.DFG_PARAM_PASS)
                if key in existing:
                    continue
                dfg_edge = GraphEdge(
                    **{"from": arg_id, "to": param_id, "type": EdgeType.DFG_PARAM_PASS}
                )
                dfg_edge.metadata = {
                    "dfg_edge_type": DFGEdgeType.DFG_ARG_PASS.value,
                    "cross_file": True,
                    "arg_position": i,
                    "confidence": 0.9,
                    "callee": func_node.name if func_node else "",
                    "callee_file": func_node.file if func_node else "",
                }
                new_edges.append(dfg_edge)
                existing.add(key)

        if new_edges:
            graph.edges.extend(new_edges)
            self.all_edges.extend(new_edges)
            print(f"  [cross-file taint] Added {len(new_edges)} DFG_PARAM_PASS edges across file boundaries")

    def _propagate_cross_file_dfg(self, cross_edges: List[GraphEdge]):
        """Add DFG edges implied by cross-file import/export links."""
        new_edges: List[GraphEdge] = []
        identity_map: Dict[str, str] = {}
        module_ref_targets: Dict[str, str] = {}
        for edge in cross_edges:
            if not edge.metadata:
                continue
            edge_kind = edge.metadata.get("cross_file_edge_type")
            if edge.type == EdgeType.IMPORTS and edge_kind == "MODULE_REF":
                module_ref_targets[edge.from_node] = edge.to_node
                continue
            if edge.type == EdgeType.IMPORTS and edge_kind == "IMPORT_CALL":
                dfg_edge = GraphEdge(
                    **{
                        "from": edge.to_node,
                        "to": edge.from_node,
                        "type": EdgeType.DFG_FLOW
                    }
                )
                dfg_edge.metadata = {
                    "cross_file_edge_type": "IMPORT_CALL",
                    "dfg_edge_type": DFGEdgeType.DFG_IMPORT.value,
                    "confidence": 0.8
                }
                new_edges.append(dfg_edge)
                identity_map[edge.from_node] = edge.to_node
            elif edge.type == EdgeType.DFG_FLOW and edge_kind == "EXPORT_RET":
                if edge.metadata.get("dfg_edge_type") != DFGEdgeType.DFG_EXPORT.value:
                    edge.metadata["dfg_edge_type"] = DFGEdgeType.DFG_EXPORT.value

        # Connect import nodes to module nodes via DFG for coarse propagation
        for import_node_id, module_node_id in module_ref_targets.items():
            dfg_edge = GraphEdge(
                **{
                    "from": module_node_id,
                    "to": import_node_id,
                    "type": EdgeType.DFG_FLOW
                }
            )
            dfg_edge.metadata = {
                "cross_file_edge_type": "MODULE_REF",
                "dfg_edge_type": DFGEdgeType.DFG_IMPORT.value,
                "confidence": 0.5
            }
            new_edges.append(dfg_edge)

        # Lift DFG edges across import identity mapping
        if identity_map:
            existing = {(e.from_node, e.to_node, e.type) for e in self.all_edges}
            for edge in self.all_edges:
                if edge.type != EdgeType.DFG_FLOW:
                    continue
                if edge.from_node in identity_map:
                    mapped = identity_map[edge.from_node]
                    key = (mapped, edge.to_node, EdgeType.DFG_FLOW)
                    if key not in existing:
                        lifted = GraphEdge(
                            **{"from": mapped, "to": edge.to_node, "type": EdgeType.DFG_FLOW}
                        )
                        lifted.metadata = dict(edge.metadata or {})
                        lifted.metadata["cross_file_edge_type"] = "IMPORT_CALL"
                        lifted.metadata["dfg_edge_type"] = DFGEdgeType.DFG_IMPORT.value
                        lifted.metadata["confidence"] = min(1.0, (edge.metadata or {}).get("confidence", 0.8))
                        new_edges.append(lifted)
                        existing.add(key)
                if edge.to_node in identity_map:
                    mapped = identity_map[edge.to_node]
                    key = (edge.from_node, mapped, EdgeType.DFG_FLOW)
                    if key not in existing:
                        lifted = GraphEdge(
                            **{"from": edge.from_node, "to": mapped, "type": EdgeType.DFG_FLOW}
                        )
                        lifted.metadata = dict(edge.metadata or {})
                        lifted.metadata["cross_file_edge_type"] = "IMPORT_CALL"
                        lifted.metadata["dfg_edge_type"] = DFGEdgeType.DFG_IMPORT.value
                        lifted.metadata["confidence"] = min(1.0, (edge.metadata or {}).get("confidence", 0.8))
                        new_edges.append(lifted)
                        existing.add(key)
        if new_edges:
            self.all_edges.extend(new_edges)

    def _link_routes_and_guards(self, graph: SemanticGraph):
        """Link route decorators to handler functions and attach auth guards."""
        # Build mapping of function nodes by file + line for quick association
        func_nodes = [n for n in graph.nodes if n.type in {NodeType.FUNCTION, NodeType.ASYNC_FUNCTION, NodeType.METHOD}]
        for deco in [n for n in graph.nodes if n.type in {NodeType.ROUTE_DECORATOR, NodeType.AUTH_GUARD}]:
            # Find nearest function in same file with higher line number
            candidates = [f for f in func_nodes if f.file == deco.file and f.line >= deco.line]
            if not candidates:
                continue
            candidates.sort(key=lambda n: n.line)
            handler = candidates[0]
            edge_type = EdgeType.HTTP_ROUTE if deco.type == NodeType.ROUTE_DECORATOR else EdgeType.AUTH_COVERAGE
            edge = GraphEdge(
                **{
                    "from": deco.id,
                    "to": handler.id,
                    "type": edge_type
                }
            )
            edge.metadata = {
                "decorator": deco.source_code or deco.name,
                "source_file": deco.file,
                "target_file": handler.file
            }
            graph.edges.append(edge)
            self.all_edges.append(edge)
    
    def extract_cross_file_path(
        self,
        source_node_id: str,
        sink_node_id: str,
        max_depth: int = 20
    ) -> List[List[GraphEdge]]:
        """
        Extract data flow paths across files
        
        Args:
            source_node_id: Starting node
            sink_node_id: Target node
            max_depth: Maximum path length
        
        Returns:
            List of paths (each path is list of edges)
        """
        paths = []
        visited = set()
        
        def dfs(current: str, target: str, path: List[GraphEdge], depth: int):
            if depth > max_depth:
                return
            
            if current == target:
                paths.append(list(path))
                return
            
            if current in visited:
                return
            
            visited.add(current)
            
            # Follow all edges (including cross-file)
            for edge in self.all_edges:
                if edge.from_node == current:
                    path.append(edge)
                    dfs(edge.to_node, target, path, depth + 1)
                    path.pop()
            
            visited.remove(current)
        
        dfs(source_node_id, sink_node_id, [], 0)
        return paths
