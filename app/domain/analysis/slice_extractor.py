from typing import List
from app.schemas.graph import GraphNode


class SliceExtractor:
    """
    Extracts code slices from a graph path.
    Converts a sequence of nodes back into readable source code.
    """
    
    def extract(self, nodes: List[GraphNode], original_code: str) -> str:
        """
        Extract code snippet from node path.
        
        Args:
            nodes: List of nodes in the taint path
            original_code: Original source code
        
        Returns:
            Code snippet showing the taint flow
        """
        if not nodes:
            return ""
        
        # Group nodes by file
        files = {}
        for node in nodes:
            if node.file not in files:
                files[node.file] = []
            files[node.file].append(node)
        
        snippets = []
        
        for filename, file_nodes in files.items():
            # Get line range
            lines = sorted(set(n.line for n in file_nodes if n.line > 0))
            
            if not lines:
                continue
            
            # Extract relevant lines from source
            source_lines = original_code.splitlines()
            min_line = max(1, min(lines) - 1)  # Add context
            max_line = min(len(source_lines), max(lines) + 1)
            
            snippet_lines = []
            for i in range(min_line - 1, max_line):
                line_num = i + 1
                prefix = ">>> " if line_num in lines else "    "
                snippet_lines.append(f"{prefix}{line_num:4d} | {source_lines[i]}")
            
            snippets.append(f"File: {filename}\n" + "\n".join(snippet_lines))
        
        return "\n\n".join(snippets)
    
    # Return source lines surrounding a single node, marking its line with a ">>>" prefix.
    def extract_context(self, node: GraphNode, original_code: str, context_lines: int = 3) -> str:
        """
        Extract code around a specific node with context.
        """
        source_lines = original_code.splitlines()
        
        if node.line <= 0 or node.line > len(source_lines):
            return ""
        
        start = max(0, node.line - context_lines - 1)
        end = min(len(source_lines), node.line + context_lines)
        
        lines = []
        for i in range(start, end):
            line_num = i + 1
            prefix = ">>> " if line_num == node.line else "    "
            lines.append(f"{prefix}{line_num:4d} | {source_lines[i]}")
        
        return "\n".join(lines)
