## graphify

This project has a graphify knowledge graph at graphify-out/.

Rules:
- **At the start of every session**, run `graphify . --update` to sync the graph with latest code before doing any work
- Before answering architecture or codebase questions, read graphify-out/GRAPH_REPORT.md for god nodes and community structure
- If graphify-out/wiki/index.md exists, navigate it instead of reading raw files
- After modifying code files, run `graphify . --update` again to keep the graph current (AST-only for code changes, no API cost)
- A git post-commit hook is installed — graph auto-rebuilds after every commit
