# CPG Parser Setup Instructions

## Issue: Tree-sitter Grammar Compilation

The CPG parser requires compiled Tree-sitter grammars for JavaScript and TypeScript. On Windows, this requires **Microsoft Visual C++ Build Tools**.

## Solution Options

### Option 1: Install Visual Studio Build Tools (Recommended for Development)

1. Download and install **Microsoft C++ Build Tools**:
   - Visit: https://visualstudio.microsoft.com/visual-cpp-build-tools/
   - Or install Visual Studio Community with "Desktop development with C++" workload

2. After installation, run:
   ```powershell
   python setup_grammars.py
   ```

3. Test the parser:
   ```powershell
   python examples/cpg_examples.py
   ```

### Option 2: Use Pre-Built Binaries (Quick Start)

If you don't want to install build tools, you can use pre-built grammar files:

1. Download pre-built grammars from a colleague or CI/CD artifacts

2. Place them in the `build/` directory:
   ```
   build/
   ├── javascript.dll
   └── typescript.dll
   ```

3. Test the parser:
   ```powershell
   python examples/cpg_examples.py
   ```

### Option 3: Use Docker (Alternative)

If you have Docker installed, you can build in a container:

```powershell
docker run -it -v ${PWD}:/workspace python:3.12 bash
cd /workspace
pip install tree-sitter==0.21.3
python setup_grammars.py
```

Then copy the built `.so` files to your Windows `build/` directory and rename them to `.dll`.

## Current Status

Your environment has:
- ✅ Python 3.12
- ✅ tree-sitter 0.21.3
- ✅ setuptools
- ❌ C++ compiler (needed for building grammars)

## Quick Test Without Setup

If you want to test the rest of the codebase without the CPG parser, you can:

1. Comment out the CPG parser import in your code
2. Use the existing AST parser temporarily
3. Come back to CPG parser setup later

## Support

For issues or questions:
- Check [CPG_PARSER_GUIDE.md](Document-MarkDowns/CPG_PARSER_GUIDE.md)
- Review [CPG_QUICK_START.md](Document-MarkDowns/CPG_QUICK_START.md)

---

**Note**: The CPG parser is production-ready once grammars are built. The compilation step is a one-time setup requirement.
