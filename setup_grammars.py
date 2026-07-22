"""
Tree-sitter Grammar Setup Script

This script downloads and compiles tree-sitter grammars for supported languages.
Run this once after installing tree-sitter to set up language support.

Usage:
    python setup_grammars.py

Supported Languages:
    - Python
    - JavaScript
    - TypeScript
    - HTML
    - JSON
    - YAML
"""

import os
import sys
import subprocess
from pathlib import Path
import shutil
import logging

logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
logger = logging.getLogger(__name__)


# Language repository URLs with specific versions for compatibility with tree-sitter 0.21.3
LANGUAGE_REPOS = {
    "python": "https://github.com/tree-sitter/tree-sitter-python",
    # JavaScript v0.20.4 (compatible with tree-sitter 0.21.3, language version 14)
    "javascript": ("https://github.com/tree-sitter/tree-sitter-javascript", "v0.20.4"),
    "typescript": ("https://github.com/tree-sitter/tree-sitter-typescript", None),
    "html": ("https://github.com/tree-sitter/tree-sitter-html", None),
    "json": ("https://github.com/tree-sitter/tree-sitter-json", None),
    "yaml": ("https://github.com/tree-sitter-grammars/tree-sitter-yaml", None),
}


def check_requirements():
    """Check if required tools are installed"""
    try:
        import tree_sitter
        logger.info("✓ tree-sitter Python package is installed")
    except ImportError:
        logger.error("✗ tree-sitter not found")
        logger.error("Install with: pip install tree-sitter")
        return False
    
    # Check for git
    try:
        subprocess.run(["git", "--version"], capture_output=True, check=True)
        logger.info("✓ git is installed")
    except (subprocess.CalledProcessError, FileNotFoundError):
        logger.error("✗ git not found")
        logger.error("Install git from: https://git-scm.com/downloads")
        return False
    
    # Check for C compiler
    try:
        if sys.platform == "win32":
            # Check for MSVC or MinGW
            subprocess.run(["cl.exe"], capture_output=True)
            logger.info("✓ C compiler (MSVC) is available")
        else:
            subprocess.run(["gcc", "--version"], capture_output=True, check=True)
            logger.info("✓ C compiler (gcc) is available")
    except (subprocess.CalledProcessError, FileNotFoundError):
        logger.warning("⚠ C compiler not found")
        logger.warning("You may need to install:")
        if sys.platform == "win32":
            logger.warning("  - Visual Studio Build Tools")
            logger.warning("  - Or MinGW-w64")
        else:
            logger.warning("  - gcc (Linux: sudo apt install build-essential)")
            logger.warning("  - Xcode Command Line Tools (macOS: xcode-select --install)")
    
    return True


def clone_repos(base_dir: Path):
    """Clone all language repositories"""
    base_dir.mkdir(exist_ok=True)
    
    for lang, repo_info in LANGUAGE_REPOS.items():
        lang_dir = base_dir / f"tree-sitter-{lang}"
        
        if lang_dir.exists():
            logger.info(f"Repository for {lang} already exists, skipping clone")
            continue
        
        logger.info(f"Cloning {lang} grammar...")
        try:
            # Handle tuple format (url, tag) or string format (url)
            if isinstance(repo_info, tuple):
                repo_url, tag = repo_info
            else:
                repo_url = repo_info
                tag = None
            
            if tag:
                # Clone with specific tag/branch
                subprocess.run(
                    ["git", "clone", "--depth", "1", "--branch", tag, repo_url, str(lang_dir)],
                    check=True,
                    capture_output=True
                )
            else:
                subprocess.run(
                    ["git", "clone", "--depth", "1", repo_url, str(lang_dir)],
                    check=True,
                    capture_output=True
                )
            logger.info(f"✓ Cloned {lang} successfully")
        except subprocess.CalledProcessError as e:
            logger.error(f"✗ Failed to clone {lang}: {e}")
            return False
    
    return True


def build_grammars(base_dir: Path, output_dir: Path):
    """Build language grammars using tree-sitter"""
    from tree_sitter import Language
    
    output_dir.mkdir(exist_ok=True)
    
    # Special handling for TypeScript (has two grammars)
    typescript_dir = base_dir / "tree-sitter-typescript"
    
    for lang in LANGUAGE_REPOS.keys():
        logger.info(f"Building {lang} grammar...")
        
        try:
            if lang == "typescript":
                # TypeScript has typescript and tsx subdirectories
                ts_path = typescript_dir / "typescript"
                tsx_path = typescript_dir / "tsx"
                
                if ts_path.exists():
                    Language.build_library(
                        str(output_dir / "typescript.so"),
                        [str(ts_path)]
                    )
                    logger.info(f"✓ Built {lang} grammar successfully")
                else:
                    logger.error(f"✗ TypeScript source not found at {ts_path}")
                    continue
            else:
                lang_dir = base_dir / f"tree-sitter-{lang}"
                
                if not lang_dir.exists():
                    logger.error(f"✗ Directory not found: {lang_dir}")
                    continue
                
                # Build the language
                Language.build_library(
                    str(output_dir / f"{lang}.so"),
                    [str(lang_dir)]
                )
                logger.info(f"✓ Built {lang} grammar successfully")
                
        except Exception as e:
            logger.error(f"✗ Failed to build {lang}: {e}")
            logger.error(f"  Check that {lang} repository was cloned correctly")
            continue


def verify_build(output_dir: Path):
    """Verify that all grammar files were created (.so or .dll)."""
    logger.info("\nVerifying build...")
    
    expected_files = [
        "python",
        "javascript",
        "typescript",
        "html",
        "json",
        "yaml",
    ]
    
    all_ok = True
    for name in expected_files:
        so_path = output_dir / f"{name}.so"
        dll_path = output_dir / f"{name}.dll"
        if so_path.exists() or dll_path.exists():
            path = so_path if so_path.exists() else dll_path
            size = path.stat().st_size
            logger.info(f"??? {path.name} ({size:,} bytes)")
        else:
            logger.error(f"??? {name}.so/.dll not found")
            all_ok = False
    
    return all_ok


def main():
    """Main setup function"""
    logger.info("=== Tree-sitter Grammar Setup ===\n")
    
    # Check requirements
    logger.info("Checking requirements...")
    if not check_requirements():
        logger.error("\nSetup cannot continue. Please install missing requirements.")
        return 1
    
    # Set up directories
    project_root = Path(__file__).parent
    repos_dir = project_root / "tree-sitter-repos"
    build_dir = project_root / "build"
    
    logger.info(f"\nRepositories will be cloned to: {repos_dir}")
    logger.info(f"Grammars will be built to: {build_dir}\n")
    
    # Clone repositories
    logger.info("=== Cloning Language Repositories ===")
    if not clone_repos(repos_dir):
        logger.error("Failed to clone repositories")
        return 1
    
    # Build grammars
    logger.info("\n=== Building Language Grammars ===")
    build_grammars(repos_dir, build_dir)
    
    # Verify
    logger.info("\n=== Verification ===")
    if verify_build(build_dir):
        logger.info("\n✓ All grammars built successfully!")
        logger.info(f"\nGrammar files are in: {build_dir}")
        logger.info("You can now use UniversalParser!")
        return 0
    else:
        logger.warning("\n⚠ Some grammars failed to build")
        logger.warning("UniversalParser will work with available grammars")
        return 0


if __name__ == "__main__":
    sys.exit(main())
