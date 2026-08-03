from functools import lru_cache
from pathlib import Path
from contextlib import contextmanager
import shutil
import uuid


@lru_cache(maxsize=1)
def _loaded_grammar_languages() -> frozenset:
    # CPGParser (used by MultiFileRepositoryGraph, the thing these tests actually
    # exercise) loads grammars via tree_sitter_languages / the per-language pip
    # packages, not from a locally-compiled build/*.so — that build/ layout is a
    # leftover from setup_grammars.py's tree-sitter<0.22 Language.build_library
    # workflow and nothing populates it anymore. Ask CPGParser what it actually
    # managed to load instead of checking a directory that's permanently empty.
    from app.domain.analysis.cpg_parser import CPGParser

    try:
        parser = CPGParser()
    except Exception:
        return frozenset()
    return frozenset(lang.value for lang in parser.languages.keys())


def has_grammar(name: str) -> bool:
    return name in _loaded_grammar_languages()


@contextmanager
def temporary_repo_dir():
    """
    Create a writable temporary directory under the repo (not the OS temp dir).

    The sandboxed environment used for automated runs can deny writes to the
    system temp path, so tests should use this helper when creating temp repos.
    """
    # Use a dedicated folder that pytest will not recurse into.
    root = Path(__file__).resolve().parent / ".tmp_work"
    root.mkdir(parents=True, exist_ok=True)

    # tempfile.TemporaryDirectory can create dirs that become unwritable in some
    # sandboxed Windows environments. Use a normal mkdir instead.
    tmpdir = root / f"repo_{uuid.uuid4().hex}"
    tmpdir.mkdir(parents=True, exist_ok=False)
    try:
        yield tmpdir
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)
