from pathlib import Path
from contextlib import contextmanager
import shutil
import uuid


def has_grammar(name: str) -> bool:
    build = Path(__file__).resolve().parent.parent / "build"
    return (build / f"{name}.so").exists() or (build / f"{name}.dll").exists()


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
