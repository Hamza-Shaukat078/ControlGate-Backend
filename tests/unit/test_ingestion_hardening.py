import socket
import tarfile
import tempfile
import zipfile
from pathlib import Path

import pytest

import app.core.archive as archive_module
from app.core.archive import _copy_within_budget, safe_extract_archive
from app.core.network import validate_public_git_url, validate_public_http_url


def test_public_url_validation_rejects_loopback_ip():
    with pytest.raises(ValueError):
        validate_public_http_url("http://127.0.0.1:8000", resolve=False)


def test_public_url_validation_rejects_localhost_name():
    with pytest.raises(ValueError):
        validate_public_http_url("https://localhost", resolve=False)


def test_public_git_url_requires_https():
    with pytest.raises(ValueError):
        validate_public_git_url("git://github.com/example/repo.git")


def test_public_url_validation_rejects_private_dns(monkeypatch):
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda *a, **kw: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.5", 443))],
    )
    with pytest.raises(ValueError):
        validate_public_http_url("https://example.internal")


def test_safe_zip_extraction_rejects_zip_slip():
    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp)
        archive = root / "bad.zip"
        with zipfile.ZipFile(archive, "w") as zf:
            zf.writestr("../escape.txt", "owned")

        with pytest.raises(ValueError):
            safe_extract_archive(archive, root / "out")
        assert not (root / "escape.txt").exists()


def test_safe_tar_extraction_rejects_symlink():
    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp)
        archive = root / "bad.tar"
        with tarfile.open(archive, "w") as tf:
            info = tarfile.TarInfo("link")
            info.type = tarfile.SYMTYPE
            info.linkname = "../escape.txt"
            tf.addfile(info)

        with pytest.raises(ValueError):
            safe_extract_archive(archive, root / "out")


# ── Regression: size cap must bound actual bytes written, not declared metadata ──
# A ZIP entry's file_size field is attacker-controlled and independent of what its
# DEFLATE stream actually decompresses to (zipfile's own CRC-32 check only proves
# the decompressed bytes match the entry's *own* checksum — not that they match
# the *declared size*). The old code summed info.file_size before calling
# shutil.copyfileobj, so a crafted archive that under-declares its size while
# genuinely containing more data would sail past the pre-check and then write an
# unbounded amount to disk. _copy_within_budget fixes this by never looking at
# declared size at all — it only ever sees a byte stream and counts what it
# actually writes, so there's no metadata field left for an attacker to lie about.

class _UnboundedStream:
    """A read() source that keeps yielding data far past any 'declared size' —
    stands in for a maliciously crafted decompression stream without needing to
    hand-forge a byte-exact malicious zip/tar file."""

    def __init__(self, total_bytes: int, chunk: bytes = b"A" * 4096):
        self._remaining = total_bytes
        self._chunk = chunk

    def read(self, n=-1):
        if self._remaining <= 0:
            return b""
        take = min(len(self._chunk), self._remaining)
        self._remaining -= take
        return self._chunk[:take]


def test_copy_within_budget_ignores_any_notion_of_declared_size():
    # _copy_within_budget's signature never takes a "declared size" argument at
    # all — it can only ever act on bytes actually read from the stream. This
    # directly proves the fix's core property: there is no metadata field left
    # for a crafted archive to lie through.
    with tempfile.TemporaryDirectory() as temp:
        target = Path(temp) / "out.bin"
        src = _UnboundedStream(total_bytes=10 * 1024 * 1024)  # "lies" would be irrelevant here
        with pytest.raises(ValueError, match="expands beyond the allowed size"):
            _copy_within_budget(src, target, budget_remaining=1024)
        assert not target.exists(), "partial output must be cleaned up on overflow"


def test_copy_within_budget_allows_content_within_budget():
    with tempfile.TemporaryDirectory() as temp:
        target = Path(temp) / "out.bin"
        src = _UnboundedStream(total_bytes=2048)
        written = _copy_within_budget(src, target, budget_remaining=4096)
        assert written == 2048
        assert target.read_bytes() == b"A" * 2048


def test_safe_zip_extraction_enforces_size_cap_on_real_content(monkeypatch):
    # End-to-end through safe_extract_archive with a real (honestly-labeled) zip,
    # confirming the cap still works for the ordinary case with the actual
    # extraction code path — not just the isolated _copy_within_budget unit.
    monkeypatch.setattr(archive_module, "MAX_EXTRACTED_SIZE", 1024)
    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp)
        archive = root / "big.zip"
        with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("data.bin", b"A" * (64 * 1024))

        out = root / "out"
        with pytest.raises(ValueError, match="expands beyond the allowed size"):
            safe_extract_archive(archive, out)
        assert not (out / "data.bin").exists()
