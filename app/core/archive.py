import stat
import tarfile
import zipfile
from pathlib import Path


MAX_ARCHIVE_MEMBERS = 10_000
MAX_EXTRACTED_SIZE = 500 * 1024 * 1024


def _safe_destination(dest_dir: Path, member_name: str) -> Path:
    if not member_name or "\x00" in member_name:
        raise ValueError("Archive contains an invalid member name")
    member_path = Path(member_name)
    if member_path.is_absolute() or member_path.drive:
        raise ValueError("Archive contains an absolute member path")

    dest_root = dest_dir.resolve()
    target = (dest_root / member_path).resolve()
    if target != dest_root and dest_root not in target.parents:
        raise ValueError("Archive member escapes extraction directory")
    return target


def _is_zip_symlink(info: zipfile.ZipInfo) -> bool:
    mode = (info.external_attr >> 16) & 0o777777
    return stat.S_IFMT(mode) == stat.S_IFLNK


_COPY_CHUNK_SIZE = 1024 * 1024


def _copy_within_budget(src, target: Path, budget_remaining: int) -> int:
    """
    Copies src -> target in chunks, enforcing the size cap against bytes
    actually written rather than any archive-declared size metadata.

    A ZIP entry's `file_size` field is attacker-controlled and decoupled from
    what its DEFLATE stream actually decompresses to — CRC-32 verification
    (enforced by zipfile itself) catches a corrupted stream, but not one
    that's honest about its own checksum while lying about the separate
    `file_size` field. A crafted archive can therefore declare a tiny size
    while its real decompressed output is enormous; a check performed only
    against declared size, before copying, never sees that. Counting actual
    bytes as they're written closes that gap regardless of what any member's
    metadata claims. Deletes the partial file and raises on overflow.
    """
    written = 0
    with target.open("wb") as dst:
        try:
            while True:
                chunk = src.read(_COPY_CHUNK_SIZE)
                if not chunk:
                    break
                written += len(chunk)
                if written > budget_remaining:
                    raise ValueError("Archive expands beyond the allowed size")
                dst.write(chunk)
        except BaseException:
            dst.close()
            target.unlink(missing_ok=True)
            raise
    return written


def _extract_zip(archive_path: Path, dest_dir: Path) -> None:
    total_size = 0
    with zipfile.ZipFile(archive_path, "r") as zf:
        infos = zf.infolist()
        if len(infos) > MAX_ARCHIVE_MEMBERS:
            raise ValueError("Archive contains too many members")
        for info in infos:
            if _is_zip_symlink(info):
                raise ValueError("Archive contains symbolic links")
            target = _safe_destination(dest_dir, info.filename)
            if info.is_dir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            with zf.open(info, "r") as src:
                total_size += _copy_within_budget(src, target, MAX_EXTRACTED_SIZE - total_size)


def _extract_tar(archive_path: Path, dest_dir: Path, mode: str) -> None:
    total_size = 0
    with tarfile.open(archive_path, mode) as tf:
        members = tf.getmembers()
        if len(members) > MAX_ARCHIVE_MEMBERS:
            raise ValueError("Archive contains too many members")
        for member in members:
            if member.issym() or member.islnk() or member.isdev():
                raise ValueError("Archive contains links or device files")
            target = _safe_destination(dest_dir, member.name)
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            if not member.isfile():
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            src = tf.extractfile(member)
            if src is None:
                continue
            with src:
                total_size += _copy_within_budget(src, target, MAX_EXTRACTED_SIZE - total_size)


def safe_extract_archive(archive_path: Path, dest_dir: Path) -> None:
    dest_dir.mkdir(parents=True, exist_ok=True)
    name = archive_path.name.lower()
    if archive_path.suffix.lower() == ".zip":
        _extract_zip(archive_path, dest_dir)
        return
    if name.endswith(".tar.gz") or archive_path.suffix.lower() in (".gz", ".tgz"):
        _extract_tar(archive_path, dest_dir, "r:gz")
        return
    if archive_path.suffix.lower() == ".tar":
        _extract_tar(archive_path, dest_dir, "r:")
        return
    raise ValueError("Unsupported archive format")
