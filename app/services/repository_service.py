import os
import shutil
import subprocess
import tarfile
import tempfile
import zipfile
from pathlib import Path

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from fastapi import HTTPException, status
from app.models.repository import Repository
from app.core.config import settings


MAX_UPLOAD_SIZE = 200 * 1024 * 1024  # 200MB


class RepositoryService:
    def _detect_language(self, path: Path) -> str | None:
        ext = path.suffix.lower()
        return {
            ".py": "python",
            ".js": "javascript",
            ".ts": "typescript",
            ".tsx": "typescript",
            ".jsx": "javascript",
            ".java": "java",
            ".php": "php",
            ".rb": "ruby",
            ".go": "go",
            ".cs": "csharp",
        }.get(ext)

    def _collect_source_files(self, root: Path) -> list[Path]:
        files = []
        for path in root.rglob("*"):
            if path.is_file() and self._detect_language(path):
                files.append(path)
        return files

    def _extract_archive(self, archive_path: Path, dest_dir: Path) -> None:
        if archive_path.suffix == ".zip":
            with zipfile.ZipFile(archive_path, "r") as zf:
                zf.extractall(dest_dir)
            return
        if archive_path.suffix in (".gz", ".tgz") or archive_path.name.endswith(".tar.gz"):
            with tarfile.open(archive_path, "r:gz") as tf:
                tf.extractall(dest_dir)
            return
        if archive_path.suffix == ".tar":
            with tarfile.open(archive_path, "r:") as tf:
                tf.extractall(dest_dir)
            return
        raise ValueError("Unsupported archive format")

    def _clone_repo(self, url: str, branch: str, token: str | None, dest_dir: Path) -> None:
        clone_url = url
        if token and url.startswith("https://"):
            clone_url = url.replace("https://", f"https://{token}@", 1)
        env = os.environ.copy()
        env["GIT_TERMINAL_PROMPT"] = "0"

        # Try the requested branch, then fall back to main/master automatically
        fallback = "master" if branch == "main" else "main"
        for attempt_branch in [branch, fallback]:
            result = subprocess.run(
                ["git", "clone", "--depth", "1", "--branch", attempt_branch, clone_url, str(dest_dir)],
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            if result.returncode == 0:
                return
            # Clean up partial clone before retrying (use rmdir /s /q on Windows to avoid lock issues)
            if dest_dir.exists():
                try:
                    shutil.rmtree(dest_dir, ignore_errors=False)
                except Exception:
                    subprocess.run(
                        ["cmd", "/c", "rmdir", "/s", "/q", str(dest_dir)],
                        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                    )

        raise subprocess.CalledProcessError(result.returncode, result.args, result.stderr)

    async def list_repos(self, session: AsyncSession) -> list[Repository]:
        result = await session.execute(select(Repository))
        return list(result.scalars().all())

    async def create(self, session: AsyncSession, data: dict) -> Repository:
        repo = Repository(
            name=data.get("name"),
            provider=data.get("provider"),
            url=data.get("url"),
            access_token=(data.get("token") or None),
            status=data.get("status") or "CONNECTED",
        )
        session.add(repo)
        await session.commit()
        await session.refresh(repo)
        return repo

    async def get(self, session: AsyncSession, repo_id: int) -> Repository:
        repo = await session.get(Repository, repo_id)
        if not repo:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Repository not found")
        return repo

    async def delete(self, session: AsyncSession, repo_id: int) -> None:
        repo = await self.get(session, repo_id)
        await session.delete(repo)
        await session.commit()

    async def branches(self, session: AsyncSession, repo_id: int) -> list[str]:
        repo = await self.get(session, repo_id)
        if repo.url:
            try:
                result = subprocess.run(
                    ["git", "ls-remote", "--heads", repo.url],
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10,
                    env={**os.environ, "GIT_TERMINAL_PROMPT": "0"},
                )
                if result.returncode == 0:
                    branches = []
                    for line in result.stdout.decode(errors="replace").splitlines():
                        if "\trefs/heads/" in line:
                            branches.append(line.split("\trefs/heads/")[-1].strip())
                    if branches:
                        return branches
            except Exception:
                pass
        return ["main", "master", "develop"]

    async def list_files(self, session: AsyncSession, repo_id: int, branch: str) -> list[str]:
        repo = await self.get(session, repo_id)
        temp_root = None
        try:
            temp_root = Path(tempfile.mkdtemp(prefix="vulcan-repo-list-"))
            repo_root = temp_root / "repo"

            if repo.provider == "LOCAL":
                upload_dir = Path(settings.REPO_STORAGE_DIR) / str(repo_id)
                if not upload_dir.exists():
                    raise HTTPException(status_code=404, detail="No uploaded archive found for this repository")
                archives = list(upload_dir.glob("*"))
                if not archives:
                    raise HTTPException(status_code=404, detail="No uploaded archive found for this repository")
                archive_path = max(archives, key=lambda p: p.stat().st_mtime)
                self._extract_archive(archive_path, repo_root)
            elif repo.url:
                self._clone_repo(repo.url, branch, repo.access_token, repo_root)
            else:
                raise HTTPException(status_code=400, detail="Repository URL is missing")

            files = self._collect_source_files(repo_root)
            rel_paths = [
                str(path.relative_to(repo_root)).replace("\\", "/")
                for path in files
            ]
            rel_paths.sort()
            return rel_paths
        finally:
            if temp_root:
                shutil.rmtree(temp_root, ignore_errors=True)
