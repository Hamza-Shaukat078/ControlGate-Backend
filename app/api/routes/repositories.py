from fastapi import APIRouter, Depends, UploadFile, File, HTTPException, status
from pathlib import Path
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_db, get_current_user
from app.schemas.repository import RepositoryCreate, RepositoryRead
from app.services.repository_service import RepositoryService, MAX_UPLOAD_SIZE
from app.core.config import settings


router = APIRouter(prefix="/repositories", tags=["repositories"])
service = RepositoryService()


@router.get("/", response_model=list[RepositoryRead])
async def list_repos(session: AsyncSession = Depends(get_db), user=Depends(get_current_user)):
    return await service.list_repos(session, user)


@router.post("/", response_model=RepositoryRead, status_code=201)
async def create_repo(payload: RepositoryCreate, session: AsyncSession = Depends(get_db), user=Depends(get_current_user)):
    try:
        return await service.create(session, payload.model_dump(), user)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@router.get("/{repo_id}", response_model=RepositoryRead)
async def get_repo(repo_id: int, session: AsyncSession = Depends(get_db), user=Depends(get_current_user)):
    return await service.get(session, repo_id, user)


@router.delete("/{repo_id}")
async def delete_repo(repo_id: int, session: AsyncSession = Depends(get_db), user=Depends(get_current_user)):
    await service.delete(session, repo_id, user)
    return {"ok": True}


@router.get("/{repo_id}/branches")
async def branches(repo_id: int, session: AsyncSession = Depends(get_db), user=Depends(get_current_user)):
    try:
        return {"branches": await service.branches(session, repo_id, user)}
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@router.get("/{repo_id}/files")
async def list_files(
    repo_id: int,
    branch: str = "main",
    session: AsyncSession = Depends(get_db),
    user=Depends(get_current_user),
):
    try:
        files = await service.list_files(session, repo_id, branch, user)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    return {"files": files}


@router.post("/{repo_id}/upload")
async def upload(
    repo_id: int,
    file: UploadFile = File(...),
    user=Depends(get_current_user),
    session: AsyncSession = Depends(get_db),
):
    await service.get(session, repo_id, user)
    # Size check after write
    if file.content_type not in ("application/zip", "application/gzip", "application/x-zip-compressed", "application/x-tar"):
        raise HTTPException(status_code=422, detail="Unsupported archive format")

    repo_dir = Path(settings.REPO_STORAGE_DIR) / str(repo_id)
    repo_dir.mkdir(parents=True, exist_ok=True)
    filename = Path(file.filename or "upload").name
    if not filename.lower().endswith((".zip", ".tar", ".tar.gz", ".tgz")):
        raise HTTPException(status_code=422, detail="Unsupported archive extension")
    dest_path = repo_dir / filename
    size = 0
    with dest_path.open("wb") as f:
        while True:
            chunk = await file.read(1024 * 1024)
            if not chunk:
                break
            size += len(chunk)
            if size > MAX_UPLOAD_SIZE:
                dest_path.unlink(missing_ok=True)
                raise HTTPException(status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, detail="File too large")
            f.write(chunk)

    return {"filename": filename, "size": size, "status": "RECEIVED"}
