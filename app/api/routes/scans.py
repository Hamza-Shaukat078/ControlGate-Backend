from fastapi import APIRouter, Depends, HTTPException, WebSocket, WebSocketDisconnect, Query
from motor.motor_asyncio import AsyncIOMotorDatabase
from sqlalchemy.ext.asyncio import AsyncSession
from app.api.deps import get_current_user
from app.db.mongo import get_mongo_db
from app.api.deps import get_db
from app.enums.role import UserRole
from app.schemas.scan import ScanStart, ScanResponse, ScanStatusRead, ScanSummary
from app.services.scan_service import ScanService
from app.services.repository_service import RepositoryService
from app.core.permissions import can_access_resource, check_scan_quota
from app.core.exceptions import AuthorizationException, ResourceNotFoundException
from datetime import datetime
from app.core.trace import trace_step
from app.core.crypto import decrypt_secret
from app.core.network import validate_public_git_url, validate_public_http_url
import asyncio


router = APIRouter(prefix="/scans", tags=["scans"])

_TERMINAL = {"COMPLETED", "FAILED", "CANCELLED"}


@router.websocket("/ws/{scan_id}")
async def scan_ws(
    scan_id: str,
    websocket: WebSocket,
    token: str = Query(None),
):
    """Stream scan progress + logs over WebSocket.

    Connect: ws://<host>/api/v1/scans/ws/<scan_id>?token=<jwt>
    Messages sent (JSON):
      {type:"status", state, progress, eta}
      {type:"logs",   lines:[...]}
      {type:"done",   state, summary?}
      {type:"error",  message}
    """
    from app.core.security import decode_token
    from app.db.mongo import get_mongo_database, to_object_id
    from app.enums.role import UserRole

    if not token:
        await websocket.close(code=4001)
        return
    try:
        payload = decode_token(token)
        user_id = str(payload.get("sub", ""))
    except Exception:
        await websocket.close(code=4001)
        return

    db = get_mongo_database()
    jti = payload.get("jti")
    if jti and await db.token_revocations.find_one({"jti": jti}):
        await websocket.close(code=4001)
        return
    user_oid = to_object_id(user_id)
    user_doc = await db.users.find_one({"_id": user_oid}) if user_oid else None
    if not user_doc or not user_doc.get("is_active", True):
        await websocket.close(code=4001)
        return

    scan = await db.scans.find_one({"scan_id": scan_id})
    if not scan:
        await websocket.close(code=4004)
        return
    if user_doc.get("role") != UserRole.ADMIN.value and str(scan.get("user_id")) != user_id:
        await websocket.close(code=4003)
        return

    await websocket.accept()

    last_log_count = 0
    try:
        while True:
            scan = await db.scans.find_one({"scan_id": scan_id})
            if not scan:
                await websocket.send_json({"type": "error", "message": "Scan not found"})
                break

            state    = scan.get("state", "UNKNOWN")
            progress = scan.get("progress", 0)
            await websocket.send_json({
                "type": "status",
                "state": state,
                "progress": progress,
                "eta": scan.get("eta", ""),
            })

            logs     = scan.get("logs", [])
            new_logs = logs[last_log_count:]
            if new_logs:
                await websocket.send_json({"type": "logs", "lines": new_logs})
                last_log_count = len(logs)

            if state in _TERMINAL:
                payload_out: dict = {"type": "done", "state": state}
                if state == "COMPLETED":
                    payload_out["summary"] = scan.get("summary", {})
                await websocket.send_json(payload_out)
                break

            await asyncio.sleep(0.5)
    except WebSocketDisconnect:
        pass
    except Exception:
        pass


@router.post("/start", status_code=202, response_model=ScanResponse)
async def start_scan(
    payload: ScanStart,
    user=Depends(get_current_user),
    db: AsyncIOMotorDatabase = Depends(get_mongo_db),
    session: AsyncSession = Depends(get_db),
):
    trace_step("API endpoint: POST /scans/start (app/api/routes/scans.py)")
    """
    Start a vulnerability scan with dual input modes.
    
    **Direct Code Scan:**
    - Provide `code`, `language`, and optionally `filename`
    - Code limited to 400 lines
    - Immediate analysis of provided code
    
    **Repository Scan:**
    - Provide `repo_id` and `branch`
    - Scans all .py/.js/.ts files in repository
    - Processes files one by one
    
    Returns scan_id for polling progress.
    
    Accessible to: All authenticated users (admin, premium, normal)
    """
    try:
        # Enforce monthly scan quota before starting (C1-C5)
        await check_scan_quota(user, db)
        if payload.target_url:
            validate_public_http_url(payload.target_url, allow_http=True)

        service = ScanService(db)
        repo_url = None
        repo_provider = None
        repo_token = None
        if payload.repo_id:
            trace_step("Scan input mode: REPOSITORY (repo_id provided)")
            repo_service = RepositoryService()
            repo = await repo_service.get(session, payload.repo_id, user)
            repo_url = repo.url
            repo_provider = repo.provider
            repo_token = decrypt_secret(repo.access_token)
        else:
            trace_step("Scan input mode: DIRECT_CODE (no repo_id)")

        scan_id, input_type = await service.start(
            user_id=user["id"],
            code=payload.code,
            language=payload.language.value if payload.language else None,
            filename=payload.filename,
            repo_id=payload.repo_id,
            branch=payload.branch,
            scan_mode=payload.scan_mode.value,
            scan_type=payload.scan_type.value,
            repo_url=repo_url,
            repo_provider=repo_provider,
            repo_token=repo_token,
            file_paths=payload.file_paths,
            target_url=payload.target_url,
            dynamic_auth_mode=payload.dynamic_auth_mode.value,
            dynamic_bearer_token=payload.dynamic_bearer_token,
            dynamic_form_login=payload.dynamic_form_login.model_dump() if payload.dynamic_form_login else None,
            dynamic_active_mode=payload.dynamic_active_mode,
            dynamic_second_actor_auth_mode=payload.dynamic_second_actor_auth_mode.value,
            dynamic_second_actor_bearer_token=payload.dynamic_second_actor_bearer_token,
            dynamic_second_actor_form_login=(
                payload.dynamic_second_actor_form_login.model_dump()
                if payload.dynamic_second_actor_form_login else None
            ),
            dynamic_scenarios=(
                [s.model_dump() for s in payload.dynamic_scenarios] if payload.dynamic_scenarios else None
            ),
            dynamic_race_probes=(
                [p.model_dump() for p in payload.dynamic_race_probes] if payload.dynamic_race_probes else None
            ),
            dynamic_idor_probes=(
                [p.model_dump() for p in payload.dynamic_idor_probes] if payload.dynamic_idor_probes else None
            ),
            dynamic_crawl_max_pages=payload.dynamic_crawl_max_pages,
            dynamic_crawl_max_depth=payload.dynamic_crawl_max_depth,
            dynamic_rule_ids=payload.dynamic_rule_ids,
        )
        
        return ScanResponse(
            scan_id=scan_id,
            user_id=user["id"],
            status="PENDING",
            message="Scan initiated successfully",
            input_type=input_type,
            created_at=datetime.utcnow().isoformat()
        )
    except HTTPException:
        raise
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e))
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to start scan: {str(e)}"
        )


@router.get("/diff-files")
async def get_diff_files(
    repo_id: int,
    base: str = "main",
    head: str = "HEAD",
    user=Depends(get_current_user),
    db: AsyncIOMotorDatabase = Depends(get_mongo_db),
    session: AsyncSession = Depends(get_db),
):
    """
    Return list of source files changed between two git refs.
    Use these as file_paths in a diff-based scan (much faster than full scan).
    """
    import subprocess, tempfile, shutil
    from pathlib import Path
    from app.services.repository_service import RepositoryService

    repo_svc = RepositoryService()
    repo = await repo_svc.get(session, repo_id, user)
    if not repo or not repo.url:
        raise HTTPException(status_code=404, detail="Repository not found or has no URL")
    try:
        validate_public_git_url(repo.url)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))

    tmp = Path(tempfile.mkdtemp(prefix="vulcan-diff-"))
    try:
        # Shallow clone to get diff
        clone_url = repo.url
        token = decrypt_secret(repo.access_token)
        if token and clone_url.startswith("https://"):
            clone_url = clone_url.replace("https://", f"https://{token}@", 1)

        subprocess.run(
            ["git", "clone", "--depth", "50", clone_url, str(tmp / "repo")],
            check=True, capture_output=True, timeout=60
        )
        repo_dir = tmp / "repo"
        result = subprocess.run(
            ["git", "diff", "--name-only", f"{base}...{head}"],
            cwd=str(repo_dir), capture_output=True, text=True, timeout=30
        )
        all_changed = [f.strip() for f in result.stdout.splitlines() if f.strip()]

        # Filter to source files only
        source_exts = {".py", ".js", ".ts", ".tsx", ".jsx"}
        changed = [f for f in all_changed if Path(f).suffix.lower() in source_exts]

        return {"base": base, "head": head, "changed_files": changed, "total": len(changed)}
    except subprocess.CalledProcessError as exc:
        raise HTTPException(status_code=400, detail=f"Git operation failed: {exc.stderr.decode()[:200]}")
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


@router.get("/{scan_id}/status", response_model=ScanStatusRead)
async def scan_status(
    scan_id: str,
    user=Depends(get_current_user),
    db: AsyncIOMotorDatabase = Depends(get_mongo_db),
):
    trace_step("API endpoint: GET /scans/{scan_id}/status (app/api/routes/scans.py)")
    """
    Get current scan status with progress information.
    
    Returns:
    - state: PENDING, RUNNING, COMPLETED, FAILED, CANCELLED
    - progress: 0-100
    - current_file: Currently scanning file (for repo scans)
    - files_scanned/total_files: File progress counters
    
    Accessible to: Scan owner or Admin
    """
    try:
        scan = await db.scans.find_one({"scan_id": scan_id})
        if not scan:
            raise ResourceNotFoundException(f"Scan {scan_id} not found")
        
        # Check ownership: allow if user is admin or owns the scan
        if not can_access_resource(user, str(scan.get("user_id"))):
            raise AuthorizationException(f"Not authorized to access scan {scan_id}")
        
        service = ScanService(db)
        status = await service.status(scan_id)
        
        if status.state == "NOT_FOUND":
            raise ResourceNotFoundException(f"Scan {scan_id} not found")
        
        # Ensure user_id is included in response
        status_dict = status.dict() if hasattr(status, 'dict') else status
        status_dict['user_id'] = str(scan.get("user_id"))
        return ScanStatusRead(**status_dict)
    except (ResourceNotFoundException, AuthorizationException) as e:
        raise e.to_http_exception()
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get scan status: {str(e)}")


@router.get("/{scan_id}/logs")
async def scan_logs(
    scan_id: str,
    user=Depends(get_current_user),
    db: AsyncIOMotorDatabase = Depends(get_mongo_db),
):
    trace_step("API endpoint: GET /scans/{scan_id}/logs (app/api/routes/scans.py)")
    """
    Get real-time scan logs.
    Returns last 100 log entries.
    
    Accessible to: Scan owner or Admin
    """
    try:
        scan = await db.scans.find_one({"scan_id": scan_id})
        if not scan:
            raise ResourceNotFoundException(f"Scan {scan_id} not found")
        
        if not can_access_resource(user, str(scan.get("user_id"))):
            raise AuthorizationException(f"Not authorized to access scan {scan_id}")
        
        service = ScanService(db)
        return await service.logs(scan_id)
    except (ResourceNotFoundException, AuthorizationException) as e:
        raise e.to_http_exception()
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get scan logs: {str(e)}")


@router.get("/{scan_id}/summary", response_model=ScanSummary)
async def scan_summary(
    scan_id: str,
    user=Depends(get_current_user),
    db: AsyncIOMotorDatabase = Depends(get_mongo_db),
):
    trace_step("API endpoint: GET /scans/{scan_id}/summary (app/api/routes/scans.py)")
    """
    Get final scan summary with vulnerability results.
    
    Available after scan completes.
    Includes:
    - Total files scanned
    - Vulnerabilities found
    - Severity breakdown
    - Full vulnerability details
    
    Accessible to: Scan owner or Admin
    """
    try:
        scan = await db.scans.find_one({"scan_id": scan_id})
        if not scan:
            raise ResourceNotFoundException(f"Scan {scan_id} not found")
        
        if not can_access_resource(user, str(scan.get("user_id"))):
            raise AuthorizationException(f"Not authorized to access scan {scan_id}")
        
        service = ScanService(db)
        summary = await service.summary(scan_id)
        
        if not summary:
            raise ResourceNotFoundException(f"Scan {scan_id} not found or not completed")
        
        # Ensure user_id is included in response
        summary_dict = summary.dict() if hasattr(summary, 'dict') else summary
        summary_dict['user_id'] = str(scan.get("user_id"))
        return ScanSummary(**summary_dict)
    except (ResourceNotFoundException, AuthorizationException) as e:
        raise e.to_http_exception()
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get scan summary: {str(e)}")


@router.post("/{scan_id}/cancel")
async def cancel_scan(
    scan_id: str,
    user=Depends(get_current_user),
    db: AsyncIOMotorDatabase = Depends(get_mongo_db),
):
    trace_step("API endpoint: POST /scans/{scan_id}/cancel (app/api/routes/scans.py)")
    """
    Cancel a running scan.
    
    Accessible to: Scan owner or Admin
    """
    try:
        scan = await db.scans.find_one({"scan_id": scan_id})
        if not scan:
            raise ResourceNotFoundException(f"Scan {scan_id} not found")
        
        if not can_access_resource(user, str(scan.get("user_id"))):
            raise AuthorizationException(f"Not authorized to cancel scan {scan_id}")
        
        service = ScanService(db)
        result = await service.cancel(scan_id)
        
        if result.get("state") == "NOT_FOUND":
            raise ResourceNotFoundException(f"Scan {scan_id} not found")
        
        return {"scan_id": scan_id, "status": "CANCELLED"}
    except (ResourceNotFoundException, AuthorizationException) as e:
        raise e.to_http_exception()
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to cancel scan: {str(e)}")


@router.get("/")
async def list_scans(
    user=Depends(get_current_user),
    db: AsyncIOMotorDatabase = Depends(get_mongo_db),
):
    trace_step("API endpoint: GET /scans/ (app/api/routes/scans.py)")
    """
    List scans visible to the current user.

    Accessible to: All authenticated users — normal/premium users see only
    their own scans, admins see every scan.
    """
    service = ScanService(db)
    return await service.list_scans(user)


@router.delete("/{scan_id}")
async def delete_scan(
    scan_id: str,
    user=Depends(get_current_user),
    db: AsyncIOMotorDatabase = Depends(get_mongo_db),
):
    trace_step("API endpoint: DELETE /scans/{scan_id} (app/api/routes/scans.py)")
    """
    Delete a scan and its stored results.

    Accessible to: Scan owner or Admin
    """
    try:
        scan = await db.scans.find_one({"scan_id": scan_id})
        if not scan:
            raise ResourceNotFoundException(f"Scan {scan_id} not found")

        if not can_access_resource(user, str(scan.get("user_id"))):
            raise AuthorizationException(f"Not authorized to delete scan {scan_id}")

        service = ScanService(db)
        await service.delete(scan_id)
        return {"scan_id": scan_id, "status": "DELETED"}
    except (ResourceNotFoundException, AuthorizationException) as e:
        raise e.to_http_exception()
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to delete scan: {str(e)}")

