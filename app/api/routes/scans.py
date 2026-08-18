from fastapi import APIRouter, Depends, HTTPException, WebSocket, WebSocketDisconnect, Query
from motor.motor_asyncio import AsyncIOMotorDatabase
from sqlalchemy.ext.asyncio import AsyncSession
from app.api.deps import get_current_user
from app.db.mongo import get_mongo_db
from app.api.deps import get_db
from app.enums.role import UserRole
from app.schemas.scan import (
    ScanStart, ScanResponse, ScanStatusRead, ScanSummary,
    ProbeDiscoveryRequest, ProbeDiscoveryResponse, IdorCandidateRead, MassAssignmentCandidateRead,
)
from app.services.scan_service import ScanService
from app.services.repository_service import RepositoryService
from app.core.permissions import can_access_resource, check_scan_quota
from app.core.exceptions import AuthorizationException, ResourceNotFoundException
from datetime import datetime, timezone
from app.core.trace import trace_step
from app.core.crypto import decrypt_secret
from app.core.network import validate_public_git_url, validate_public_http_url
from app.domain.analysis.dast.config import ActorConfig, AuthMode, DynamicScanConfig, FormLoginConfig, OAuth2Config
from app.domain.analysis.dast.session import DastSessionPair
from app.domain.analysis.dast.probe_discovery import discover_probe_candidates
import asyncio
import logging
import shutil
import tempfile
from pathlib import Path
from typing import Optional
from urllib.parse import urlsplit

logger = logging.getLogger(__name__)


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
      {type:"status", state, progress, eta, current_file, files_scanned,
              total_files, current_dynamic_action, dynamic_findings_count}
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
                "current_file": scan.get("current_file"),
                "files_scanned": scan.get("files_scanned", 0),
                "total_files": scan.get("total_files", 0),
                # Dynamic/DAST phase telemetry — see ScanStatusRead docstring
                # in schemas/scan.py for why this exists alongside current_file.
                "current_dynamic_action": scan.get("current_dynamic_action"),
                "dynamic_findings_count": scan.get("dynamic_findings_count", 0),
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
        for extra_url in (payload.dynamic_additional_target_urls or []):
            validate_public_http_url(extra_url, allow_http=True)

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
            dynamic_additional_target_urls=payload.dynamic_additional_target_urls,
            dynamic_auth_mode=payload.dynamic_auth_mode.value,
            dynamic_bearer_token=payload.dynamic_bearer_token,
            dynamic_form_login=payload.dynamic_form_login.model_dump() if payload.dynamic_form_login else None,
            dynamic_oauth2=payload.dynamic_oauth2.model_dump() if payload.dynamic_oauth2 else None,
            dynamic_api_key_header=payload.dynamic_api_key_header,
            dynamic_api_key_value=payload.dynamic_api_key_value,
            dynamic_active_mode=payload.dynamic_active_mode,
            dynamic_second_actor_auth_mode=payload.dynamic_second_actor_auth_mode.value,
            dynamic_second_actor_bearer_token=payload.dynamic_second_actor_bearer_token,
            dynamic_second_actor_form_login=(
                payload.dynamic_second_actor_form_login.model_dump()
                if payload.dynamic_second_actor_form_login else None
            ),
            dynamic_second_actor_oauth2=(
                payload.dynamic_second_actor_oauth2.model_dump()
                if payload.dynamic_second_actor_oauth2 else None
            ),
            dynamic_second_actor_api_key_header=payload.dynamic_second_actor_api_key_header,
            dynamic_second_actor_api_key_value=payload.dynamic_second_actor_api_key_value,
            dynamic_scenarios=(
                [s.model_dump() for s in payload.dynamic_scenarios] if payload.dynamic_scenarios else None
            ),
            dynamic_race_probes=(
                [p.model_dump() for p in payload.dynamic_race_probes] if payload.dynamic_race_probes else None
            ),
            dynamic_idor_probes=(
                [p.model_dump() for p in payload.dynamic_idor_probes] if payload.dynamic_idor_probes else None
            ),
            dynamic_mass_assignment_probes=(
                [p.model_dump() for p in payload.dynamic_mass_assignment_probes]
                if payload.dynamic_mass_assignment_probes else None
            ),
            dynamic_timing_probes=(
                [p.model_dump() for p in payload.dynamic_timing_probes]
                if payload.dynamic_timing_probes else None
            ),
            dynamic_signaling_fuzz_probes=(
                [p.model_dump() for p in payload.dynamic_signaling_fuzz_probes]
                if payload.dynamic_signaling_fuzz_probes else None
            ),
            dynamic_media_flood_probes=(
                [p.model_dump() for p in payload.dynamic_media_flood_probes]
                if payload.dynamic_media_flood_probes else None
            ),
            dynamic_malformed_packet_probes=(
                [p.model_dump() for p in payload.dynamic_malformed_packet_probes]
                if payload.dynamic_malformed_packet_probes else None
            ),
            dynamic_srtp_auth_probes=(
                [p.model_dump() for p in payload.dynamic_srtp_auth_probes]
                if payload.dynamic_srtp_auth_probes else None
            ),
            dynamic_crawl_max_pages=payload.dynamic_crawl_max_pages,
            dynamic_crawl_max_depth=payload.dynamic_crawl_max_depth,
            dynamic_state_crawl_max_forms=payload.dynamic_state_crawl_max_forms,
            dynamic_state_crawl_max_depth=payload.dynamic_state_crawl_max_depth,
            dynamic_rule_ids=payload.dynamic_rule_ids,
            dynamic_ssrf_collaborator_host=payload.dynamic_ssrf_collaborator_host,
            dynamic_ssrf_collaborator_port=payload.dynamic_ssrf_collaborator_port,
            dynamic_openapi_spec_url=payload.dynamic_openapi_spec_url,
            dynamic_openapi_spec=payload.dynamic_openapi_spec,
            dynamic_use_headless_browser=payload.dynamic_use_headless_browser,
            enable_llm=payload.enable_llm,
        )
        
        return ScanResponse(
            scan_id=scan_id,
            user_id=user["id"],
            status="PENDING",
            message="Scan initiated successfully",
            input_type=input_type,
            created_at=datetime.now(timezone.utc).replace(tzinfo=None).isoformat()
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


def _build_probe_discovery_actor(
    auth_mode: AuthMode,
    bearer_token,
    form_login,
    oauth2,
    api_key_header,
    api_key_value,
) -> ActorConfig:
    actor = ActorConfig(auth_mode=auth_mode)
    if auth_mode == AuthMode.BEARER:
        actor.bearer_token = bearer_token
    elif auth_mode == AuthMode.FORM_LOGIN and form_login:
        actor.form_login = FormLoginConfig(**form_login.model_dump())
    elif auth_mode == AuthMode.OAUTH2 and oauth2:
        actor.oauth2 = OAuth2Config(**oauth2.model_dump())
    elif auth_mode == AuthMode.API_KEY:
        actor.api_key_header = api_key_header
        actor.api_key_value = api_key_value
    return actor


@router.post("/discover-probes", response_model=ProbeDiscoveryResponse)
async def discover_probes(
    payload: ProbeDiscoveryRequest,
    user=Depends(get_current_user),
    db: AsyncIOMotorDatabase = Depends(get_mongo_db),
    session: AsyncSession = Depends(get_db),
):
    trace_step("API endpoint: POST /scans/discover-probes (app/api/routes/scans.py)")
    """
    Track: probe auto-discovery — GET-only sweep across the given targets,
    authenticated as the primary (and, if configured, second) actor, looking
    for JSON "list of resources I own" endpoints to pre-fill IDOR/mass-
    assignment probe candidates. Never runs a probe itself; the GUI shows
    what comes back for review before any actual scan uses it.

    When repo_id is set, briefly clones the repo (same as a real scan) to
    pull in its real route definitions via bridge.py's source-route
    discovery — the only way a pure-JSON API (a bare origin GET finds
    nothing; there's no HTML to crawl, no OpenAPI spec published) surfaces
    its actual resource-list endpoints (/orders, /products, ...) instead of
    every target contributing zero candidates.

    Accessible to: All authenticated users (no scan quota consumed — this
    doesn't create a scan record, just a handful of GET requests plus an
    optional throwaway clone).
    """
    for url in payload.target_urls:
        validate_public_http_url(url, allow_http=True)

    sweep_urls = list(payload.target_urls)
    temp_dir: Optional[Path] = None
    if payload.repo_id:
        try:
            repo_service = RepositoryService()
            repo = await repo_service.get(session, payload.repo_id, user)
            repo_token = decrypt_secret(repo.access_token) if repo.access_token else None
            temp_dir = Path(tempfile.mkdtemp(prefix="controlgate-probe-discovery-"))
            repo_root = temp_dir / "repo"
            scan_service = ScanService(db)
            await asyncio.to_thread(scan_service._clone_repo, repo.url, payload.repo_branch, repo_token, repo_root)

            from app.domain.analysis.dast.bridge import discover_routes_from_source

            for base_url in payload.target_urls:
                parts = urlsplit(base_url)
                origin = f"{parts.scheme}://{parts.netloc}"
                try:
                    endpoints = discover_routes_from_source(repo_root, origin)
                except Exception as exc:
                    logger.warning(f"Source-route discovery failed for {origin}: {exc}")
                    continue
                sweep_urls.extend(e.url for e in endpoints if e.method == "GET" and e.url not in sweep_urls)
        except (AuthorizationException, ResourceNotFoundException) as e:
            raise e.to_http_exception()
        except Exception as exc:
            logger.warning(f"repo_id={payload.repo_id} clone/route-discovery failed (non-blocking): {exc}")
        finally:
            if temp_dir is not None:
                shutil.rmtree(temp_dir, ignore_errors=True)

    try:
        actor = _build_probe_discovery_actor(
            payload.dynamic_auth_mode, payload.dynamic_bearer_token, payload.dynamic_form_login,
            payload.dynamic_oauth2, payload.dynamic_api_key_header, payload.dynamic_api_key_value,
        )
        second_actor = None
        if payload.dynamic_second_actor_auth_mode != AuthMode.NONE:
            second_actor = _build_probe_discovery_actor(
                payload.dynamic_second_actor_auth_mode, payload.dynamic_second_actor_bearer_token,
                payload.dynamic_second_actor_form_login, payload.dynamic_second_actor_oauth2,
                payload.dynamic_second_actor_api_key_header, payload.dynamic_second_actor_api_key_value,
            )
        # target_url is required by DynamicScanConfig's dataclass shape but
        # unused here — discover_probe_candidates takes the full sweep_urls
        # list directly, this pair is just for auth/session management.
        config = DynamicScanConfig(target_url=payload.target_urls[0], actor=actor, second_actor=second_actor)
        async with DastSessionPair(config) as pair:
            result = await discover_probe_candidates(
                pair.primary, sweep_urls, second_actor_session=pair.secondary,
            )
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Probe discovery failed: {str(e)}")

    return ProbeDiscoveryResponse(
        idor_candidates=[IdorCandidateRead(**vars(c)) for c in result.idor_candidates],
        mass_assignment_candidates=[MassAssignmentCandidateRead(**vars(c)) for c in result.mass_assignment_candidates],
        notes=result.notes,
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

