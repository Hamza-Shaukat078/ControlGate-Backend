import re
import uuid
from datetime import datetime, timezone
from pathlib import Path

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile
from motor.motor_asyncio import AsyncIOMotorDatabase

from app.api.deps import get_current_user
from app.core.config import settings
from app.core.permissions import can_access_resource
from app.db.mongo import get_mongo_db
from app.schemas.asvs import AttestationSubmit
from app.services.asvs_service import ASVSService

router = APIRouter(prefix="/attestations", tags=["attestations"])
MAX_EVIDENCE_BYTES = 10 * 1024 * 1024


def _safe_control_id(control_id: str) -> str:
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", control_id):
        raise HTTPException(status_code=422, detail="Invalid control_id")
    return control_id


def _safe_scan_id(scan_id: str) -> str:
    if not re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", scan_id):
        raise HTTPException(status_code=422, detail="Invalid scan_id")
    return scan_id


def _require_proof(payload: AttestationSubmit) -> None:
    if payload.answer.value == "not_tested":
        raise HTTPException(status_code=422, detail="Cannot submit not_tested as an attestation answer")
    if not (payload.evidence_url or (payload.evidence_notes or "").strip()):
        raise HTTPException(status_code=422, detail="Attestation requires proof: upload evidence or provide evidence notes")


async def _get_authorized_scan(scan_id: str, user: dict, db: AsyncIOMotorDatabase) -> dict:
    scan_id = _safe_scan_id(scan_id)
    scan = await db.scans.find_one({"scan_id": scan_id})
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if not can_access_resource(user, str(scan.get("user_id"))):
        raise HTTPException(status_code=403, detail="Not authorized to access this scan")
    return scan


async def _store_evidence_file(evidence_dir: Path, control_id: str, file: UploadFile, url_prefix: str) -> dict:
    control_id = _safe_control_id(control_id)
    evidence_dir.mkdir(parents=True, exist_ok=True)

    safe_name = f"{uuid.uuid4().hex[:8]}_{Path(file.filename or 'evidence').name}"
    dest = evidence_dir / safe_name
    try:
        size = 0
        with dest.open("wb") as fh:
            while True:
                chunk = await file.read(1024 * 1024)
                if not chunk:
                    break
                size += len(chunk)
                if size > MAX_EVIDENCE_BYTES:
                    dest.unlink(missing_ok=True)
                    raise HTTPException(status_code=413, detail="Evidence file too large")
                fh.write(chunk)
    except Exception as exc:
        if isinstance(exc, HTTPException):
            raise
        raise HTTPException(status_code=500, detail=f"Failed to store evidence file: {exc}")

    return {"evidence_url": f"{url_prefix}/{control_id}/evidence/{safe_name}"}


@router.get("")
async def list_attestations(
    scan_id: str | None = None,
    user=Depends(get_current_user),
    db: AsyncIOMotorDatabase = Depends(get_mongo_db),
):
    """
    Current attestations keyed by control_id. Supply scan_id for scan-scoped
    answers; new attestation writes require scan_id.
    """
    query = {"user_id": user.get("id")}
    if scan_id:
        await _get_authorized_scan(scan_id, user, db)
        query["scan_id"] = _safe_scan_id(scan_id)

    result = {}
    async for doc in db.attestations.find(query, {"_id": 0}):
        result[doc["control_id"]] = doc
    return result


@router.get("/scan/{scan_id}")
async def list_scan_attestation_tasks(
    scan_id: str,
    user=Depends(get_current_user),
    db: AsyncIOMotorDatabase = Depends(get_mongo_db),
):
    """Manual attestation work queue for one scan, with process and current answers."""
    scan_id = _safe_scan_id(scan_id)
    await _get_authorized_scan(scan_id, user, db)
    return await ASVSService(db).list_manual_attestation_tasks(scan_id, user=user)


@router.post("")
async def submit_attestation(
    payload: AttestationSubmit,
    user=Depends(get_current_user),
    db: AsyncIOMotorDatabase = Depends(get_mongo_db),
):
    """
    Upsert one scan-scoped attestation answer. Proof is mandatory: either an
    uploaded evidence URL or reviewer evidence notes.
    """
    if not payload.scan_id:
        raise HTTPException(status_code=422, detail="scan_id is required so attestation is tied to one scan")
    scan_id = _safe_scan_id(payload.scan_id)
    await _get_authorized_scan(scan_id, user, db)
    _safe_control_id(payload.control_id)
    _require_proof(payload)

    record = {
        "user_id": user.get("id"),
        "scan_id": scan_id,
        "control_id": payload.control_id,
        "answer": payload.answer.value,
        "evidence_url": payload.evidence_url,
        "evidence_notes": (payload.evidence_notes or "").strip() or None,
        "proof_type": payload.proof_type.value if payload.proof_type else None,
        "attested_by": user.get("full_name") or user.get("email") or user.get("id"),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    await db.attestations.update_one(
        {"user_id": user.get("id"), "scan_id": scan_id, "control_id": payload.control_id},
        {"$set": record},
        upsert=True,
    )
    await ASVSService(db).build_results_for_scan(scan_id, user=user)
    return record


@router.post("/scan/{scan_id}")
async def submit_scan_attestation(
    scan_id: str,
    payload: AttestationSubmit,
    user=Depends(get_current_user),
    db: AsyncIOMotorDatabase = Depends(get_mongo_db),
):
    """Submit one control attestation for a specific scan."""
    payload.scan_id = _safe_scan_id(scan_id)
    return await submit_attestation(payload, user=user, db=db)


@router.post("/scan/{scan_id}/{control_id}/evidence")
async def upload_scan_evidence(
    scan_id: str,
    control_id: str,
    file: UploadFile = File(...),
    user=Depends(get_current_user),
    db: AsyncIOMotorDatabase = Depends(get_mongo_db),
):
    """Store an evidence file tied to one scan/control attestation."""
    scan_id = _safe_scan_id(scan_id)
    control_id = _safe_control_id(control_id)
    await _get_authorized_scan(scan_id, user, db)
    evidence_dir = Path(settings.ATTESTATION_EVIDENCE_DIR) / str(user.get("id")) / scan_id / control_id
    return await _store_evidence_file(evidence_dir, control_id, file, f"/attestations/scan/{scan_id}")
