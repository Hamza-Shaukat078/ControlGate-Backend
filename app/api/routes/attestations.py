import uuid
import re
from datetime import datetime, timezone
from pathlib import Path

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile
from motor.motor_asyncio import AsyncIOMotorDatabase

from app.api.deps import get_current_user
from app.core.config import settings
from app.db.mongo import get_mongo_db
from app.schemas.asvs import AttestationSubmit

router = APIRouter(prefix="/attestations", tags=["attestations"])
MAX_EVIDENCE_BYTES = 10 * 1024 * 1024


def _safe_control_id(control_id: str) -> str:
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", control_id):
        raise HTTPException(status_code=422, detail="Invalid control_id")
    return control_id


@router.get("")
async def list_attestations(
    user=Depends(get_current_user),
    db: AsyncIOMotorDatabase = Depends(get_mongo_db),
):
    """
    All current attestations, keyed by control_id (matches the frontend's
    localStorage fallback shape exactly — one current answer per control).
    """
    result = {}
    async for doc in db.attestations.find({"user_id": user.get("id")}, {"_id": 0}):
        result[doc["control_id"]] = doc
    return result


@router.post("")
async def submit_attestation(
    payload: AttestationSubmit,
    user=Depends(get_current_user),
    db: AsyncIOMotorDatabase = Depends(get_mongo_db),
):
    """
    Upsert the current attestation answer for one control. `control_id` is
    carried in the body (matches the frontend's attestationService.submit
    payload shape) rather than the URL.
    """
    record = {
        "user_id": user.get("id"),
        "control_id": payload.control_id,
        "answer": payload.answer.value,
        "evidence_url": payload.evidence_url,
        "attested_by": user.get("full_name") or user.get("email") or user.get("id"),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    await db.attestations.update_one(
        {"user_id": user.get("id"), "control_id": payload.control_id},
        {"$set": record},
        upsert=True,
    )
    return record


@router.post("/{control_id}/evidence")
async def upload_evidence(
    control_id: str,
    file: UploadFile = File(...),
    user=Depends(get_current_user),
    db: AsyncIOMotorDatabase = Depends(get_mongo_db),
):
    """Store an evidence file for a control's attestation and return its reference URL."""
    control_id = _safe_control_id(control_id)
    evidence_dir = Path(settings.ATTESTATION_EVIDENCE_DIR) / str(user.get("id")) / control_id
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

    evidence_url = f"/attestations/{control_id}/evidence/{safe_name}"
    return {"evidence_url": evidence_url}
