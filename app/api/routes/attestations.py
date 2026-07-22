import uuid
from datetime import datetime, timezone
from pathlib import Path

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile
from motor.motor_asyncio import AsyncIOMotorDatabase

from app.api.deps import get_current_user
from app.core.config import settings
from app.db.mongo import get_mongo_db
from app.schemas.asvs import AttestationSubmit

router = APIRouter(prefix="/attestations", tags=["attestations"])


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
    async for doc in db.attestations.find({}, {"_id": 0}):
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
        "control_id": payload.control_id,
        "answer": payload.answer.value,
        "evidence_url": payload.evidence_url,
        "attested_by": user.get("full_name") or user.get("email") or user.get("id"),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    await db.attestations.update_one(
        {"control_id": payload.control_id},
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
    evidence_dir = Path(settings.ATTESTATION_EVIDENCE_DIR) / control_id
    evidence_dir.mkdir(parents=True, exist_ok=True)

    safe_name = f"{uuid.uuid4().hex[:8]}_{Path(file.filename or 'evidence').name}"
    dest = evidence_dir / safe_name
    try:
        content = await file.read()
        dest.write_bytes(content)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to store evidence file: {exc}")

    evidence_url = f"/attestations/{control_id}/evidence/{safe_name}"
    return {"evidence_url": evidence_url}
