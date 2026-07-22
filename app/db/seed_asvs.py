import json
import logging
from pathlib import Path

from app.db.mongo import get_mongo_database

logger = logging.getLogger(__name__)

_CATALOG_PATH = Path(__file__).resolve().parent.parent / "data" / "asvs_l1_controls.json"


async def seed_asvs_controls() -> None:
    """
    Load the ASVS 5.0.0 Level-1 control catalog (app/data/asvs_l1_controls.json)
    into the asvs_controls collection. Upserts by control_id so re-running on
    every startup keeps the catalog in sync with the source file without
    duplicating documents.
    """
    db = get_mongo_database()

    with open(_CATALOG_PATH, "r", encoding="utf-8") as f:
        controls = json.load(f)

    for control in controls:
        await db.asvs_controls.update_one(
            {"control_id": control["control_id"]},
            {"$set": control},
            upsert=True,
        )

    logger.info(f"ASVS control catalog synced: {len(controls)} controls")
