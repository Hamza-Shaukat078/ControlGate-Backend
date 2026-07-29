import json
import logging
from pathlib import Path

from app.db.mongo import get_mongo_database

logger = logging.getLogger(__name__)

_DATA_DIR = Path(__file__).resolve().parent.parent / "data"
_CATALOG_PATHS = [
    _DATA_DIR / "asvs_l1_controls.json",
    _DATA_DIR / "asvs_l2_controls.json",
]


async def seed_asvs_controls() -> None:
    """
    Load the ASVS 5.0.0 Level-1 and Level-2 control catalogs (app/data/asvs_l1_controls.json,
    app/data/asvs_l2_controls.json) into the asvs_controls collection. Upserts by control_id so
    re-running on every startup keeps the catalog in sync with the source files without
    duplicating documents.
    """
    db = get_mongo_database()

    controls = []
    for catalog_path in _CATALOG_PATHS:
        with open(catalog_path, "r", encoding="utf-8") as f:
            controls += json.load(f)

    for control in controls:
        await db.asvs_controls.update_one(
            {"control_id": control["control_id"]},
            {"$set": control},
            upsert=True,
        )

    logger.info(f"ASVS control catalog synced: {len(controls)} controls")
