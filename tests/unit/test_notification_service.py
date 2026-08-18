"""app/services/notification_service.py — zero prior coverage. Derives
"notifications" from the scans collection directly (there's no dedicated
notifications collection), scoped per-user unless the caller is an admin.
"""
from datetime import datetime, timezone

import pytest
from bson import ObjectId

from app.enums.role import UserRole
from app.services.notification_service import NotificationService


async def _insert_scan(mongo_db, *, scan_id, user_id, state="COMPLETED", created_at=None):
    # scan_service.py's start() stores user_id as a real ObjectId (see
    # `object_id = to_object_id(user_id)` there), not a string — matching
    # that shape here, since notification_service.py's own query converts
    # the caller's user id to ObjectId before matching against this field.
    await mongo_db.scans.insert_one({
        "scan_id": scan_id,
        "user_id": ObjectId(user_id),
        "state": state,
        "created_at": created_at or datetime.now(timezone.utc),
    })


class TestNotificationScoping:
    @pytest.mark.asyncio
    async def test_normal_user_only_sees_their_own_scans(self, mongo_db, normal_user, admin_user):
        await _insert_scan(mongo_db, scan_id="mine", user_id=str(normal_user["_id"]))
        await _insert_scan(mongo_db, scan_id="theirs", user_id=str(admin_user["_id"]))

        result = await NotificationService().list(mongo_db, normal_user)

        ids = {item["id"] for item in result["items"]}
        assert ids == {"mine"}
        assert result["total"] == 1

    @pytest.mark.asyncio
    async def test_admin_sees_every_users_scans(self, mongo_db, normal_user, admin_user):
        await _insert_scan(mongo_db, scan_id="mine", user_id=str(normal_user["_id"]))
        await _insert_scan(mongo_db, scan_id="theirs", user_id=str(admin_user["_id"]))

        admin_doc = dict(admin_user)
        admin_doc["role"] = UserRole.ADMIN.value
        result = await NotificationService().list(mongo_db, admin_doc)

        ids = {item["id"] for item in result["items"]}
        assert ids == {"mine", "theirs"}
        assert result["total"] == 2


class TestNotificationShapeAndPaging:
    @pytest.mark.asyncio
    async def test_message_includes_scan_id_and_lowercased_state(self, mongo_db, normal_user):
        await _insert_scan(mongo_db, scan_id="scan-1", user_id=str(normal_user["_id"]), state="FAILED")

        result = await NotificationService().list(mongo_db, normal_user)

        assert result["items"][0]["message"] == "Scan scan-1 failed"
        assert result["items"][0]["level"] == "INFO"

    @pytest.mark.asyncio
    async def test_missing_state_defaults_to_unknown(self, mongo_db, normal_user):
        await mongo_db.scans.insert_one({
            "scan_id": "scan-2", "user_id": normal_user["_id"],
            "created_at": datetime.now(timezone.utc),
        })

        result = await NotificationService().list(mongo_db, normal_user)

        assert "unknown" in result["items"][0]["message"]

    @pytest.mark.asyncio
    async def test_results_sorted_newest_first(self, mongo_db, normal_user):
        older = datetime(2020, 1, 1, tzinfo=timezone.utc)
        newer = datetime(2024, 1, 1, tzinfo=timezone.utc)
        await _insert_scan(mongo_db, scan_id="old", user_id=str(normal_user["_id"]), created_at=older)
        await _insert_scan(mongo_db, scan_id="new", user_id=str(normal_user["_id"]), created_at=newer)

        result = await NotificationService().list(mongo_db, normal_user)

        assert [item["id"] for item in result["items"]] == ["new", "old"]

    @pytest.mark.asyncio
    async def test_pagination_second_page_offsets_by_size(self, mongo_db, normal_user):
        for i in range(5):
            await _insert_scan(
                mongo_db, scan_id=f"scan-{i}", user_id=str(normal_user["_id"]),
                created_at=datetime(2024, 1, i + 1, tzinfo=timezone.utc),
            )

        page1 = await NotificationService().list(mongo_db, normal_user, page=1, size=2)
        page2 = await NotificationService().list(mongo_db, normal_user, page=2, size=2)

        assert len(page1["items"]) == 2
        assert len(page2["items"]) == 2
        assert {i["id"] for i in page1["items"]}.isdisjoint({i["id"] for i in page2["items"]})
        assert page1["total"] == 5 and page2["total"] == 5

    @pytest.mark.asyncio
    async def test_no_scans_returns_empty_items_with_zero_total(self, mongo_db, normal_user):
        result = await NotificationService().list(mongo_db, normal_user)
        assert result == {"items": [], "page": 1, "size": 10, "total": 0}
