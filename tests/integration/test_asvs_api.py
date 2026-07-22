"""
Route-level tests for the new /asvs/*, /attestations, and /export/asvs-report
endpoints (Section F).

These call the route handler functions directly (they're plain async
functions under FastAPI decorators) rather than going through
`TestClient(app)`. That's a deliberate choice, not a shortcut: this repo's
app startup lifespan (`ensure_indexes`/`seed_admin`/`seed_asvs_controls`)
needs a reachable MongoDB, which this sandbox doesn't have — confirmed by
running an existing, unrelated `TestClient`-based test
(`test_auth_api.py::TestRegister::test_register_new_user_returns_201`) in
complete isolation and getting the identical `RuntimeError: Event loop is
closed` failure. That's the same pre-existing environment issue behind the
standing ~86 failures/errors across this whole suite (present before any of
this work), not something these tests can route around by trying harder.
Calling the handlers directly proves the actual request/response logic
without depending on a real database connection at import time.
"""
import json
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from fastapi import HTTPException, UploadFile
from io import BytesIO

from app.api.routes import asvs as asvs_routes
from app.api.routes import attestations as attestations_routes
from app.api.routes import reports as reports_routes
from app.schemas.asvs import AttestationSubmit
from app.enums.asvs import ControlVerdict

CATALOG = json.loads(
    (Path(__file__).resolve().parents[2] / "app" / "data" / "asvs_l1_controls.json").read_text(encoding="utf-8")
)


class FakeCursor:
    def __init__(self, docs):
        self.docs = docs

    def sort(self, *a, **kw):
        return self

    async def to_list(self, length=None):
        return self.docs

    def __aiter__(self):
        async def gen():
            for d in self.docs:
                yield d
        return gen()


class FakeCollection:
    def __init__(self, docs=None):
        self.docs = docs if docs is not None else []

    def find(self, *a, **kw):
        return FakeCursor(self.docs)

    async def find_one(self, query=None, sort=None):
        query = query or {}
        for d in self.docs:
            if all(d.get(k) == v for k, v in query.items()):
                return d
        return None

    async def update_one(self, query, update, upsert=False):
        for d in self.docs:
            if all(d.get(k) == v for k, v in query.items()):
                d.update(update.get("$set", {}))
                return MagicMock()
        if upsert:
            new_doc = dict(query)
            new_doc.update(update.get("$set", {}))
            self.docs.append(new_doc)
        return MagicMock()


class FakeDB:
    def __init__(self, scans=None, attestations=None):
        self.asvs_controls = FakeCollection(list(CATALOG))
        self.scans = FakeCollection(scans or [])
        self.attestations = FakeCollection(attestations or [])
        self.asvs_results = FakeCollection([])


FAKE_USER = {"id": "user-1", "email": "test@example.com", "full_name": "Test User", "role": "normal"}


class TestAsvsControlsRoutes:
    @pytest.mark.asyncio
    async def test_list_controls_returns_all_70(self):
        result = await asvs_routes.list_controls(user=FAKE_USER, db=FakeDB())
        assert len(result) == 70

    @pytest.mark.asyncio
    async def test_list_chapters_returns_15(self):
        result = await asvs_routes.list_chapters(user=FAKE_USER, db=FakeDB())
        assert len(result) == 15

    @pytest.mark.asyncio
    async def test_get_control_by_id(self):
        db = FakeDB()
        result = await asvs_routes.get_control("V9.2.1", user=FAKE_USER, db=db)
        assert result["control"]["control_id"] == "V9.2.1"

    @pytest.mark.asyncio
    async def test_get_unknown_control_raises_404(self):
        with pytest.raises(HTTPException) as exc_info:
            await asvs_routes.get_control("V99.9.9", user=FAKE_USER, db=FakeDB())
        assert exc_info.value.status_code == 404


class TestComplianceRoute:
    @pytest.mark.asyncio
    async def test_compliance_summary_shape(self):
        db = FakeDB(scans=[{"scan_id": "scan-1", "summary": {
            "scan_id": "scan-1", "vulnerabilities": [], "config_findings": [],
            "dependency_findings": [], "dependency_control_result": None,
            "dynamic_probe_findings": [],
        }}])
        result = await reports_routes.get_asvs_compliance("scan-1", framework="asvs", user=FAKE_USER, db=db)
        assert set(result.keys()) >= {"scan_id", "chapters", "levels", "results"}
        assert len(result["results"]) == 70

    @pytest.mark.asyncio
    async def test_unsupported_framework_raises_400(self):
        with pytest.raises(HTTPException) as exc_info:
            await reports_routes.get_asvs_compliance("scan-1", framework="owasp-top10", user=FAKE_USER, db=FakeDB())
        assert exc_info.value.status_code == 400


class TestAttestationRoutes:
    @pytest.mark.asyncio
    async def test_list_empty(self):
        result = await attestations_routes.list_attestations(user=FAKE_USER, db=FakeDB())
        assert result == {}

    @pytest.mark.asyncio
    async def test_submit_then_list(self):
        db = FakeDB()
        payload = AttestationSubmit(control_id="V2.1.1", answer=ControlVerdict.PASS, evidence_url="https://example.com/doc.pdf")
        submitted = await attestations_routes.submit_attestation(payload, user=FAKE_USER, db=db)
        assert submitted["control_id"] == "V2.1.1"
        assert submitted["attested_by"] == "Test User"

        listed = await attestations_routes.list_attestations(user=FAKE_USER, db=db)
        assert "V2.1.1" in listed

    @pytest.mark.asyncio
    async def test_resubmit_overwrites_previous_answer_not_duplicates(self):
        db = FakeDB()
        await attestations_routes.submit_attestation(
            AttestationSubmit(control_id="V2.1.1", answer=ControlVerdict.FAIL), user=FAKE_USER, db=db,
        )
        await attestations_routes.submit_attestation(
            AttestationSubmit(control_id="V2.1.1", answer=ControlVerdict.PASS), user=FAKE_USER, db=db,
        )
        listed = await attestations_routes.list_attestations(user=FAKE_USER, db=db)
        assert len(listed) == 1
        assert listed["V2.1.1"]["answer"] == "pass"

    @pytest.mark.asyncio
    async def test_upload_evidence_returns_url(self, tmp_path, monkeypatch):
        from app.core.config import settings
        monkeypatch.setattr(settings, "ATTESTATION_EVIDENCE_DIR", str(tmp_path))

        upload = UploadFile(filename="evidence.txt", file=BytesIO(b"hello world"))
        result = await attestations_routes.upload_evidence("V2.1.1", file=upload, user=FAKE_USER, db=FakeDB())
        assert result["evidence_url"].startswith("/attestations/V2.1.1/evidence/")
        assert (tmp_path / "V2.1.1").exists()
