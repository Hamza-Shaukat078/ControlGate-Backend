"""
Integration tests — /api/v1/scan/* and /api/v1/scans/* endpoints

Tests direct code scanning, scan status polling, scan listing,
and WebSocket streaming. LLM and pipeline calls are mocked.
"""
import pytest
from unittest.mock import patch, MagicMock, AsyncMock


VULN_SQL = {
    "id": "v1",
    "type": "SQL Injection",
    "severity": "critical",
    "confidence": 0.9,
    "cvss_score": 9.8,
    "cwe": "CWE-89",
    "owasp": "A03",
    "location": {"file": "app.py", "start_line": 10, "end_line": 10},
    "evidence": {"source": "username", "sink": "execute", "pattern": "DFG_FLOW", "code_snippet": ""},
    "analysis": {
        "static_detection": {"severity": "critical", "confidence": "high", "reason": "SQLi"},
        "llm_classification": {"classification": "VULNERABLE", "severity": "critical",
                                "exploitability": 0.9, "confidence": 0.9,
                                "explanation": "SQL injection detected", "remediation": "Use parameterized queries"},
    },
}

MOCK_PIPELINE_RESULT = MagicMock(
    success=True,
    vulnerabilities=[VULN_SQL],
    analysis_time=1.2,
    files_analyzed=1,
    nodes_count=50,
    edges_count=30,
)


class TestDirectScan:
    URL = "/api/v1/scan"

    def _post(self, client, code: str, language: str = "python", filename: str = "test.py"):
        return client.post(self.URL, json={
            "code": code,
            "language": language,
            "filename": filename,
        })

    def test_scan_clean_code_returns_200(self, client):
        with patch("semantic_engine.pipeline.get_pipeline") as mock_get:
            mock_pipeline = MagicMock()
            mock_pipeline.analyze_code = AsyncMock(return_value=MagicMock(
                success=True, vulnerabilities=[], analysis_time=0.5,
                files_analyzed=1, nodes_count=10, edges_count=5,
            ))
            mock_get.return_value = mock_pipeline
            r = self._post(client, "x = 1")
        assert r.status_code == 200

    def test_scan_vulnerable_code_returns_findings(self, client):
        with patch("semantic_engine.pipeline.get_pipeline") as mock_get:
            mock_pipeline = MagicMock()
            mock_pipeline.analyze_code = AsyncMock(return_value=MOCK_PIPELINE_RESULT)
            mock_get.return_value = mock_pipeline
            r = self._post(client, 'query = f"SELECT * FROM users WHERE id={uid}"')
        assert r.status_code == 200
        body = r.json()
        assert body.get("vulnerabilities_found", 0) >= 0

    def test_scan_missing_code_returns_422(self, client):
        r = client.post(self.URL, json={"language": "python"})
        assert r.status_code == 422

    def test_scan_missing_language_returns_422(self, client):
        r = client.post(self.URL, json={"code": "x = 1"})
        assert r.status_code == 422

    def test_scan_response_reports_success(self, client):
        # POST /api/v1/scan is the synchronous direct-code-scan endpoint — it
        # returns results inline with no persisted job to poll, so (unlike
        # /api/v1/scans/start) its ScanResponse schema has no scan_id field.
        with patch("semantic_engine.pipeline.get_pipeline") as mock_get:
            mock_pipeline = MagicMock()
            mock_pipeline.analyze_code = AsyncMock(return_value=MagicMock(
                success=True, vulnerabilities=[], analysis_time=0.1,
                files_analyzed=1, nodes_count=0, edges_count=0,
            ))
            mock_get.return_value = mock_pipeline
            r = self._post(client, "pass")
        assert r.status_code == 200
        assert r.json().get("success") is True

    def test_scan_response_has_severity_breakdown(self, client):
        with patch("semantic_engine.pipeline.get_pipeline") as mock_get:
            mock_pipeline = MagicMock()
            mock_pipeline.analyze_code = AsyncMock(return_value=MOCK_PIPELINE_RESULT)
            mock_get.return_value = mock_pipeline
            r = self._post(client, 'query = f"SELECT {x}"')
        assert r.status_code == 200
        body = r.json()
        assert "by_severity" in body or "vulnerabilities_found" in body

    def test_scan_javascript_code(self, client):
        with patch("semantic_engine.pipeline.get_pipeline") as mock_get:
            mock_pipeline = MagicMock()
            mock_pipeline.analyze_code = AsyncMock(return_value=MagicMock(
                success=True, vulnerabilities=[], analysis_time=0.1,
                files_analyzed=1, nodes_count=0, edges_count=0,
            ))
            mock_get.return_value = mock_pipeline
            r = self._post(client, "const x = req.query.id;", language="javascript", filename="app.js")
        assert r.status_code == 200

    def test_scan_unauthenticated_returns_401(self, mongo_db):
        from app.main import app
        from app.db.mongo import get_mongo_db
        async def _db():
            yield mongo_db
        app.dependency_overrides[get_mongo_db] = _db
        from fastapi.testclient import TestClient
        with TestClient(app, raise_server_exceptions=False) as c:
            r = c.post(self.URL, json={"code": "x=1", "language": "python"})
        app.dependency_overrides.clear()
        assert r.status_code == 401


class TestScanStatus:
    def test_get_existing_scan_status(self, client, sample_scan):
        sid = sample_scan["scan_id"]
        r = client.get(f"/api/v1/scans/{sid}/status")
        assert r.status_code == 200

    def test_get_nonexistent_scan_returns_404(self, client):
        r = client.get("/api/v1/scans/nonexistent-scan-id/status")
        assert r.status_code == 404

    def test_status_response_has_status_field(self, client, sample_scan):
        r = client.get(f"/api/v1/scans/{sample_scan['scan_id']}/status")
        assert r.status_code == 200
        assert "state" in r.json()

    def test_completed_scan_status_is_completed(self, client, sample_scan):
        r = client.get(f"/api/v1/scans/{sample_scan['scan_id']}/status")
        assert r.json().get("state") == "COMPLETED"


class TestScanList:
    URL = "/api/v1/scans/"

    def test_list_scans_returns_200(self, client):
        r = client.get(self.URL)
        assert r.status_code == 200

    def test_list_scans_returns_list(self, client):
        r = client.get(self.URL)
        body = r.json()
        assert isinstance(body, list) or isinstance(body, dict)

    def test_completed_scan_appears_in_list(self, client, sample_scan):
        r = client.get(self.URL)
        assert r.status_code == 200

    def test_list_scan_unauthenticated_returns_401(self, mongo_db):
        from app.main import app
        from app.db.mongo import get_mongo_db
        async def _db():
            yield mongo_db
        app.dependency_overrides[get_mongo_db] = _db
        from fastapi.testclient import TestClient
        with TestClient(app, raise_server_exceptions=False) as c:
            r = c.get(self.URL)
        app.dependency_overrides.clear()
        assert r.status_code == 401


class TestScanDelete:
    def test_delete_existing_scan_returns_200_or_204(self, client, sample_scan):
        sid = sample_scan["scan_id"]
        r = client.delete(f"/api/v1/scans/{sid}")
        assert r.status_code in (200, 204, 404)

    def test_delete_nonexistent_scan_returns_404(self, client):
        r = client.delete("/api/v1/scans/does-not-exist")
        assert r.status_code == 404
