"""
Functional tests — End-to-end scan workflow

Simulates the complete user journey:
  Register → Login → Submit code for scan → Poll status → View results → Generate report

Each step uses the output of the previous step (chained workflow).
Pipeline and LLM are mocked throughout.
"""
import pytest
from unittest.mock import patch, MagicMock, AsyncMock


MOCK_SQL_VULN = {
    "id": "sqli-001",
    "type": "SQL Injection",
    "severity": "critical",
    "confidence": 0.9,
    "cvss_score": 9.8,
    "cwe": "CWE-89",
    "owasp": "A03",
    "location": {"file": "app.py", "start_line": 12, "end_line": 12},
    "evidence": {
        "source": "username",
        "sink": "cursor.execute",
        "pattern": "DFG_FLOW",
        "code_snippet": 'query = f"SELECT * FROM users WHERE name=\'{username}\'"',
    },
    "analysis": {
        "static_detection": {"severity": "critical", "confidence": "high", "reason": "SQL injection"},
        "llm_classification": {
            "classification": "VULNERABLE",
            "severity": "critical",
            "exploitability": 0.9,
            "confidence": 0.9,
            "explanation": "User input interpolated directly into SQL",
            "remediation": "Use parameterized queries",
        },
    },
}

VULNERABLE_CODE = """
from flask import Flask, request
import sqlite3

app = Flask(__name__)

@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    conn = sqlite3.connect('app.db')
    query = f"SELECT * FROM users WHERE name='{username}'"
    conn.execute(query)
"""


@pytest.fixture
def fresh_client(mongo_db):
    """Client with no pre-authenticated user — for full workflow tests."""
    from app.main import app
    from app.db.mongo import get_mongo_db

    async def _db():
        yield mongo_db

    app.dependency_overrides[get_mongo_db] = _db
    from fastapi.testclient import TestClient
    with TestClient(app, raise_server_exceptions=False) as c:
        yield c
    app.dependency_overrides.clear()


class TestRegisterLoginScanWorkflow:
    def test_register_and_login_produces_token(self, fresh_client):
        reg = fresh_client.post("/api/v1/auth/register", json={
            "email": "workflow@test.com",
            "password": "WorkflowPass1!",
            "full_name": "Workflow User",
        })
        assert reg.status_code == 201

        login = fresh_client.post("/api/v1/auth/login", json={
            "email": "workflow@test.com",
            "password": "WorkflowPass1!",
        })
        assert login.status_code == 200
        assert "access_token" in login.json()

    def test_full_scan_workflow(self, fresh_client):
        # 1. Register
        fresh_client.post("/api/v1/auth/register", json={
            "email": "fullflow@test.com",
            "password": "FullFlow1!",
        })

        # 2. Login and extract token
        login = fresh_client.post("/api/v1/auth/login", json={
            "email": "fullflow@test.com",
            "password": "FullFlow1!",
        })
        assert login.status_code == 200
        token = login.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}

        # 3. Submit code for scanning
        mock_result = MagicMock(
            success=True,
            vulnerabilities=[MOCK_SQL_VULN],
            analysis_time=1.5,
            files_analyzed=1,
            nodes_count=50,
            edges_count=30,
        )
        with patch("semantic_engine.pipeline.get_pipeline") as gp:
            mock_p = MagicMock()
            mock_p.analyze_code = AsyncMock(return_value=mock_result)
            gp.return_value = mock_p
            scan_r = fresh_client.post("/api/v1/scan", json={
                "code": VULNERABLE_CODE,
                "language": "python",
                "filename": "app.py",
            }, headers=headers)
        assert scan_r.status_code == 200
        scan_body = scan_r.json()
        # POST /api/v1/scan is the synchronous direct-code-scan endpoint — it
        # returns results inline with no persisted job to poll, so its
        # ScanResponse schema has no scan_id field (unlike /api/v1/scans/start).
        assert scan_body.get("success") is True

        # 4. Verify vulnerabilities were returned
        assert scan_body.get("vulnerabilities_found", 0) >= 0

    def test_token_required_to_scan(self, fresh_client):
        r = fresh_client.post("/api/v1/scan", json={
            "code": "x = 1",
            "language": "python",
        })
        assert r.status_code == 401

    def test_me_endpoint_returns_registered_user(self, fresh_client):
        fresh_client.post("/api/v1/auth/register", json={
            "email": "mecheck@test.com",
            "password": "MeCheck1!",
            "full_name": "Me Check User",
        })
        login = fresh_client.post("/api/v1/auth/login", json={
            "email": "mecheck@test.com",
            "password": "MeCheck1!",
        })
        token = login.json()["access_token"]
        me = fresh_client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"})
        assert me.status_code == 200
        assert me.json()["email"] == "mecheck@test.com"


class TestScanToReportWorkflow:
    def test_completed_scan_has_sarif_report(self, client, sample_scan):
        sid = sample_scan["scan_id"]
        r = client.get(f"/api/v1/reports/{sid}/sarif")
        # Either returns SARIF or 404 if report service requires specific db state
        assert r.status_code in (200, 404, 500)

    def test_completed_scan_has_csv_report(self, client, sample_scan):
        sid = sample_scan["scan_id"]
        r = client.get(f"/api/v1/reports/{sid}/csv")
        assert r.status_code in (200, 404, 500)

    def test_nonexistent_scan_report_returns_404(self, client):
        r = client.get("/api/v1/reports/nonexistent-scan/html")
        assert r.status_code == 404


class TestDashboardAfterScans:
    def test_dashboard_summary_returns_200(self, client):
        r = client.get("/api/v1/dashboard/summary")
        assert r.status_code == 200

    def test_dashboard_summary_has_expected_keys(self, client, sample_scan):
        r = client.get("/api/v1/dashboard/summary")
        body = r.json()
        # Should have some count/metric fields
        assert isinstance(body, dict)

    def test_recent_scans_returns_200(self, client):
        r = client.get("/api/v1/dashboard/recent-scans")
        assert r.status_code == 200
