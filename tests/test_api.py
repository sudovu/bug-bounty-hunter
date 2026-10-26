"""Integration Tests for FastAPI Endpoints."""
import pytest
from fastapi.testclient import TestClient

from backend.app.main import app
from backend.app.db.base import get_db

client = TestClient(app)


def test_system_status_endpoint(db_session):
    app.dependency_overrides[get_db] = lambda: db_session
    try:
        response = client.get("/api/v1/system/status")
        assert response.status_code == 200
        data = response.json()
        assert "emergency_stop" in data
        assert "total_findings" in data
    finally:
        app.dependency_overrides.clear()


def test_create_program_and_verify_scope(db_session):
    app.dependency_overrides[get_db] = lambda: db_session
    try:
        # Create program
        payload = {
            "name": "Integration Test Program",
            "platform": "Bugcrowd",
            "program_url": "https://bugcrowd.com/test",
            "in_scope_assets": [
                {"asset_type": "WILDCARD", "pattern": "*.testapp.com"}
            ],
            "excluded_assets": [
                {"pattern": "internal.testapp.com", "reason": "Restricted staging"}
            ]
        }
        res = client.post("/api/v1/programs", json=payload)
        assert res.status_code == 201
        prog_id = res.json()["id"]

        # Dry-run verify scope on out-of-scope target
        verify_res = client.post(f"/api/v1/programs/{prog_id}/verify-scope?target=unauthorized.com")
        assert verify_res.status_code == 200
        assert verify_res.json()["allowed"] is False

        # Dry-run verify scope on excluded target
        verify_res_excl = client.post(f"/api/v1/programs/{prog_id}/verify-scope?target=internal.testapp.com")
        assert verify_res_excl.status_code == 200
        assert verify_res_excl.json()["allowed"] is False
    finally:
        app.dependency_overrides.clear()


def test_emergency_stop_toggle(db_session):
    app.dependency_overrides[get_db] = lambda: db_session
    try:
        # Engage stop
        res = client.post("/api/v1/system/emergency-stop?active=true")
        assert res.status_code == 200
        assert res.json()["emergency_stop"] is True

        # Disengage stop
        res = client.post("/api/v1/system/emergency-stop?active=false")
        assert res.status_code == 200
        assert res.json()["emergency_stop"] is False
    finally:
        app.dependency_overrides.clear()
