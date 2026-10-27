"""Unit & Integration Tests for Authentication and Authorization."""
import pytest
from fastapi.testclient import TestClient

from backend.app.main import app
from backend.app.db.base import get_db
from backend.app.db.models import User, UserRole
from backend.app.core.security import hash_password, create_access_token

client = TestClient(app)


def test_auth_status_setup_required(db_session):
    app.dependency_overrides[get_db] = lambda: db_session
    try:
        res = client.get("/api/v1/auth/status")
        assert res.status_code == 200
        data = res.json()
        assert data["setup_required"] is True
        assert data["authenticated"] is False
    finally:
        app.dependency_overrides.clear()


def test_admin_setup_wizard_lifecycle(db_session):
    app.dependency_overrides[get_db] = lambda: db_session
    try:
        # 1. First-time setup succeeds
        setup_payload = {
            "username": "masteradmin",
            "email": "admin@example.com",
            "password": "MasterSecurePassword2026!",
            "confirm_password": "MasterSecurePassword2026!"
        }
        res = client.post("/api/v1/auth/setup", json=setup_payload)
        assert res.status_code == 201
        data = res.json()
        assert "access_token" in data
        assert data["user"]["username"] == "masteradmin"
        assert data["user"]["role"] == "admin"
        token = data["access_token"]

        # 2. Subsequent setup attempts MUST be rejected (locked)
        res_locked = client.post("/api/v1/auth/setup", json=setup_payload)
        assert res_locked.status_code == 400
        assert "already initialized" in res_locked.json()["detail"].lower()

        # 3. /status now shows setup_required = False
        res_status = client.get("/api/v1/auth/status")
        assert res_status.json()["setup_required"] is False

        # 4. Access /me using the returned token
        headers = {"Authorization": f"Bearer {token}"}
        res_me = client.get("/api/v1/auth/me", headers=headers)
        assert res_me.status_code == 200
        assert res_me.json()["username"] == "masteradmin"

    finally:
        app.dependency_overrides.clear()


def test_login_flow(db_session):
    app.dependency_overrides[get_db] = lambda: db_session
    try:
        # Seed an operator
        user = User(
            username="security_analyst",
            email="analyst@example.com",
            hashed_password=hash_password("AnalystPass123!"),
            role=UserRole.REVIEWER,
            is_active=True
        )
        db_session.add(user)
        db_session.commit()

        # 1. Invalid password -> 401
        res_bad = client.post("/api/v1/auth/login", json={
            "username": "security_analyst",
            "password": "WrongPassword"
        })
        assert res_bad.status_code == 401

        # 2. Valid credentials -> 200 with JWT
        res_ok = client.post("/api/v1/auth/login", json={
            "username": "security_analyst",
            "password": "AnalystPass123!"
        })
        assert res_ok.status_code == 200
        assert "access_token" in res_ok.json()
        assert res_ok.json()["user"]["role"] == "reviewer"

        # 3. Login using email also works
        res_email = client.post("/api/v1/auth/login", json={
            "username": "analyst@example.com",
            "password": "AnalystPass123!"
        })
        assert res_email.status_code == 200

    finally:
        app.dependency_overrides.clear()


def test_role_authorization_admin_only_features(db_session):
    app.dependency_overrides[get_db] = lambda: db_session
    try:
        # Create Admin and Reviewer
        admin = User(
            username="admin_user",
            email="admin@test.com",
            hashed_password=hash_password("AdminPass123!"),
            role=UserRole.ADMIN,
            is_active=True
        )
        reviewer = User(
            username="reviewer_user",
            email="rev@test.com",
            hashed_password=hash_password("RevPass123!"),
            role=UserRole.REVIEWER,
            is_active=True
        )
        db_session.add_all([admin, reviewer])
        db_session.commit()

        admin_token = create_access_token({"sub": str(admin.id), "username": admin.username, "role": "admin"})
        reviewer_token = create_access_token({"sub": str(reviewer.id), "username": reviewer.username, "role": "reviewer"})

        # Reviewer cannot access /users (Admin only)
        res_rev = client.get("/api/v1/auth/users", headers={"Authorization": f"Bearer {reviewer_token}"})
        assert res_rev.status_code == 403

        # Admin CAN access /users
        res_admin = client.get("/api/v1/auth/users", headers={"Authorization": f"Bearer {admin_token}"})
        assert res_admin.status_code == 200
        assert len(res_admin.json()) == 2

        # Admin creates new user
        new_user_payload = {
            "username": "new_operator",
            "email": "operator@test.com",
            "password": "OperatorPass123!",
            "role": "reviewer"
        }
        res_create = client.post("/api/v1/auth/users", json=new_user_payload, headers={"Authorization": f"Bearer {admin_token}"})
        assert res_create.status_code == 201
        assert res_create.json()["username"] == "new_operator"

    finally:
        app.dependency_overrides.clear()
