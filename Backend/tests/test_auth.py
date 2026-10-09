import pytest
from fastapi.testclient import TestClient
import jwt
from datetime import datetime, timezone, timedelta
from app.main import app
from app.config import settings
from app.database import SessionLocal
from app.models.user import User
from app.services.auth_service import hash_password, create_access_token
from app.services.notification_service import notification_service

client = TestClient(app)


def test_auth_config_endpoint():
    response = client.get("/api/auth/config")
    assert response.status_code == 200
    data = response.json()
    assert "supabase_url" in data
    assert "supabase_anon_key" in data
    assert "configured" in data
    assert "auth_required" in data
    assert "demo_account" not in data


def test_auth_me_unauthenticated():
    # Without Authorization header -> 401
    response = client.get("/api/auth/me")
    assert response.status_code == 401


def test_auth_verify_invalid_tokens():
    # Demo token -> 401 valid: False
    payload = {"access_token": "demo-token"}
    response = client.post("/api/auth/verify", json=payload)
    assert response.status_code == 401
    data = response.json()
    assert data["valid"] is False

    # Wrong secret token -> 401
    bad_token = jwt.encode({"sub": "1", "exp": datetime.now(timezone.utc) + timedelta(hours=1), "iat": datetime.now(timezone.utc)}, "wrong-secret-key-12345678901234567890", algorithm="HS256")
    resp_bad = client.post("/api/auth/verify", json={"access_token": bad_token})
    assert resp_bad.status_code == 401
    assert resp_bad.json()["valid"] is False


def test_auth_verify_jwt_token(auth_headers):
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.email == "test_investigator@cyberscope.io").first()
        token = create_access_token(user.to_dict())

        response = client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"})
        assert response.status_code == 200
        data = response.json()
        assert data["user"]["email"] == "test_investigator@cyberscope.io"
        assert data["user"]["name"] == "Test Investigator"

        # Test POST /api/auth/verify
        verify_resp = client.post("/api/auth/verify", json={"access_token": token})
        assert verify_resp.status_code == 200
        v_data = verify_resp.json()
        assert v_data["valid"] is True
        assert v_data["user"]["email"] == "test_investigator@cyberscope.io"
    finally:
        db.close()


def test_auth_registration_flow():
    from app.models.user import UserVerification
    new_email = "new_officer@police.gov.in"
    db = SessionLocal()
    try:
        db.query(User).filter(User.email == new_email).delete()
        db.query(UserVerification).filter(UserVerification.email == new_email).delete()
        db.commit()
    finally:
        db.close()

    res_check = client.post("/api/auth/check-email", json={"email": "test_investigator@cyberscope.io"})
    assert res_check.status_code == 200
    assert res_check.json()["exists"] is True

    res_check_new = client.post("/api/auth/check-email", json={"email": new_email})
    assert res_check_new.status_code == 200
    assert res_check_new.json()["exists"] is False

    conflict_resp = client.post("/api/auth/register/initiate", json={
        "name": "Demo Dup",
        "phone": "9876543210",
        "email": "test_investigator@cyberscope.io",
        "password": "SecureTestPass123!"
    })
    assert conflict_resp.status_code == 409

    init_resp = client.post("/api/auth/register/initiate", json={
        "name": "Officer Sharma",
        "phone": "9876543210",
        "email": new_email,
        "password": "SecurePassword123!",
        "role": "Lead Investigator",
        "organization": "Delhi Cyber Cell"
    })
    assert init_resp.status_code == 200
    init_data = init_resp.json()
    assert init_data["status"] == "initiated"

    outbox = notification_service.get_test_outbox()
    email_entry = next(e for e in reversed(outbox["emails"]) if e["to_email"] == new_email)
    email_otp = email_entry["code"]

    verify_resp = client.post("/api/auth/register/verify", json={
        "email": new_email,
        "email_otp": email_otp
    })
    assert verify_resp.status_code == 200
    v_data = verify_resp.json()
    assert v_data["status"] == "verified"
    assert "access_token" in v_data
    assert v_data["user"]["email"] == new_email


def test_auth_register_validation_errors():
    resp_email = client.post("/api/auth/register/initiate", json={
        "name": "Test", "phone": "9876543210", "email": "invalidemail", "password": "SecurePassword123!"
    })
    assert resp_email.status_code == 400

    resp_pass = client.post("/api/auth/register/initiate", json={
        "name": "Test", "phone": "9876543210", "email": "valid@gov.in", "password": "123"
    })
    assert resp_pass.status_code == 400


def test_auth_resend_cooldown():
    test_email = "cooldown_test@police.gov.in"
    from app.models.user import UserVerification
    from app.api.auth import _last_resend_timestamps
    db = SessionLocal()
    try:
        db.query(User).filter(User.email == test_email).delete()
        db.query(UserVerification).filter(UserVerification.email == test_email).delete()
        db.commit()
    finally:
        db.close()

    init_resp = client.post("/api/auth/register/initiate", json={
        "name": "Cooldown Tester",
        "email": test_email,
        "phone": "+919876543211",
        "password": "SecurePassword123!"
    })
    assert init_resp.status_code == 200

    _last_resend_timestamps[test_email] = 0

    resend1 = client.post("/api/auth/register/resend", json={"email": test_email})
    assert resend1.status_code == 200

    resend2 = client.post("/api/auth/register/resend", json={"email": test_email})
    assert resend2.status_code == 429
    assert resend2.json()["code"] == "COOLDOWN_ACTIVE"


def test_auth_login_endpoints():
    # Non-existent user -> 401 INVALID_CREDENTIALS
    resp_nonexistent = client.post("/api/auth/login", json={
        "email": "ghost_agent@cyberscope.io",
        "password": "somepassword"
    })
    assert resp_nonexistent.status_code == 401
    assert resp_nonexistent.json()["code"] == "INVALID_CREDENTIALS"

    # Wrong password for existing user -> 401 (identical body)
    resp_wrongpass = client.post("/api/auth/login", json={
        "email": "test_investigator@cyberscope.io",
        "password": "wrongpassword"
    })
    assert resp_wrongpass.status_code == 401
    assert resp_wrongpass.json() == resp_nonexistent.json()

    # Valid user login -> 200 authenticated
    resp_ok = client.post("/api/auth/login", json={
        "email": "test_investigator@cyberscope.io",
        "password": "SecureTestPass123!"
    })
    assert resp_ok.status_code == 200
    data = resp_ok.json()
    assert data["status"] == "authenticated"
    assert "access_token" in data


def test_all_data_routes_require_auth():
    """
    Acceptance test iterating app.routes to ensure every route not on the
    public allowlist returns 401 when called without a valid Bearer token.
    """
    public_allowlist = {
        ("GET", "/"),
        ("GET", "/api/health"),
        ("POST", "/api/auth/login"),
        ("POST", "/api/auth/register/initiate"),
        ("POST", "/api/auth/register/verify"),
        ("POST", "/api/auth/register/resend"),
        ("POST", "/api/auth/verify"),
        ("GET", "/api/auth/config"),
        ("POST", "/api/auth/check-password"),
        ("POST", "/api/auth/check-email"),
    }

    # Generate forged / invalid tokens for testing
    wrong_secret_token = jwt.encode(
        {"sub": "1", "exp": datetime.now(timezone.utc) + timedelta(hours=1), "iat": datetime.now(timezone.utc)},
        "wrong-secret-key-12345678901234567890",
        algorithm="HS256"
    )
    alg_none_token = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxIiwiZXhwIjo5OTk5OTk5OTk5fQ."
    expired_token = jwt.encode(
        {"sub": "1", "exp": datetime.now(timezone.utc) - timedelta(hours=1), "iat": datetime.now(timezone.utc) - timedelta(hours=2)},
        settings.JWT_SECRET,
        algorithm="HS256"
    )
    demo_token = "demo-investigator-token-123"

    for route in app.routes:
        methods = getattr(route, "methods", {"GET"}) or {"GET"}
        path = getattr(route, "path", None)
        if not path or path.startswith("/docs") or path.startswith("/openapi") or path.startswith("/redoc"):
            continue

        for method in methods:
            if (method, path) in public_allowlist:
                continue

            # 1. No Authorization header -> 401
            req_func = getattr(client, method.lower())
            res_no_auth = req_func(path)
            assert res_no_auth.status_code == 401, f"Route {method} {path} returned {res_no_auth.status_code} without auth, expected 401"

            # 2. Wrong secret token -> 401
            res_wrong = req_func(path, headers={"Authorization": f"Bearer {wrong_secret_token}"})
            assert res_wrong.status_code == 401, f"Route {method} {path} returned {res_wrong.status_code} with wrong secret token, expected 401"

            # 3. Alg none token -> 401
            res_none = req_func(path, headers={"Authorization": f"Bearer {alg_none_token}"})
            assert res_none.status_code == 401, f"Route {method} {path} returned {res_none.status_code} with alg:none token, expected 401"

            # 4. Expired token -> 401
            res_exp = req_func(path, headers={"Authorization": f"Bearer {expired_token}"})
            assert res_exp.status_code == 401, f"Route {method} {path} returned {res_exp.status_code} with expired token, expected 401"

            # 5. Demo token -> 401
            res_demo = req_func(path, headers={"Authorization": f"Bearer {demo_token}"})
            assert res_demo.status_code == 401, f"Route {method} {path} returned {res_demo.status_code} with demo token, expected 401"
