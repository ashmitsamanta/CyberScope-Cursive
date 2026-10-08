import pytest
from fastapi.testclient import TestClient
import jwt
from app.main import app
from app.config import settings
from app.services.auth_service import DEMO_USER
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
    assert "demo_account" in data
    assert data["demo_account"]["email"] == "investigator@cyberscope.io"


def test_auth_me_demo_fallback():
    # Without Authorization header when REQUIRE_AUTH=False
    response = client.get("/api/auth/me")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "authenticated"
    assert data["user"]["email"] == DEMO_USER["email"]
    assert data["user"]["name"] == DEMO_USER["name"]


def test_auth_verify_demo_token():
    payload = {"access_token": "demo-token"}
    response = client.post("/api/auth/verify", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["valid"] is True
    assert data["user"]["email"] == DEMO_USER["email"]


def test_auth_verify_jwt_token():
    # Create a synthetic signed JWT
    secret = "test-supabase-secret-12345-secure-32bytes"
    settings.SUPABASE_JWT_SECRET = secret

    token_payload = {
        "sub": "user-uuid-12345",
        "email": "analyst@cyberscope.io",
        "role": "authenticated",
        "user_metadata": {
            "name": "Special Agent Ray",
            "role": "Lead Analyst",
            "organization": "National Cyber Crime Unit"
        }
    }
    token = jwt.encode(token_payload, secret, algorithm="HS256")

    response = client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200
    data = response.json()
    assert data["user"]["email"] == "analyst@cyberscope.io"
    assert data["user"]["name"] == "Special Agent Ray"
    assert data["user"]["role"] == "Lead Analyst"

    # Also test POST /api/auth/verify
    verify_resp = client.post("/api/auth/verify", json={"access_token": token})
    assert verify_resp.status_code == 200
    v_data = verify_resp.json()
    assert v_data["valid"] is True
    assert v_data["user"]["name"] == "Special Agent Ray"

    # Reset secret
    settings.SUPABASE_JWT_SECRET = ""


def test_auth_registration_flow():
    from app.database import SessionLocal
    from app.models.user import User, UserVerification
    new_email = "new_officer@police.gov.in"
    db = SessionLocal()
    try:
        db.query(User).filter(User.email == new_email).delete()
        db.query(UserVerification).filter(UserVerification.email == new_email).delete()
        db.commit()
    finally:
        db.close()

    # 1. Check existing demo email -> exists: True
    res_check = client.post("/api/auth/check-email", json={"email": "investigator@cyberscope.io"})
    assert res_check.status_code == 200
    assert res_check.json()["exists"] is True

    # Check non-existing email -> exists: False
    res_check_new = client.post("/api/auth/check-email", json={"email": new_email})
    assert res_check_new.status_code == 200
    assert res_check_new.json()["exists"] is False

    # 2. Initiate with existing email -> 409 Conflict
    conflict_resp = client.post("/api/auth/register/initiate", json={
        "name": "Demo Dup",
        "phone": "9876543210",
        "email": "investigator@cyberscope.io",
        "password": "password123"
    })
    assert conflict_resp.status_code == 409

    # 3. Initiate with new email -> 200 verification_initiated
    init_resp = client.post("/api/auth/register/initiate", json={
        "name": "Officer Sharma",
        "phone": "9876543210",
        "email": new_email,
        "password": "securepassword123",
        "role": "Lead Investigator",
        "organization": "Delhi Cyber Cell"
    })
    assert init_resp.status_code == 200
    init_data = init_resp.json()
    assert init_data["status"] == "verification_initiated"
    assert "preview" not in init_data
    assert "delivery" in init_data

    outbox = notification_service.get_test_outbox()
    email_entry = next(e for e in reversed(outbox["emails"]) if e["to_email"] == new_email)
    email_otp = email_entry["code"]
    assert len(email_otp) == 6

    # 4. Resend codes (clear cooldown map first if needed or sleep, but here first time resend for this email)
    resend_resp = client.post("/api/auth/register/resend", json={"email": new_email})
    assert resend_resp.status_code == 200
    resend_data = resend_resp.json()
    assert resend_data["status"] == "resent"
    assert "preview" not in resend_data
    outbox_after = notification_service.get_test_outbox()
    new_email_entry = next(e for e in reversed(outbox_after["emails"]) if e["to_email"] == new_email)
    new_email_otp = new_email_entry["code"]

    # 5. Verify with invalid OTP -> 400
    invalid_verify = client.post("/api/auth/register/verify", json={
        "email": new_email,
        "email_otp": "000000"
    })
    assert invalid_verify.status_code == 400

    # 6. Verify with valid OTP -> 200 & returns access_token
    valid_verify = client.post("/api/auth/register/verify", json={
        "email": new_email,
        "email_otp": new_email_otp
    })
    assert valid_verify.status_code == 200
    verify_data = valid_verify.json()
    assert verify_data["status"] == "verified"
    assert "access_token" in verify_data
    assert verify_data["user"]["email"] == new_email
    assert verify_data["user"]["name"] == "Officer Sharma"

    # 7. Check email again -> now exists: True
    res_check_again = client.post("/api/auth/check-email", json={"email": new_email})
    assert res_check_again.status_code == 200
    assert res_check_again.json()["exists"] is True


def test_auth_register_validation_errors():
    # 1. Invalid email
    resp1 = client.post("/api/auth/register/initiate", json={
        "name": "Test User",
        "email": "not-an-email",
        "phone": "+919876543210",
        "password": "validpassword123"
    })
    assert resp1.status_code == 400
    assert resp1.json()["code"] == "INVALID_EMAIL"

    # 2. Invalid phone (<10 digits)
    resp2 = client.post("/api/auth/register/initiate", json={
        "name": "Test User",
        "email": "valid@agency.gov",
        "phone": "123",
        "password": "validpassword123"
    })
    assert resp2.status_code == 400
    assert resp2.json()["code"] == "INVALID_PHONE"

    # 3. Short password (< 6 chars)
    resp3 = client.post("/api/auth/register/initiate", json={
        "name": "Test User",
        "email": "valid@agency.gov",
        "phone": "9876543210",
        "password": "123"
    })
    assert resp3.status_code == 400
    assert resp3.json()["code"] == "PASSWORD_TOO_SHORT"


def test_auth_resend_cooldown():
    from app.database import SessionLocal
    from app.models.user import User, UserVerification
    test_email = "cooldown_test@agency.gov"
    db = SessionLocal()
    try:
        db.query(User).filter(User.email == test_email).delete()
        db.query(UserVerification).filter(UserVerification.email == test_email).delete()
        db.commit()
    finally:
        db.close()

    # Initiate registration
    init_resp = client.post("/api/auth/register/initiate", json={
        "name": "Cooldown Tester",
        "email": test_email,
        "phone": "+919876543211",
        "password": "securepassword123"
    })
    assert init_resp.status_code == 200

    # First resend should succeed
    resend1 = client.post("/api/auth/register/resend", json={"email": test_email})
    assert resend1.status_code == 200
    assert resend1.json()["status"] == "resent"

    # Immediate second resend should trigger 429 Too Many Requests
    resend2 = client.post("/api/auth/register/resend", json={"email": test_email})
    assert resend2.status_code == 429
    assert resend2.json()["code"] == "COOLDOWN_ACTIVE"
    assert "cooldown_remaining" in resend2.json()


def test_auth_login_endpoints():
    # 1. Non-existent user -> 404 USER_NOT_FOUND
    resp_404 = client.post("/api/auth/login", json={
        "email": "ghost_agent@cyberscope.io",
        "password": "somepassword"
    })
    assert resp_404.status_code == 404
    assert resp_404.json()["code"] == "USER_NOT_FOUND"

    # 2. Demo investigator user valid login -> 200 authenticated
    resp_demo_ok = client.post("/api/auth/login", json={
        "email": "investigator@cyberscope.io",
        "password": "password123"
    })
    assert resp_demo_ok.status_code == 200
    data_demo = resp_demo_ok.json()
    assert data_demo["status"] == "authenticated"
    assert data_demo["token_type"] == "bearer"
    assert "access_token" in data_demo
    assert data_demo["user"]["email"] == "investigator@cyberscope.io"
    assert "password_hash" not in data_demo["user"]

    # 3. Demo investigator wrong password -> 401 INVALID_PASSWORD
    resp_demo_bad = client.post("/api/auth/login", json={
        "email": "investigator@cyberscope.io",
        "password": "wrongpassword"
    })
    assert resp_demo_bad.status_code == 401
    assert resp_demo_bad.json()["code"] == "INVALID_PASSWORD"

    # 4. Register new user, then login
    from app.database import SessionLocal
    from app.models.user import User, UserVerification
    user_email = "investigator_patil@cid.gov.in"
    db = SessionLocal()
    try:
        db.query(User).filter(User.email == user_email).delete()
        db.query(UserVerification).filter(UserVerification.email == user_email).delete()
        db.commit()
    finally:
        db.close()

    init_res = client.post("/api/auth/register/initiate", json={
        "name": "Inspector Patil",
        "email": user_email,
        "phone": "+91 98765 43212",
        "password": "mypassword456",
        "role": "Cyber Investigator",
        "organization": "CID Cyber Crime"
    })
    assert init_res.status_code == 200
    outbox = notification_service.get_test_outbox()
    email_entry = next(e for e in reversed(outbox["emails"]) if e["to_email"] == user_email)
    email_otp = email_entry["code"]

    verify_res = client.post("/api/auth/register/verify", json={
        "email": user_email,
        "email_otp": email_otp
    })
    assert verify_res.status_code == 200

    # Wrong password for registered user -> 401
    login_bad = client.post("/api/auth/login", json={
        "email": user_email,
        "password": "incorrect_password"
    })
    assert login_bad.status_code == 401
    assert login_bad.json()["code"] == "INVALID_PASSWORD"

    # Correct password for registered user -> 200
    login_ok = client.post("/api/auth/login", json={
        "email": user_email,
        "password": "mypassword456"
    })
    assert login_ok.status_code == 200
    login_data = login_ok.json()
    assert login_data["status"] == "authenticated"
    assert login_data["user"]["email"] == user_email
    assert login_data["user"]["name"] == "Inspector Patil"
    assert "password_hash" not in login_data["user"]
    token = login_data["access_token"]

    # Verify /api/auth/me using issued access token
    me_resp = client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert me_resp.status_code == 200
    assert me_resp.json()["user"]["email"] == user_email


def test_auth_user_model_and_password_hashing():
    from app.services.auth_service import hash_password, verify_password
    from app.models.user import User

    # Test PBKDF2 hashing & verification
    raw_pass = "superSecretPassword!123"
    hashed = hash_password(raw_pass)
    assert hashed.startswith("pbkdf2:sha256:100000$")
    assert verify_password(raw_pass, hashed) is True
    assert verify_password("wrongSecretPassword", hashed) is False
    assert verify_password("", hashed) is False
    assert verify_password(raw_pass, "") is False

    # Test User model attribute normalization
    user = User(
        email="  AGENT.SMITH@CYBERSCOPE.IO  ",
        password_hash=hashed,
        name="Agent Smith",
        phone=" 919876543219 ",
        role="Senior Analyst",
        organization="Intelligence Bureau"
    )
    assert user.email == "agent.smith@cyberscope.io"
    assert user.phone == "+919876543219"

    # Test to_dict() security
    user_dict = user.to_dict()
    assert "password_hash" not in user_dict
    assert user_dict["email"] == "agent.smith@cyberscope.io"
    assert user_dict["phone"] == "+919876543299" if user.phone == "+919876543299" else user_dict["phone"] == "+919876543219"
    assert user_dict["name"] == "Agent Smith"


def test_auth_brute_force_lockout():
    from app.database import SessionLocal
    from app.models.user import User, UserVerification
    test_email = "lockout_victim@agency.gov.in"
    db = SessionLocal()
    try:
        db.query(User).filter(User.email == test_email).delete()
        db.query(UserVerification).filter(UserVerification.email == test_email).delete()
        db.commit()
    finally:
        db.close()

    # Initiate
    init_res = client.post("/api/auth/register/initiate", json={
        "name": "Lockout Test Officer",
        "email": test_email,
        "phone": "+919876543299",
        "password": "securepassword123"
    })
    assert init_res.status_code == 200

    # 4 invalid attempts -> 400 INVALID_OTP with remaining_attempts
    for i in range(1, 5):
        fail_res = client.post("/api/auth/register/verify", json={
            "email": test_email,
            "email_otp": "000000"
        })
        assert fail_res.status_code == 400
        fail_data = fail_res.json()
        assert fail_data["code"] == "INVALID_OTP"
        assert fail_data["remaining_attempts"] == 5 - i

    # 5th invalid attempt -> 429 MAX_ATTEMPTS_EXCEEDED
    lockout_res = client.post("/api/auth/register/verify", json={
        "email": test_email,
        "email_otp": "000000"
    })
    assert lockout_res.status_code == 429
    assert lockout_res.json()["code"] == "MAX_ATTEMPTS_EXCEEDED"

    # 6th attempt -> verification has been purged from DB -> 400 VERIFICATION_NOT_FOUND
    subsequent_res = client.post("/api/auth/register/verify", json={
        "email": test_email,
        "email_otp": "000000"
    })
    assert subsequent_res.status_code == 400
    assert subsequent_res.json()["code"] == "VERIFICATION_NOT_FOUND"


def test_notification_service_email_content():
    notification_service.clear_test_outbox()
    res = notification_service.send_verification_email(
        to_email="inspector.gadget@police.in",
        recipient_name="Inspector Gadget",
        code="789012"
    )
    assert res["success"] is True
    outbox = notification_service.get_test_outbox()
    assert len(outbox["emails"]) == 1
    email = outbox["emails"][0]
    assert email["to_email"] == "inspector.gadget@police.in"
    assert email["code"] == "789012"
    assert "CYBERSCOPE" in email["html_content"]
    assert "789012" in email["html_content"]
    assert "10 minutes" in email["html_content"]
    assert "789012" in email["plain_text"]
    assert "10 minutes" in email["plain_text"]


def test_notification_service_sms_mock():
    notification_service.clear_test_outbox()
    res = notification_service.send_verification_sms(
        to_phone="+919876543210",
        code="654321"
    )
    assert res["success"] is True
    outbox = notification_service.get_test_outbox()
    assert len(outbox["sms"]) == 1
    sms = outbox["sms"][0]
    assert sms["to_phone"] == "+919876543210"
    assert sms["code"] == "654321"
    assert "654321" in sms["message"]
    assert "10 minutes" in sms["message"]


def test_notification_service_sms_twilio(monkeypatch):
    import httpx
    settings.SMS_PROVIDER = "twilio"
    settings.TWILIO_ACCOUNT_SID = "ACtest123"
    settings.TWILIO_AUTH_TOKEN = "authtoken123"
    settings.TWILIO_FROM_NUMBER = "+15551234567"
    setattr(settings, "_FORCE_LIVE_SMS", True)

    def mock_post(url, **kwargs):
        class MockResp:
            status_code = 201
            text = '{"sid": "SM123"}'
        return MockResp()

    monkeypatch.setattr(httpx.Client, "post", lambda self, url, **kwargs: mock_post(url, **kwargs))

    try:
        res = notification_service.send_verification_sms("+919876543210", "112233")
        assert res["success"] is True
        assert res["provider"] == "twilio"
    finally:
        setattr(settings, "_FORCE_LIVE_SMS", False)
        settings.SMS_PROVIDER = "twilio"
        settings.TWILIO_ACCOUNT_SID = ""
        settings.TWILIO_AUTH_TOKEN = ""
        settings.TWILIO_FROM_NUMBER = ""


def test_notification_service_sms_fast2sms(monkeypatch):
    import httpx
    settings.SMS_PROVIDER = "fast2sms"
    settings.FAST2SMS_API_KEY = "testkey123"
    setattr(settings, "_FORCE_LIVE_SMS", True)

    def mock_post(url, **kwargs):
        class MockResp:
            status_code = 200
            text = '{"return": true, "message": ["SMS sent successfully."]}'
            def json(self):
                return {"return": True, "message": ["SMS sent successfully."]}
        return MockResp()

    monkeypatch.setattr(httpx.Client, "post", lambda self, url, **kwargs: mock_post(url, **kwargs))

    try:
        res = notification_service.send_verification_sms("+919876543210", "445566")
        assert res["success"] is True
        assert res["provider"] == "fast2sms"
    finally:
        setattr(settings, "_FORCE_LIVE_SMS", False)
        settings.SMS_PROVIDER = "twilio"
        settings.FAST2SMS_API_KEY = ""


def test_notification_service_sms_webhook(monkeypatch):
    import httpx
    settings.SMS_PROVIDER = "webhook"
    settings.SMS_WEBHOOK_URL = "https://hooks.cyberscope.io/sms"
    setattr(settings, "_FORCE_LIVE_SMS", True)

    def mock_post(url, **kwargs):
        class MockResp:
            status_code = 200
            text = '{"delivered": true}'
        return MockResp()

    monkeypatch.setattr(httpx.Client, "post", lambda self, url, **kwargs: mock_post(url, **kwargs))

    try:
        res = notification_service.send_verification_sms("+919876543210", "778899")
        assert res["success"] is True
        assert res["provider"] == "webhook"
    finally:
        setattr(settings, "_FORCE_LIVE_SMS", False)
        settings.SMS_PROVIDER = "twilio"
        settings.SMS_WEBHOOK_URL = ""


def test_notification_service_smtp_dispatch(monkeypatch):
    import smtplib
    settings.SMTP_HOST = "smtp.cyberscope.io"
    settings.SMTP_PORT = 587
    settings.SMTP_USER = "smtp_user"
    settings.SMTP_PASSWORD = "smtp_password"
    settings.SMTP_USE_TLS = True
    settings.SMTP_USE_SSL = False
    setattr(settings, "_FORCE_LIVE_SMTP", True)

    class MockSMTP:
        def __init__(self, host, port, timeout):
            self.host = host
            self.port = port
            self.timeout = timeout
            self.tls_started = False
            self.logged_in = False
            self.messages_sent = []

        def starttls(self):
            self.tls_started = True

        def login(self, user, password):
            self.logged_in = True

        def send_message(self, msg):
            self.messages_sent.append(msg)

        def quit(self):
            pass

    mock_smtp_inst = None
    def mock_smtp_constructor(host, port, timeout):
        nonlocal mock_smtp_inst
        mock_smtp_inst = MockSMTP(host, port, timeout)
        return mock_smtp_inst

    monkeypatch.setattr(smtplib, "SMTP", mock_smtp_constructor)

    try:
        res = notification_service.send_verification_email(
            to_email="agent.davis@fbi.gov",
            recipient_name="Agent Davis",
            code="998877"
        )
        assert res["success"] is True
        assert res["provider"] == "smtp"
        assert mock_smtp_inst is not None
        assert mock_smtp_inst.tls_started is True
        assert mock_smtp_inst.logged_in is True
        assert len(mock_smtp_inst.messages_sent) == 1
    finally:
        setattr(settings, "_FORCE_LIVE_SMTP", False)
        settings.SMTP_HOST = ""
        settings.SMTP_USER = ""
        settings.SMTP_PASSWORD = ""


