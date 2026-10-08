import re
import hmac
import secrets
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, Optional
from pydantic import BaseModel, Field
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session

from app.config import settings
from app.database import get_db
from app.models.user import User, UserVerification
from app.services.auth_service import (
    auth_service,
    get_current_user,
    hash_password,
    verify_password,
    create_access_token,
    DEMO_USER,
)
from app.services.notification_service import notification_service
from app.utils.normalization import normalize_phone

router = APIRouter(prefix="/auth", tags=["Authentication"])

EMAIL_REGEX = re.compile(r"^[\w\.\+\-]+@[a-zA-Z0-9\.\-]+\.[a-zA-Z]{2,}$")
_last_resend_timestamps: Dict[str, float] = {}


# ---------------------------------------------------------
# Request & Response Schemas
# ---------------------------------------------------------

class TokenVerifyRequest(BaseModel):
    access_token: str = Field(..., description="Supabase or local JWT access token to verify")


class AuthConfigResponse(BaseModel):
    supabase_url: str
    supabase_anon_key: str
    configured: bool
    auth_required: bool
    demo_account: Dict[str, str]


class CheckEmailRequest(BaseModel):
    email: str = Field(..., description="Email address to check")


class RegisterInitiateRequest(BaseModel):
    name: str = Field(..., min_length=1, description="Full name")
    email: str = Field(..., description="Email address")
    phone: str = Field(..., description="Phone number")
    password: str = Field(..., min_length=1, description="Password (at least 6 characters)")
    role: Optional[str] = Field("Investigator", description="Role (e.g., Investigator, Analyst)")
    organization: Optional[str] = Field("", description="Agency or organization name")


class RegisterVerifyRequest(BaseModel):
    email: str = Field(..., description="Email address")
    email_otp: str = Field(..., description="6-digit email verification code")


class ResendOTPRequest(BaseModel):
    email: str = Field(..., description="Email address")


class LoginRequest(BaseModel):
    email: str = Field(..., description="Email address")
    password: str = Field(..., description="Password")


# ---------------------------------------------------------
# Authentication & Verification Endpoints
# ---------------------------------------------------------

@router.post("/check-email")
def check_email(payload: CheckEmailRequest, db: Session = Depends(get_db)):
    """
    Checks if a user with this email already exists in the users table.
    """
    normalized_email = payload.email.strip().lower()
    if not normalized_email:
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={"detail": "Email address cannot be empty.", "code": "INVALID_EMAIL"}
        )

    user = db.query(User).filter(User.email == normalized_email).first()
    exists = user is not None
    return {
        "exists": exists,
        "message": "An account with this email already exists." if exists else "Email available."
    }


@router.post("/register/initiate")
def register_initiate(payload: RegisterInitiateRequest, db: Session = Depends(get_db)):
    """
    Validates registration input, checks email uniqueness,
    generates 6-digit email OTP, stores pending verification,
    and dispatches verification code to email.
    """
    normalized_email = payload.email.strip().lower()
    if not EMAIL_REGEX.match(normalized_email):
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={"detail": "Invalid email address format.", "code": "INVALID_EMAIL"}
        )

    cleaned_phone = re.sub(r"[\s\-\(\)\.]", "", payload.phone.strip())
    digits_only = re.sub(r"\D", "", cleaned_phone)
    if len(digits_only) < 10:
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={"detail": "Invalid phone number format. Must contain at least 10 digits.", "code": "INVALID_PHONE"}
        )

    if len(payload.password) < 6:
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={"detail": "Password must be at least 6 characters long.", "code": "PASSWORD_TOO_SHORT"}
        )

    if not payload.name.strip():
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={"detail": "Name is required.", "code": "INVALID_NAME"}
        )

    # Check if email exists in users table
    existing_user = db.query(User).filter(User.email == normalized_email).first()
    if existing_user:
        return JSONResponse(
            status_code=status.HTTP_409_CONFLICT,
            content={
                "detail": "An account with this email already exists in the database. Please sign in instead.",
                "code": "ACCOUNT_EXISTS"
            }
        )

    # Clean up previous pending verifications for this email
    db.query(UserVerification).filter(UserVerification.email == normalized_email).delete()

    normalized_phone = normalize_phone(payload.phone)
    email_otp = f"{secrets.randbelow(900000) + 100000:06d}"
    expires_at = datetime.now(timezone.utc) + timedelta(minutes=10)

    verification = UserVerification(
        email=normalized_email,
        phone=normalized_phone,
        name=payload.name.strip(),
        password_hash=hash_password(payload.password),
        role=payload.role.strip() if payload.role else "Investigator",
        organization=payload.organization.strip() if payload.organization else "",
        email_otp=email_otp,
        expires_at=expires_at,
        created_at=datetime.now(timezone.utc),
        attempts=0
    )
    db.add(verification)
    db.commit()

    email_result = notification_service.send_verification_email(
        to_email=normalized_email,
        recipient_name=payload.name,
        code=email_otp
    )

    return {
        "status": "verification_initiated",
        "message": "Verification code has been dispatched to your email.",
        "email": normalized_email,
        "delivery": {
            "email": email_result
        }
    }


@router.post("/register/verify")
def register_verify(payload: RegisterVerifyRequest, db: Session = Depends(get_db)):
    """
    Validates email OTP code, creates verified user record,
    removes pending verification, and issues an access token.
    Enforces brute-force lockout after 5 failed verification attempts.
    """
    normalized_email = payload.email.strip().lower()
    verification = db.query(UserVerification).filter(UserVerification.email == normalized_email).first()

    if not verification:
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={
                "detail": "No pending verification found for this email. Please initiate registration first.",
                "code": "VERIFICATION_NOT_FOUND"
            }
        )

    # Brute force lockout check if already exceeded
    if verification.attempts >= 5:
        db.delete(verification)
        db.commit()
        return JSONResponse(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            content={
                "detail": "Too many failed attempts. Verification codes invalidated. Please request new codes.",
                "code": "MAX_ATTEMPTS_EXCEEDED"
            }
        )

    # Check expiry
    now = datetime.now(timezone.utc)
    is_expired = False
    if verification.expires_at:
        if verification.expires_at.tzinfo is None:
            is_expired = verification.expires_at < now.replace(tzinfo=None)
        else:
            is_expired = verification.expires_at < now

    if is_expired:
        db.delete(verification)
        db.commit()
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={
                "detail": "Verification codes have expired. Please request new codes.",
                "code": "OTP_EXPIRED"
            }
        )

    # Validate OTP using constant-time comparison to prevent timing attacks
    email_match = hmac.compare_digest(payload.email_otp.strip(), verification.email_otp)

    if not email_match:
        verification.attempts += 1
        db.commit()
        if verification.attempts >= 5:
            db.delete(verification)
            db.commit()
            return JSONResponse(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                content={
                    "detail": "Too many failed attempts. Verification codes invalidated. Please request new codes.",
                    "code": "MAX_ATTEMPTS_EXCEEDED"
                }
            )
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={
                "detail": "Invalid email verification code.",
                "code": "INVALID_OTP",
                "remaining_attempts": 5 - verification.attempts
            }
        )

    # Create new User in database
    new_user = User(
        email=verification.email,
        phone=verification.phone,
        name=verification.name,
        password_hash=verification.password_hash,
        role=verification.role,
        organization=verification.organization,
        is_verified_email=True,
        is_verified_phone=True,
        is_active=True
    )
    db.add(new_user)
    db.delete(verification)
    db.commit()
    db.refresh(new_user)

    token = create_access_token(new_user.to_dict())

    return {
        "status": "verified",
        "message": "Account successfully verified and created in database.",
        "user": new_user.to_dict(),
        "access_token": token,
        "token_type": "bearer"
    }


@router.post("/register/resend")
def register_resend(payload: ResendOTPRequest, db: Session = Depends(get_db)):
    """
    Generates fresh OTPs with a 60s rate-limit cooldown and dispatches them
    via notification service without returning plaintext codes in response.
    """
    normalized_email = payload.email.strip().lower()
    verification = db.query(UserVerification).filter(UserVerification.email == normalized_email).first()

    if not verification:
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={
                "detail": "No pending verification found for this email. Please initiate registration first.",
                "code": "VERIFICATION_NOT_FOUND"
            }
        )

    now_ts = datetime.now(timezone.utc).timestamp()
    last_ts = _last_resend_timestamps.get(normalized_email)
    if last_ts is not None and (now_ts - last_ts) < 60:
        remaining = int(60 - (now_ts - last_ts))
        return JSONResponse(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            content={
                "detail": f"Please wait {remaining} seconds before requesting new verification codes.",
                "cooldown_remaining": remaining,
                "code": "COOLDOWN_ACTIVE"
            }
        )

    _last_resend_timestamps[normalized_email] = now_ts

    new_email_otp = f"{secrets.randbelow(900000) + 100000:06d}"

    verification.email_otp = new_email_otp
    verification.expires_at = datetime.now(timezone.utc) + timedelta(minutes=10)
    verification.created_at = datetime.now(timezone.utc)
    verification.attempts = 0
    db.commit()

    email_result = notification_service.send_verification_email(
        to_email=verification.email,
        recipient_name=verification.name,
        code=new_email_otp
    )

    return {
        "status": "resent",
        "message": "Fresh verification codes have been generated and sent.",
        "email": verification.email,
        "delivery": {
            "email": email_result
        }
    }


@router.post("/login")
def login(payload: LoginRequest, db: Session = Depends(get_db)):
    """
    Authenticates an investigator via email and password.
    Falls back to recognizing the demo account if not yet created in the database.
    """
    normalized_email = payload.email.strip().lower()
    user = db.query(User).filter(User.email == normalized_email).first()

    if not user:
        if normalized_email == "investigator@cyberscope.io":
            if payload.password != "password123":
                return JSONResponse(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    content={
                        "detail": "Invalid password. Please check your credentials.",
                        "code": "INVALID_PASSWORD"
                    }
                )
            # Auto-seed demo investigator
            user = User(
                email="investigator@cyberscope.io",
                password_hash=hash_password("password123"),
                name="Investigator Demo",
                phone="+919876543210",
                role="Investigator",
                organization="TetraByte Cyber Defense",
                is_verified_email=True,
                is_verified_phone=True,
                is_active=True
            )
            db.add(user)
            db.commit()
            db.refresh(user)
        else:
            return JSONResponse(
                status_code=status.HTTP_404_NOT_FOUND,
                content={
                    "detail": "No account found with this email address. Please register a new account.",
                    "code": "USER_NOT_FOUND"
                }
            )
    else:
        is_valid = verify_password(payload.password, user.password_hash)
        if not is_valid and user.email == "investigator@cyberscope.io" and payload.password == "password123":
            is_valid = True

        if not is_valid:
            return JSONResponse(
                status_code=status.HTTP_401_UNAUTHORIZED,
                content={
                    "detail": "Invalid password. Please check your credentials.",
                    "code": "INVALID_PASSWORD"
                }
            )

    token = create_access_token(user.to_dict())

    return {
        "status": "authenticated",
        "user": user.to_dict(),
        "access_token": token,
        "token_type": "bearer"
    }


# ---------------------------------------------------------
# Existing Profile & Token Verification Endpoints
# ---------------------------------------------------------

@router.get("/config", response_model=AuthConfigResponse)
def get_auth_config():
    """
    Returns public Supabase client configuration parameters.
    Allows frontend clients to dynamically initialize Supabase without
    baking credentials directly into static builds.
    """
    return {
        "supabase_url": settings.SUPABASE_URL,
        "supabase_anon_key": settings.SUPABASE_ANON_KEY,
        "configured": auth_service.is_configured(),
        "auth_required": settings.REQUIRE_AUTH,
        "demo_account": {
            "email": "investigator@cyberscope.io",
            "password": "password123",
            "name": "Investigator Demo",
            "role": "Investigator"
        }
    }


@router.get("/me")
def get_authenticated_user(current_user: Dict[str, Any] = Depends(get_current_user)):
    """
    Returns the current authenticated investigator's profile.
    Extracts identity from Supabase or local JWT access token.
    """
    return {
        "status": "authenticated",
        "user": current_user
    }


@router.post("/verify")
def verify_access_token(payload: TokenVerifyRequest):
    """
    Verifies an access token and returns decoded investigator claims.
    """
    try:
        user_info = auth_service.verify_token(payload.access_token)
        return {
            "valid": True,
            "user": user_info
        }
    except HTTPException as e:
        raise e
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Token verification failed: {str(e)}"
        )
