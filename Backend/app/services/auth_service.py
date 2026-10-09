import hashlib
import hmac
import logging
import secrets
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, Optional
import jwt
from fastapi import Request, HTTPException, status, Depends
from sqlalchemy.orm import Session
from app.config import settings
from app.database import SessionLocal, get_db
from app.models.user import User

logger = logging.getLogger("cyberscope.auth")

PBKDF2_ITERATIONS = 100_000


def hash_password(password: str) -> str:
    """
    Hash a password using secure PBKDF2-HMAC-SHA256 with a random salt.
    Format: pbkdf2:sha256:<iterations>$<salt_hex>$<hash_hex>
    """
    if not password:
        raise ValueError("Password cannot be empty")
    salt = secrets.token_hex(16)
    key = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt.encode("utf-8"),
        PBKDF2_ITERATIONS,
    )
    return f"pbkdf2:sha256:{PBKDF2_ITERATIONS}${salt}${key.hex()}"


def verify_password(password: str, hashed: str) -> bool:
    """
    Verify a plaintext password against a PBKDF2-HMAC-SHA256 hashed string.
    """
    if not password or not hashed:
        return False
    try:
        if hashed.startswith("pbkdf2:sha256:"):
            parts = hashed.split("$")
            if len(parts) != 3:
                return False
            iter_spec, salt, target_hash = parts
            iterations = int(iter_spec.split(":")[-1])
            derived = hashlib.pbkdf2_hmac(
                "sha256",
                password.encode("utf-8"),
                salt.encode("utf-8"),
                iterations,
            )
            return hmac.compare_digest(derived.hex(), target_hash)
        elif "$" in hashed:
            salt, target_hash = hashed.split("$", 1)
            derived = hashlib.pbkdf2_hmac(
                "sha256",
                password.encode("utf-8"),
                salt.encode("utf-8"),
                PBKDF2_ITERATIONS,
            )
            return hmac.compare_digest(derived.hex(), target_hash)
        return False
    except Exception as e:
        logger.warning(f"Password verification error: {e}")
        return False


def create_access_token(user_dict: dict, expires_delta: Optional[timedelta] = None) -> str:
    """
    Creates a signed JWT access token containing investigator identity claims.
    """
    now = datetime.now(timezone.utc)
    expire = now + (expires_delta if expires_delta else timedelta(minutes=60))

    payload = {
        "sub": str(user_dict.get("id", "")),
        "id": user_dict.get("id"),
        "email": user_dict.get("email", ""),
        "exp": expire,
        "iat": now,
        "jti": secrets.token_hex(16),
    }

    return jwt.encode(payload, settings.JWT_SECRET, algorithm="HS256")


class SupabaseAuthService:
    """
    Authentication & Token Verification Service.
    Handles JWT decoding, verification with JWT_SECRET, and loading user from database.
    """

    def extract_token_from_header(self, request: Request) -> Optional[str]:
        auth_header = request.headers.get("Authorization")
        if not auth_header:
            return None
        parts = auth_header.split()
        if len(parts) == 2 and parts[0].lower() == "bearer":
            return parts[1]
        return None

    def verify_token(self, token: str, db: Optional[Session] = None) -> Dict[str, Any]:
        """
        Verifies a JWT access token:
        1. Decodes HS256 with JWT_SECRET and required claims: exp, iat, sub.
        2. Loads active user from DB by sub/email and returns user dict.
        """
        if not token:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Empty authentication token",
                headers={"WWW-Authenticate": "Bearer"}
            )

        try:
            payload = jwt.decode(
                token,
                settings.JWT_SECRET,
                algorithms=["HS256"],
                options={"require": ["exp", "iat", "sub"]}
            )
        except jwt.ExpiredSignatureError:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Authentication token has expired",
                headers={"WWW-Authenticate": "Bearer"}
            )
        except jwt.InvalidTokenError as e:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"Invalid authentication token: {e}",
                headers={"WWW-Authenticate": "Bearer"}
            )

        sub = payload.get("sub")
        close_db = False
        if db is None:
            db = SessionLocal()
            close_db = True

        try:
            user = None
            if sub:
                if str(sub).isdigit():
                    user = db.query(User).filter(User.id == int(sub)).first()
                if not user:
                    user = db.query(User).filter(User.email == str(sub)).first()
            if not user and payload.get("email"):
                user = db.query(User).filter(User.email == payload.get("email")).first()

            if not user or not getattr(user, "is_active", True):
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="User inactive or not found",
                    headers={"WWW-Authenticate": "Bearer"}
                )
            return user.to_dict()
        finally:
            if close_db:
                db.close()

    def is_configured(self) -> bool:
        return bool(settings.JWT_SECRET)

    def get_current_user(self, request: Request, db: Optional[Session] = None) -> Dict[str, Any]:
        """
        FastAPI dependency to extract and verify the current authenticated user.
        Raises 401 if missing, invalid, or expired.
        """
        token = self.extract_token_from_header(request)
        if not token:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Authentication required. Please provide a valid Bearer token.",
                headers={"WWW-Authenticate": "Bearer"}
            )
        return self.verify_token(token, db=db)


auth_service = SupabaseAuthService()


def get_current_user(request: Request, db: Session = Depends(get_db)) -> Dict[str, Any]:
    """FastAPI dependency for accessing authenticated user."""
    return auth_service.get_current_user(request, db=db)

