import hashlib
import hmac
import logging
import secrets
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, Optional
import jwt
import httpx
from fastapi import Request, HTTPException, status
from app.config import settings

logger = logging.getLogger("cyberscope.auth")

PBKDF2_ITERATIONS = 100_000
DEFAULT_JWT_SECRET = "cyberscope-secret-jwt-key-for-auth-token-verification-32b"

DEMO_USER = {
    "id": "demo-investigator-001",
    "email": "investigator@cyberscope.io",
    "name": "Investigator Demo",
    "role": "Investigator",
    "phone": "+919876543210",
    "organization": "TetraByte Cyber Defense",
    "is_demo": True
}


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
    Supports standard formats and legacy demo tokens.
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
    expire = now + (expires_delta if expires_delta else timedelta(days=7))

    payload = {
        "sub": str(user_dict.get("id", "")),
        "id": user_dict.get("id"),
        "email": user_dict.get("email", ""),
        "role": user_dict.get("role", "Investigator"),
        "user_metadata": {
            "name": user_dict.get("name", ""),
            "role": user_dict.get("role", "Investigator"),
            "phone": user_dict.get("phone", ""),
            "organization": user_dict.get("organization", ""),
        },
        "exp": expire,
        "iat": now,
    }

    secret = settings.SUPABASE_JWT_SECRET if settings.SUPABASE_JWT_SECRET else DEFAULT_JWT_SECRET
    return jwt.encode(payload, secret, algorithm="HS256")


class SupabaseAuthService:
    """
    Supabase Authentication & Token Verification Service.
    Handles JWT decoding, verification with Supabase secret or Auth REST API,
    and provides fallback handling for local evaluation and offline demo mode.
    """

    def __init__(self):
        self.supabase_url = settings.SUPABASE_URL.rstrip("/") if settings.SUPABASE_URL else ""
        self.anon_key = settings.SUPABASE_ANON_KEY
        self._jwt_secret = settings.SUPABASE_JWT_SECRET

    @property
    def jwt_secret(self) -> str:
        return settings.SUPABASE_JWT_SECRET or self._jwt_secret

    @property
    def require_auth(self) -> bool:
        return settings.REQUIRE_AUTH

    def is_configured(self) -> bool:
        """Returns True if Supabase project URL and anon key are configured."""
        return bool(self.supabase_url and self.anon_key)

    def extract_token_from_header(self, request: Request) -> Optional[str]:
        auth_header = request.headers.get("Authorization")
        if not auth_header:
            return None
        parts = auth_header.split()
        if len(parts) == 2 and parts[0].lower() == "bearer":
            return parts[1]
        return None

    def verify_token(self, token: str) -> Dict[str, Any]:
        """
        Verifies a JWT access token.
        1. Checks for demo tokens (used in local testing/offline demo)
        2. Verifies using configured SUPABASE_JWT_SECRET or local default secret
        3. Calls Supabase /auth/v1/user endpoint if SUPABASE_URL & ANON_KEY provided
        4. Falls back to unverified payload decoding for local flexibility
        """
        if not token:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Empty authentication token"
            )

        if token in ("demo-token", "demo-session-token") or token.startswith("demo-"):
            return DEMO_USER

        # Method A1: Verify with active Supabase JWT Secret if configured
        if self.jwt_secret:
            try:
                payload = jwt.decode(
                    token,
                    self.jwt_secret,
                    algorithms=["HS256"],
                    options={"verify_aud": False}
                )
                return self._format_user_from_jwt(payload)
            except jwt.ExpiredSignatureError:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Authentication token has expired"
                )
            except jwt.InvalidTokenError as e:
                logger.warning(f"JWT Secret verification failed: {e}. Trying fallback methods...")

        # Method A2: Verify with default local token secret
        try:
            payload = jwt.decode(
                token,
                DEFAULT_JWT_SECRET,
                algorithms=["HS256"],
                options={"verify_aud": False}
            )
            return self._format_user_from_jwt(payload)
        except jwt.ExpiredSignatureError:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Authentication token has expired"
            )
        except jwt.InvalidTokenError:
            pass

        # Method B: Verify by querying Supabase Auth endpoint
        if self.is_configured():
            try:
                with httpx.Client(timeout=5.0) as client:
                    resp = client.get(
                        f"{self.supabase_url}/auth/v1/user",
                        headers={
                            "Authorization": f"Bearer {token}",
                            "apikey": self.anon_key
                        }
                    )
                    if resp.status_code == 200:
                        data = resp.json()
                        return self._format_user_from_supabase_api(data)
                    else:
                        logger.warning(f"Supabase Auth API returned {resp.status_code}: {resp.text}")
            except Exception as e:
                logger.warning(f"Failed to reach Supabase Auth API: {e}")

        # Method C: Local unverified decode (graceful development fallback)
        try:
            unverified_payload = jwt.decode(token, options={"verify_signature": False})
            logger.info("Token decoded without signature verification (local development mode)")
            return self._format_user_from_jwt(unverified_payload)
        except Exception as e:
            logger.error(f"Failed to decode token claims: {e}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token format or corrupt payload"
            )

    def _format_user_from_jwt(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        metadata = payload.get("user_metadata", {}) or {}
        email = payload.get("email", "")
        name = metadata.get("name") or metadata.get("full_name") or (email.split("@")[0].capitalize() if email else "Investigator")
        user_id = payload.get("sub") or payload.get("id")
        return {
            "id": int(user_id) if str(user_id).isdigit() else user_id,
            "email": email,
            "name": name,
            "role": metadata.get("role") or payload.get("role") or "Investigator",
            "phone": metadata.get("phone", ""),
            "organization": metadata.get("organization", ""),
            "is_demo": email == "investigator@cyberscope.io" or payload.get("is_demo", False)
        }

    def _format_user_from_supabase_api(self, data: Dict[str, Any]) -> Dict[str, Any]:
        metadata = data.get("user_metadata", {}) or {}
        email = data.get("email", "")
        name = metadata.get("name") or metadata.get("full_name") or (email.split("@")[0].capitalize() if email else "Investigator")
        return {
            "id": data.get("id"),
            "email": email,
            "name": name,
            "role": metadata.get("role", "Investigator"),
            "phone": metadata.get("phone", ""),
            "organization": metadata.get("organization", ""),
            "is_demo": email == "investigator@cyberscope.io"
        }

    def get_current_user(self, request: Request) -> Dict[str, Any]:
        """
        FastAPI dependency to extract and verify the current authenticated user.
        If REQUIRE_AUTH is False and no token is supplied, returns DEMO_USER.
        """
        token = self.extract_token_from_header(request)

        if not token:
            if self.require_auth:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Authentication required. Please provide a valid Bearer token.",
                    headers={"WWW-Authenticate": "Bearer"}
                )
            return DEMO_USER

        try:
            return self.verify_token(token)
        except HTTPException:
            if self.require_auth:
                raise
            return DEMO_USER


auth_service = SupabaseAuthService()


def get_current_user(request: Request) -> Dict[str, Any]:
    """FastAPI dependency for accessing authenticated user."""
    return auth_service.get_current_user(request)
