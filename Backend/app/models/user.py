from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, Boolean, DateTime
from sqlalchemy.orm import validates
from app.database import Base
from app.models.base import TimestampMixin
from app.utils.normalization import normalize_phone


class User(Base, TimestampMixin):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    email = Column(String(255), unique=True, index=True, nullable=False)
    password_hash = Column(String(255), nullable=False)
    name = Column(String(255), nullable=False)
    phone = Column(String(64), index=True, nullable=False)
    role = Column(String(50), default="Investigator", nullable=False)
    organization = Column(String(255), default="", nullable=False)
    is_verified_email = Column(Boolean, default=False, nullable=False)
    is_verified_phone = Column(Boolean, default=True, nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)

    @validates("email")
    def validate_email(self, key, value):
        if value:
            return str(value).strip().lower()
        return value

    @validates("phone")
    def validate_phone(self, key, value):
        if value:
            return normalize_phone(str(value))
        return value

    def to_dict(self):
        return {
            "id": self.id,
            "email": self.email,
            "name": self.name,
            "phone": self.phone,
            "role": self.role,
            "organization": self.organization,
            "is_verified_email": self.is_verified_email,
            "is_verified_phone": self.is_verified_phone,
            "is_active": self.is_active,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }


class UserVerification(Base):
    __tablename__ = "user_verifications"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    email = Column(String(255), index=True, nullable=False)
    phone = Column(String(64), nullable=False)
    name = Column(String(255), nullable=False)
    password_hash = Column(String(255), nullable=False)
    role = Column(String(50), default="Investigator", nullable=False)
    organization = Column(String(255), default="", nullable=False)
    email_otp = Column(String(10), nullable=False)
    expires_at = Column(DateTime, nullable=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    attempts = Column(Integer, default=0, nullable=False)

    @validates("email")
    def validate_email(self, key, value):
        if value:
            return str(value).strip().lower()
        return value

    @validates("phone")
    def validate_phone(self, key, value):
        if value:
            return normalize_phone(str(value))
        return value

    def to_dict(self):
        return {
            "id": self.id,
            "email": self.email,
            "phone": self.phone,
            "name": self.name,
            "role": self.role,
            "organization": self.organization,
            "email_otp": self.email_otp,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "attempts": self.attempts,
        }
