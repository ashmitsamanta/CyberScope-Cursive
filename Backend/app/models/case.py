from sqlalchemy import Column, Integer, String, Float, DateTime, Text, JSON, ForeignKey
from datetime import datetime, timezone
from app.database import Base
from app.models.base import TimestampMixin


class Case(Base, TimestampMixin):
    __tablename__ = "cases"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    case_number = Column(String(64), unique=True, nullable=False, index=True)
    title = Column(String(255), nullable=False)
    description = Column(Text, default="")
    status = Column(String(50), default="NEW", nullable=False, index=True)
    # NEW, INVESTIGATING, ESCALATED, RESOLVED, FALSE_POSITIVE
    severity = Column(String(50), default="MEDIUM", nullable=False, index=True)
    # LOW, MEDIUM, HIGH, CRITICAL
    source = Column(String(100), default="SYSTEM_INGESTION", nullable=False)
    risk_score = Column(Float, default=0.0, nullable=False, index=True)
    campaign_id = Column(Integer, ForeignKey("campaigns.id", ondelete="SET NULL"), nullable=True, index=True)
    meta_data = Column(JSON, default=dict)

    def to_dict(self):
        return {
            "id": self.id,
            "case_number": self.case_number,
            "title": self.title,
            "description": self.description,
            "status": self.status,
            "severity": self.severity,
            "source": self.source,
            "risk_score": round(self.risk_score, 1),
            "campaign_id": self.campaign_id,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
            "metadata": self.meta_data or {},
        }
