from sqlalchemy import Column, Integer, String, Float, DateTime, JSON
from datetime import datetime, timezone
from app.database import Base


class Campaign(Base):
    __tablename__ = "campaigns"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    campaign_id = Column(String(64), unique=True, nullable=False, index=True)
    name = Column(String(255), nullable=False)
    description = Column(String(1024), default="")
    risk_score = Column(Float, default=0.0, nullable=False)
    case_count = Column(Integer, default=0, nullable=False)
    entity_count = Column(Integer, default=0, nullable=False)
    status = Column(String(50), default="ACTIVE", nullable=False)  # ACTIVE, MONITORED, DISRUPTED
    first_seen = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    last_seen = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    shared_indicators = Column(JSON, default=dict)
    meta_data = Column(JSON, default=dict)

    def to_dict(self):
        return {
            "id": self.id,
            "campaign_id": self.campaign_id,
            "name": self.name,
            "description": self.description,
            "risk_score": round(self.risk_score, 1),
            "case_count": self.case_count,
            "entity_count": self.entity_count,
            "status": self.status,
            "first_seen": self.first_seen.isoformat() if self.first_seen else None,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
            "shared_indicators": self.shared_indicators or {},
            "code": self.campaign_id,
            "shared_entity_count": self.entity_count,
            "severity": "CRITICAL" if self.risk_score >= 80 else ("HIGH" if self.risk_score >= 60 else "MEDIUM"),
            "metadata": self.meta_data or {},
        }
