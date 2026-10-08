from sqlalchemy import Column, Integer, String, DateTime, JSON, ForeignKey
from datetime import datetime, timezone
from app.database import Base


class Indicator(Base):
    __tablename__ = "indicators"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    case_id = Column(Integer, ForeignKey("cases.id", ondelete="CASCADE"), nullable=True, index=True)
    entity_id = Column(Integer, ForeignKey("entities.id", ondelete="CASCADE"), nullable=True, index=True)
    indicator_type = Column(String(100), nullable=False, index=True)
    # PHISHING_URL, MULE_ACCOUNT, SPOOFED_PHONE, SHARED_INFRASTRUCTURE, BURST_VELOCITY, CIRCULAR_FLOW
    severity = Column(String(50), default="HIGH", nullable=False)
    description = Column(String(1024), nullable=False)
    detected_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    meta_data = Column(JSON, default=dict)

    def to_dict(self):
        return {
            "id": self.id,
            "case_id": self.case_id,
            "entity_id": self.entity_id,
            "indicator_type": self.indicator_type,
            "severity": self.severity,
            "description": self.description,
            "detected_at": self.detected_at.isoformat() if self.detected_at else None,
            "metadata": self.meta_data or {},
        }
