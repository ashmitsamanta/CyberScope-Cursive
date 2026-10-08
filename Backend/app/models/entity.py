from sqlalchemy import Column, Integer, String, Float, DateTime, JSON, Index
from datetime import datetime, timezone
from app.database import Base


class Entity(Base):
    __tablename__ = "entities"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    entity_type = Column(String(50), nullable=False, index=True)
    # PERSON, PHONE, EMAIL, URL, DOMAIN, UPI_ID, BANK_ACCOUNT, DEVICE, IP_ADDRESS, MERCHANT, ORGANIZATION, CASE
    value = Column(String(512), nullable=False)
    normalized_value = Column(String(512), nullable=False, index=True)
    risk_score = Column(Float, default=0.0, nullable=False)
    first_seen = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    last_seen = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    meta_data = Column(JSON, default=dict)

    __table_args__ = (
        Index("idx_entity_type_norm", "entity_type", "normalized_value", unique=True),
    )

    def to_dict(self):
        return {
            "id": self.id,
            "entity_type": self.entity_type,
            "value": self.value,
            "normalized_value": self.normalized_value,
            "risk_score": round(self.risk_score, 1),
            "first_seen": self.first_seen.isoformat() if self.first_seen else None,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
            "metadata": self.meta_data or {},
        }
