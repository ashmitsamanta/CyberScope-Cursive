from sqlalchemy import Column, Integer, String, Float, DateTime, JSON, ForeignKey, Index
from datetime import datetime, timezone
from app.database import Base


class Relationship(Base):
    __tablename__ = "relationships"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    source_entity_id = Column(Integer, ForeignKey("entities.id", ondelete="CASCADE"), nullable=False, index=True)
    target_entity_id = Column(Integer, ForeignKey("entities.id", ondelete="CASCADE"), nullable=False, index=True)
    relationship_type = Column(String(50), nullable=False, index=True)
    # SENT, RECEIVED, USED_BY, OWNS, ASSOCIATED_WITH, CONTAINS, RESOLVES_TO, TRANSFERRED_TO, LINKED_TO, REPORTED_IN, SHARED_WITH
    confidence = Column(Float, default=1.0, nullable=False)
    first_seen = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    last_seen = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    meta_data = Column(JSON, default=dict)

    __table_args__ = (
        Index("idx_rel_src_tgt_type", "source_entity_id", "target_entity_id", "relationship_type"),
    )

    def to_dict(self):
        return {
            "id": self.id,
            "source_entity_id": self.source_entity_id,
            "target_entity_id": self.target_entity_id,
            "relationship_type": self.relationship_type,
            "confidence": self.confidence,
            "first_seen": self.first_seen.isoformat() if self.first_seen else None,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
            "metadata": self.meta_data or {},
        }
