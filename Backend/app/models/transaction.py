from sqlalchemy import Column, Integer, String, Float, DateTime, JSON, ForeignKey, Index
from datetime import datetime, timezone
from app.database import Base


class Transaction(Base):
    __tablename__ = "transactions"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    transaction_ref = Column(String(64), unique=True, nullable=False, index=True)
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False, index=True)
    sender_entity_id = Column(Integer, ForeignKey("entities.id", ondelete="CASCADE"), nullable=False, index=True)
    receiver_entity_id = Column(Integer, ForeignKey("entities.id", ondelete="CASCADE"), nullable=False, index=True)
    amount = Column(Float, nullable=False, index=True)
    currency = Column(String(10), default="INR", nullable=False)
    channel = Column(String(50), default="UPI", nullable=False, index=True)  # UPI, NEFT, IMPS, RTGS, CARD, WEB
    device_id = Column(Integer, ForeignKey("entities.id", ondelete="SET NULL"), nullable=True)
    ip_id = Column(Integer, ForeignKey("entities.id", ondelete="SET NULL"), nullable=True)
    case_id = Column(Integer, ForeignKey("cases.id", ondelete="SET NULL"), nullable=True, index=True)
    status = Column(String(50), default="SUCCESS", nullable=False)  # SUCCESS, FLAGGED, BLOCKED, PENDING
    meta_data = Column(JSON, default=dict)

    __table_args__ = (
        Index("idx_tx_sender_time", "sender_entity_id", "timestamp"),
        Index("idx_tx_receiver_time", "receiver_entity_id", "timestamp"),
    )

    def to_dict(self):
        return {
            "id": self.id,
            "transaction_ref": self.transaction_ref,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "sender_entity_id": self.sender_entity_id,
            "receiver_entity_id": self.receiver_entity_id,
            "amount": self.amount,
            "currency": self.currency,
            "channel": self.channel,
            "device_id": self.device_id,
            "ip_id": self.ip_id,
            "case_id": self.case_id,
            "status": self.status,
            "metadata": self.meta_data or {},
        }
