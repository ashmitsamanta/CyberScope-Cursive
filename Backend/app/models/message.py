from sqlalchemy import Column, Integer, String, Text, DateTime, JSON, ForeignKey
from datetime import datetime, timezone
from app.database import Base


class Message(Base):
    __tablename__ = "messages"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    sender_phone = Column(String(64), nullable=True, index=True)
    receiver_phone = Column(String(64), nullable=True, index=True)
    channel = Column(String(50), default="SMS", nullable=False)
    # SMS, EMAIL, WHATSAPP_SIMULATION, VOICE_TRANSCRIPT, WEB
    subject = Column(String(255), nullable=True)
    content = Column(Text, nullable=False)
    url = Column(String(512), nullable=True)
    case_id = Column(Integer, ForeignKey("cases.id", ondelete="SET NULL"), nullable=True, index=True)
    meta_data = Column(JSON, default=dict)

    def to_dict(self):
        return {
            "id": self.id,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "sender_phone": self.sender_phone,
            "receiver_phone": self.receiver_phone,
            "channel": self.channel,
            "subject": self.subject,
            "content": self.content,
            "url": self.url,
            "case_id": self.case_id,
            "metadata": self.meta_data or {},
        }
