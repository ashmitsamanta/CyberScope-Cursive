from sqlalchemy import Column, Integer, String, Text, DateTime, JSON, ForeignKey
from datetime import datetime, timezone
from app.database import Base


class InvestigationLog(Base):
    __tablename__ = "investigation_logs"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    case_id = Column(Integer, ForeignKey("cases.id", ondelete="CASCADE"), nullable=True, index=True)
    query = Column(String(1024), nullable=False)
    response = Column(Text, nullable=False)
    evidence = Column(JSON, default=list)
    risk_signals = Column(JSON, default=list)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)

    def to_dict(self):
        return {
            "id": self.id,
            "case_id": self.case_id,
            "query": self.query,
            "response": self.response,
            "evidence": self.evidence or [],
            "risk_signals": self.risk_signals or [],
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }
