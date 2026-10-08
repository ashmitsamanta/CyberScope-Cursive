from pydantic import BaseModel, Field, ConfigDict
from typing import Optional, List, Dict, Any
from datetime import datetime


class RiskSignal(BaseModel):
    code: str
    points: float
    explanation: str
    category: str = "GENERAL"


class CaseBase(BaseModel):
    case_number: str
    title: str
    description: Optional[str] = ""
    status: str = "NEW"
    severity: str = "MEDIUM"
    source: str = "SYSTEM_INGESTION"
    risk_score: float = 0.0
    campaign_id: Optional[int] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)


class CaseCreate(CaseBase):
    pass


class CaseUpdate(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    status: Optional[str] = None
    severity: Optional[str] = None
    risk_score: Optional[float] = None
    campaign_id: Optional[int] = None
    metadata: Optional[Dict[str, Any]] = None


class CaseResponse(CaseBase):
    id: int
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    entity_count: Optional[int] = None
    model_config = ConfigDict(from_attributes=True)


class CaseDetailResponse(CaseResponse):
    risk_breakdown: Optional[Dict[str, Any]] = None
    entity_count: int = 0
    transaction_count: int = 0
    message_count: int = 0
    indicator_count: int = 0
    campaign_name: Optional[str] = None
    connected_paths: Optional[int] = None
