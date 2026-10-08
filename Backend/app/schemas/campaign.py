from pydantic import BaseModel, Field, ConfigDict
from typing import Optional, Dict, Any, List
from datetime import datetime


class CampaignBase(BaseModel):
    campaign_id: str
    name: str
    description: Optional[str] = ""
    risk_score: float = 0.0
    case_count: int = 0
    entity_count: int = 0
    status: str = "ACTIVE"
    shared_indicators: Dict[str, Any] = Field(default_factory=dict)
    metadata: Dict[str, Any] = Field(default_factory=dict)


class CampaignResponse(CampaignBase):
    id: int
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    code: Optional[str] = None
    shared_entity_count: Optional[int] = None
    severity: Optional[str] = None
    model_config = ConfigDict(from_attributes=True)


class CampaignDetailResponse(CampaignResponse):
    cases: List[Dict[str, Any]] = Field(default_factory=list)
    key_entities: List[Dict[str, Any]] = Field(default_factory=list)
    timeline: List[Dict[str, Any]] = Field(default_factory=list)
