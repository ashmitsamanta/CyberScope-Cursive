from pydantic import BaseModel, Field, ConfigDict
from typing import Optional, Dict, Any, List
from datetime import datetime


class EntityBase(BaseModel):
    entity_type: str
    value: str
    normalized_value: str
    risk_score: float = 0.0
    metadata: Dict[str, Any] = Field(default_factory=dict)


class EntityCreate(EntityBase):
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None


class EntityResponse(EntityBase):
    id: int
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    case_count: Optional[int] = None
    degree: Optional[int] = None
    model_config = ConfigDict(from_attributes=True)


class EntityNeighbor(BaseModel):
    id: int
    entity_type: str
    value: str
    normalized_value: str
    risk_score: float
    relationship_type: str
    confidence: float
    direction: str  # outgoing, incoming, bidirectional


class EntityDetailResponse(EntityResponse):
    connected_cases: List[Dict[str, Any]] = Field(default_factory=list)
    neighbors: List[EntityNeighbor] = Field(default_factory=list)
    transaction_summary: Dict[str, Any] = Field(default_factory=dict)
    indicators: List[Dict[str, Any]] = Field(default_factory=list)
