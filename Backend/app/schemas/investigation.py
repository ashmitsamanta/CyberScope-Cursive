from pydantic import BaseModel, Field
from typing import Optional, Dict, Any, List
from datetime import datetime


class InvestigationQueryRequest(BaseModel):
    case_id: Optional[int] = None
    query: str
    focus_entity_id: Optional[int] = None


class EvidenceCitation(BaseModel):
    tag: str  # e.g. "[CASE-102]", "[DOMAIN-14]", "[TX-9281]"
    type: str  # CASE, DOMAIN, PHONE, TRANSACTION, ACCOUNT, INDICATOR
    identifier: str
    summary: str


class InvestigationResponse(BaseModel):
    query: str
    case_id: Optional[int] = None
    answer: str
    observed_evidence: List[str] = Field(default_factory=list)
    calculated_signals: List[Dict[str, Any]] = Field(default_factory=list)
    inferences: List[str] = Field(default_factory=list)
    uncertainties: List[str] = Field(default_factory=list)
    evidence_citations: List[EvidenceCitation] = Field(default_factory=list)
    recommended_next_steps: List[str] = Field(default_factory=list)
    model_used: str = "CYBER-ASSIST-EXPERT-DETERMINISTIC"


class CaseSummaryRequest(BaseModel):
    case_id: int


class TimelineEvent(BaseModel):
    id: str
    timestamp: str
    event_type: str  # MESSAGE, TRANSACTION, INDICATOR, CASE_CREATED, STATUS_CHANGE
    title: str
    description: str
    severity: str
    entities: List[Dict[str, Any]] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)
