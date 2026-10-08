from pydantic import BaseModel, Field
from typing import Optional, Dict, Any, List


class GraphNode(BaseModel):
    id: str  # e.g. "e-10" or "c-5"
    numeric_id: int
    label: str
    entity_type: str
    risk_score: float
    metadata: Dict[str, Any] = Field(default_factory=dict)
    case_ids: List[int] = Field(default_factory=list)


class GraphEdge(BaseModel):
    id: str
    source: str
    target: str
    relationship_type: str
    confidence: float = 1.0
    amount: Optional[float] = None
    channel: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)


class GraphData(BaseModel):
    nodes: List[GraphNode] = Field(default_factory=list)
    edges: List[GraphEdge] = Field(default_factory=list)
    stats: Dict[str, Any] = Field(default_factory=dict)


class GraphFilterRequest(BaseModel):
    case_id: Optional[int] = None
    center_entity_id: Optional[int] = None
    hops: int = 2
    entity_types: Optional[List[str]] = None
    min_risk_score: Optional[float] = 0.0
    relationship_types: Optional[List[str]] = None
    limit_nodes: int = 150
