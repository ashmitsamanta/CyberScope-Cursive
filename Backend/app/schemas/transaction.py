from pydantic import BaseModel, Field, ConfigDict
from typing import Optional, Dict, Any, List
from datetime import datetime


class TransactionBase(BaseModel):
    transaction_ref: str
    timestamp: datetime
    sender_entity_id: int
    receiver_entity_id: int
    amount: float
    currency: str = "INR"
    channel: str = "UPI"
    device_id: Optional[int] = None
    ip_id: Optional[int] = None
    case_id: Optional[int] = None
    status: str = "SUCCESS"
    metadata: Dict[str, Any] = Field(default_factory=dict)


class TransactionCreate(TransactionBase):
    pass


class TransactionResponse(TransactionBase):
    id: int
    sender_value: Optional[str] = None
    receiver_value: Optional[str] = None
    sender_type: Optional[str] = None
    receiver_type: Optional[str] = None
    case_number: Optional[str] = None
    risk_signals: List[Dict[str, Any]] = Field(default_factory=list)
    tx_hash: Optional[str] = None
    from_account: Optional[str] = None
    to_account: Optional[str] = None
    is_suspicious: Optional[bool] = None
    model_config = ConfigDict(from_attributes=True)


class MoneyFlowTraceRequest(BaseModel):
    start_account_id: Optional[int] = None
    start_transaction_id: Optional[int] = None
    max_hops: int = 4
    time_window_hours: Optional[int] = 72
    min_amount: Optional[float] = 0.0


class MoneyFlowNode(BaseModel):
    id: str
    entity_id: int
    label: str
    entity_type: str
    risk_score: float
    hop_level: int
    role: str = "INTERMEDIARY"  # SOURCE, INTERMEDIARY, DESTINATION, MULE


class MoneyFlowEdge(BaseModel):
    id: str
    source: str
    target: str
    amount: float
    currency: str
    channel: str
    timestamp: str
    transaction_ref: str
    flagged: bool = False


class MoneyFlowTraceResponse(BaseModel):
    root_entity_id: int
    max_hops_reached: int
    total_volume_traced: float
    detected_patterns: List[Dict[str, Any]] = Field(default_factory=list)
    nodes: List[MoneyFlowNode] = Field(default_factory=list)
    edges: List[MoneyFlowEdge] = Field(default_factory=list)
    summary: str = ""
