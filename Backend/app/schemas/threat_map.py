from pydantic import BaseModel, Field, ConfigDict
from typing import Optional, List, Dict, Any


class ThreatAttackerResponse(BaseModel):
    id: int
    ip: str
    hostname: Optional[str] = None
    asn: str
    isp: str
    city: str
    state: str
    pincode: str = "110001"
    latitude: float
    longitude: float
    lat: float
    lng: float
    attack_type: str
    severity: str
    risk_score: float
    attack_count: int
    target_sector: str
    malicious_request_sample: Optional[str] = None
    active_campaign: Optional[str] = None
    primary_case_id: Optional[int] = None
    primary_case_number: Optional[str] = None
    linked_case_ids: List[int] = Field(default_factory=list)
    linked_case_numbers: List[str] = Field(default_factory=list)
    status: str
    last_seen: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)

    model_config = ConfigDict(from_attributes=True)


class AttackTypeStat(BaseModel):
    type: str
    count: int


class HotspotStat(BaseModel):
    city: str
    state: str
    pincode: Optional[str] = None
    count: int
    latitude: float
    longitude: float
    lat: Optional[float] = None
    lng: Optional[float] = None


class ThreatStatsResponse(BaseModel):
    total_attackers: int
    active_attacks: int
    critical_threats: int
    top_attack_types: List[AttackTypeStat]
    top_hotspots: List[HotspotStat]
    total_blocked_requests: int
    avg_risk_score: float
    active_attacks_per_min: int = 1420
    blocked_ips: List[str] = Field(default_factory=list)
    severity_breakdown: Dict[str, int] = Field(default_factory=dict)
    target_sector_breakdown: Dict[str, int] = Field(default_factory=dict)
    status_breakdown: Dict[str, int] = Field(default_factory=dict)

    model_config = ConfigDict(from_attributes=True)


class LiveFeedEvent(BaseModel):
    id: str
    event_id: Optional[str] = None
    timestamp: str
    attacker_ip: str
    hostname: Optional[str] = None
    city: str
    state: str
    pincode: Optional[str] = None
    location: Optional[str] = None
    latitude: float
    longitude: float
    lat: Optional[float] = None
    lng: Optional[float] = None
    attack_type: str
    severity: str
    target: str
    malicious_request_sample: Optional[str] = None
    payload_sample: Optional[str] = None
    blocked_status: bool
    action_taken: str
    primary_case_id: Optional[int] = None
    primary_case_number: Optional[str] = None
    linked_case_ids: List[int] = Field(default_factory=list)
    linked_case_numbers: List[str] = Field(default_factory=list)

    model_config = ConfigDict(from_attributes=True)


class BlockAttackerRequest(BaseModel):
    attacker_id: Optional[int] = None
    ip: Optional[str] = None
    action: Optional[str] = None
    reason: Optional[str] = "Perimeter SIEM / Honeypot threshold exceeded"
    firewall_rule: Optional[str] = "DROP"


class BlockAttackerResponse(BaseModel):
    success: bool
    message: str
    attacker: ThreatAttackerResponse
    firewall_rule_id: str
    action: str = "BLOCKED_BY_FIREWALL"
    timestamp: str

    model_config = ConfigDict(from_attributes=True)
