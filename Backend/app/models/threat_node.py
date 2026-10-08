from sqlalchemy import Column, Integer, String, Float, DateTime, JSON
from datetime import datetime, timezone
from app.database import Base


class ThreatNode(Base):
    """
    SQLAlchemy model representing an attacker/scammer infrastructure node.
    Strictly restricted to attacker infrastructure (IPs, ASNs, C2s, botnet nodes, phishing hosts).
    Victim data is NEVER stored or referenced here.
    """
    __tablename__ = "threat_nodes"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    ip = Column(String(64), nullable=False, unique=True, index=True)
    hostname = Column(String(255), nullable=True)
    asn = Column(String(255), nullable=False)
    isp = Column(String(255), nullable=False)
    city = Column(String(100), nullable=False, index=True)
    state = Column(String(100), nullable=False, index=True)
    pincode = Column(String(20), nullable=False, default="110001", index=True)
    latitude = Column(Float, nullable=False)
    longitude = Column(Float, nullable=False)
    attack_type = Column(String(100), nullable=False, index=True)
    # 'PHISHING_HOST', 'DDOS_BOTNET', 'UPI_MULE_VECTOR', 'SIM_BOX_RELAY', 'FAKE_KYC_GATEWAY', 'BRUTE_FORCE_STUFFER', 'MALWARE_C2'
    severity = Column(String(50), nullable=False, default="HIGH", index=True)
    # 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'
    risk_score = Column(Float, nullable=False, default=75.0)
    attack_count = Column(Integer, nullable=False, default=1)
    target_sector = Column(String(100), nullable=False)
    # 'Banking & Financial', 'Public Utilities', 'E-Commerce / Logistics', 'Telecommunications', 'Govt Services'
    malicious_request_sample = Column(String(512), nullable=True)
    active_campaign = Column(String(255), nullable=True, index=True)
    primary_case_id = Column(Integer, nullable=True, index=True)
    primary_case_number = Column(String(50), nullable=True, index=True)
    linked_case_ids = Column(JSON, default=list)
    linked_case_numbers = Column(JSON, default=list)
    status = Column(String(50), nullable=False, default="ACTIVE_ATTACKING", index=True)
    # 'ACTIVE_ATTACKING', 'HONEYPOT_TRAPPED', 'BLOCKED_BY_FIREWALL'
    last_seen = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    meta_data = Column(JSON, default=dict)

    @property
    def lat(self) -> float:
        return float(self.latitude)

    @property
    def lng(self) -> float:
        return float(self.longitude)

    def to_dict(self):
        linked_nums = self.linked_case_numbers or []
        primary_num = self.primary_case_number or (linked_nums[0] if linked_nums else "CS-1024")
        
        # Ensure linked_case_ids are resolved integers
        linked_ids = []
        if self.linked_case_ids:
            linked_ids = [int(x) for x in self.linked_case_ids if str(x).isdigit()]
        if not linked_ids and linked_nums:
            # Deterministic resolution fallback: CS-1024 -> 1, CS-1025 -> 2, etc.
            for num in linked_nums:
                if str(num).startswith("CS-") and str(num)[3:].isdigit():
                    linked_ids.append(int(str(num)[3:]) - 1023)
                elif str(num).isdigit():
                    linked_ids.append(int(num))
        
        primary_id = self.primary_case_id
        if primary_id is None:
            if linked_ids:
                primary_id = linked_ids[0]
            elif primary_num and str(primary_num).startswith("CS-") and str(primary_num)[3:].isdigit():
                primary_id = int(str(primary_num)[3:]) - 1023
            else:
                primary_id = 1

        return {
            "id": self.id,
            "ip": self.ip,
            "hostname": self.hostname or f"node-{self.ip.replace('.', '-')}.net",
            "asn": self.asn,
            "isp": self.isp,
            "city": self.city,
            "state": self.state,
            "pincode": self.pincode or "110001",
            "latitude": float(self.latitude),
            "longitude": float(self.longitude),
            "lat": float(self.latitude),
            "lng": float(self.longitude),
            "attack_type": self.attack_type,
            "severity": self.severity,
            "risk_score": round(self.risk_score, 1),
            "attack_count": self.attack_count,
            "target_sector": self.target_sector,
            "malicious_request_sample": self.malicious_request_sample,
            "active_campaign": self.active_campaign,
            "primary_case_id": primary_id,
            "primary_case_number": primary_num,
            "linked_case_ids": linked_ids,
            "linked_case_numbers": linked_nums,
            "status": self.status,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
            "metadata": self.meta_data or {},
        }

