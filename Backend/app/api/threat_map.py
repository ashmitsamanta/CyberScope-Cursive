from fastapi import APIRouter, Depends, HTTPException, Query, Path
from sqlalchemy.orm import Session
from typing import List, Optional, Dict, Any

from app.database import get_db
from app.schemas.threat_map import (
    ThreatAttackerResponse,
    ThreatStatsResponse,
    LiveFeedEvent,
    BlockAttackerRequest,
    BlockAttackerResponse
)
from app.services.threat_map_service import ThreatMapService

router = APIRouter(prefix="/threat-map", tags=["Threat Intelligence Map"])


@router.get("/attackers", response_model=List[ThreatAttackerResponse])
def get_attackers(
    severity: Optional[str] = Query(None, description="Filter by severity: CRITICAL, HIGH, MEDIUM, LOW"),
    attack_type: Optional[str] = Query(None, description="Filter by attack type: PHISHING_HOST, DDOS_BOTNET, UPI_MULE_VECTOR, SIM_BOX_RELAY, FAKE_KYC_GATEWAY, BRUTE_FORCE_STUFFER, MALWARE_C2"),
    campaign: Optional[str] = Query(None, description="Filter by campaign name or substring"),
    pincode: Optional[str] = Query(None, description="Filter by verified 6-digit India Post PIN code (e.g. 815351, 110001)"),
    min_risk: Optional[float] = Query(None, description="Minimum risk score threshold (60.0 - 99.0)"),
    search: Optional[str] = Query(None, description="Search by IP, hostname, city, state, pincode, ISP, ASN, or campaign"),
    limit: int = Query(100, ge=1, le=500, description="Page limit"),
    offset: int = Query(0, ge=0, description="Page offset"),
    db: Session = Depends(get_db)
):
    """
    Returns verified cyber attacker and scammer infrastructure nodes with Indian geolocation metadata.
    STRICT PRIVACY GUARANTEE: Only attacker infrastructure is returned. No victim data is ever exposed.
    """
    attackers = ThreatMapService.get_attackers(
        db=db,
        severity=severity,
        attack_type=attack_type,
        campaign=campaign,
        pincode=pincode,
        min_risk=min_risk,
        search=search,
        limit=limit,
        offset=offset
    )
    return attackers


@router.get("/stats", response_model=ThreatStatsResponse)
def get_threat_stats(db: Session = Depends(get_db)):
    """
    Returns threat intelligence KPIs, hotspot density, attack typology breakdown,
    and mitigation metrics.
    """
    stats = ThreatMapService.get_stats(db=db)
    return stats


@router.get("/live-feed", response_model=List[LiveFeedEvent])
def get_live_threat_feed(
    limit: int = Query(20, ge=5, le=50, description="Number of recent attack events to return"),
    db: Session = Depends(get_db)
):
    """
    Returns recent live malicious attack events from known cybercrime hubs and attacker infrastructure.
    """
    feed = ThreatMapService.get_live_feed(db=db, limit=limit)
    return feed


@router.post("/block/{attacker_id}", response_model=BlockAttackerResponse)
def block_attacker_by_id(
    attacker_id: int = Path(..., description="ID of the attacker node to block"),
    request: Optional[BlockAttackerRequest] = None,
    db: Session = Depends(get_db)
):
    """
    Applies immediate perimeter firewall / ISP mitigation against the specified attacker infrastructure IP,
    updating its threat status to 'BLOCKED_BY_FIREWALL'.
    """
    reason = request.reason if request else "Perimeter SIEM policy enforcement"
    firewall_rule = request.firewall_rule if request else "DROP"
    
    result = ThreatMapService.block_attacker(
        db=db,
        attacker_id=attacker_id,
        reason=reason,
        firewall_rule=firewall_rule
    )
    if not result:
        raise HTTPException(status_code=404, detail=f"Attacker node with ID {attacker_id} not found")
    return result


@router.post("/block", response_model=BlockAttackerResponse)
def block_attacker_generic(
    request: BlockAttackerRequest,
    db: Session = Depends(get_db)
):
    """
    Applies immediate perimeter firewall mitigation against an attacker by ID or IP.
    """
    if not request.attacker_id and not request.ip:
        raise HTTPException(status_code=400, detail="Either 'attacker_id' or 'ip' must be provided in request body")
    
    result = ThreatMapService.block_attacker(
        db=db,
        attacker_id=request.attacker_id,
        ip=request.ip,
        reason=request.reason,
        firewall_rule=request.firewall_rule
    )
    if not result:
        ident = request.attacker_id or request.ip
        raise HTTPException(status_code=404, detail=f"Attacker node '{ident}' not found")
    return result
