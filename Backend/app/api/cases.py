from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from typing import List, Optional, Dict, Any

from app.database import get_db
from app.models.case import Case
from app.models.entity import Entity
from app.models.transaction import Transaction
from app.models.message import Message
from app.models.indicator import Indicator
from app.models.campaign import Campaign
from app.schemas.case import CaseResponse, CaseDetailResponse, CaseCreate, CaseUpdate
from app.services.risk_service import RiskEngine
from app.services.timeline_service import TimelineService
from app.services.ingestion_service import IngestionService

router = APIRouter(prefix="/cases", tags=["Cases"])


@router.get("", response_model=List[CaseResponse])
def list_cases(
    db: Session = Depends(get_db),
    status: Optional[str] = Query(None, description="Filter by status (NEW, INVESTIGATING, ESCALATED, RESOLVED)"),
    severity: Optional[str] = Query(None, description="Filter by severity (LOW, MEDIUM, HIGH, CRITICAL)"),
    min_risk: Optional[float] = Query(None, description="Minimum risk score threshold"),
    search: Optional[str] = Query(None, description="Search query matching case number or title"),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0)
):
    query = db.query(Case)

    if status:
        query = query.filter(Case.status == status.upper())
    if severity:
        query = query.filter(Case.severity == severity.upper())
    if min_risk is not None:
        query = query.filter(Case.risk_score >= min_risk)
    if search:
        s_pat = f"%{search}%"
        query = query.filter((Case.case_number.ilike(s_pat)) | (Case.title.ilike(s_pat)))

    cases = query.order_by(Case.risk_score.desc(), Case.created_at.desc()).offset(offset).limit(limit).all()
    results = []
    for c in cases:
        c_dict = c.to_dict()
        # Find count of linked entities via transactions or indicators
        t_cnt = db.query(Transaction).filter(Transaction.case_id == c.id).count()
        i_cnt = db.query(Indicator).filter(Indicator.case_id == c.id).count()
        c_dict["entity_count"] = max(1, t_cnt * 2 + i_cnt)
        results.append(c_dict)
    return results


@router.get("/{case_identifier}", response_model=CaseDetailResponse)
def get_case(case_identifier: str, db: Session = Depends(get_db)):
    case = None
    if case_identifier.isdigit():
        case = db.query(Case).filter(Case.id == int(case_identifier)).first()
    if not case:
        case = db.query(Case).filter(Case.case_number.ilike(case_identifier.strip())).first()
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")

    case_id = case.id
    # Risk breakdown calculation
    risk_breakdown = RiskEngine.evaluate_case(db, case_id)

    # Counts
    tx_count = db.query(Transaction).filter(Transaction.case_id == case_id).count()
    msg_count = db.query(Message).filter(Message.case_id == case_id).count()
    ind_count = db.query(Indicator).filter(Indicator.case_id == case_id).count()
    calculated_entities = max(1, tx_count * 2 + ind_count)

    camp_name = None
    if case.campaign_id:
        camp = db.query(Campaign).filter(Campaign.id == case.campaign_id).first()
        if camp:
            camp_name = camp.name

    case_dict = case.to_dict()
    case_dict.update({
        "risk_breakdown": risk_breakdown,
        "entity_count": calculated_entities,
        "transaction_count": tx_count,
        "message_count": msg_count,
        "indicator_count": ind_count,
        "campaign_name": camp_name,
        "connected_paths": max(2, tx_count + ind_count)
    })

    return case_dict


@router.get("/{case_identifier}/timeline")
def get_case_timeline(case_identifier: str, db: Session = Depends(get_db)):
    case = None
    if case_identifier.isdigit():
        case = db.query(Case).filter(Case.id == int(case_identifier)).first()
    if not case:
        case = db.query(Case).filter(Case.case_number.ilike(case_identifier.strip())).first()
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")

    events = TimelineService.get_case_timeline(db, case.id)
    return {"case_id": case.id, "case_number": case.case_number, "events": events}


import html

@router.post("/ingest", response_model=Dict[str, Any])
def ingest_new_case_report(
    payload: Dict[str, Any],
    db: Session = Depends(get_db)
):
    title = payload.get("title", "Reported Cyber Fraud Incident")
    content = payload.get("content", "")
    sender_phone = payload.get("sender_phone")
    channel = payload.get("channel", "SMS")

    if not content:
        raise HTTPException(status_code=400, detail="Report content cannot be empty")

    # Security: Guard against upload abuse / payload flooding
    if len(content) > 50000:
        raise HTTPException(status_code=413, detail="Payload exceeds maximum allowed size of 50KB")

    if len(title) > 256:
        raise HTTPException(status_code=400, detail="Title length exceeds maximum permitted limit of 256 characters")

    # Security: Defense-in-depth XSS sanitization for reported scam content
    safe_title = html.escape(str(title).strip())
    safe_content = html.escape(str(content).strip())

    res = IngestionService.ingest_report(
        db=db,
        title=safe_title,
        content=safe_content,
        channel=channel,
        sender_phone=sender_phone
    )
    return res


@router.patch("/{case_id}", response_model=CaseResponse)
def update_case(case_id: int, updates: CaseUpdate, db: Session = Depends(get_db)):
    case = db.query(Case).filter(Case.id == case_id).first()
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")

    data = updates.model_dump(exclude_unset=True)
    for field, val in data.items():
        setattr(case, field, val)

    db.commit()
    db.refresh(case)
    return case.to_dict()
