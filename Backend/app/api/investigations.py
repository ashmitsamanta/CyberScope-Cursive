from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import Dict, Any, List

from app.database import get_db
from app.models.investigation import InvestigationLog
from app.models.case import Case
from app.schemas.investigation import InvestigationQueryRequest, InvestigationResponse, CaseSummaryRequest
from app.services.ai_service import ai_service
from app.services.risk_service import RiskEngine

router = APIRouter(prefix="/investigations", tags=["Investigations"])


@router.post("/query", response_model=InvestigationResponse)
def query_cyber_assist(
    payload: InvestigationQueryRequest,
    db: Session = Depends(get_db)
):
    """
    Submits an investigator question to CYBER-ASSIST.
    Grounds answer strictly in structured evidence, itemizing signals,
    citations, and recommended next defensive actions.
    """
    if not payload.query.strip():
        raise HTTPException(status_code=400, detail="Query cannot be empty")

    res = ai_service.answer_query(db, query=payload.query, case_id=payload.case_id)

    # Persist log if tied to a case
    if payload.case_id:
        log = InvestigationLog(
            case_id=payload.case_id,
            query=payload.query,
            response=res.get("answer", ""),
            evidence=res.get("evidence_citations", []),
            risk_signals=res.get("calculated_signals", [])
        )
        db.add(log)
        db.commit()

    return res


@router.post("/summary", response_model=Dict[str, Any])
def generate_case_summary(
    payload: CaseSummaryRequest,
    db: Session = Depends(get_db)
):
    """Generates structured executive investigator brief for a case."""
    case = db.query(Case).filter(Case.id == payload.case_id).first()
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")

    res = ai_service.answer_query(
        db,
        query="Provide a comprehensive summary of this case, risk assessment, and recommended next steps.",
        case_id=payload.case_id
    )
    return res


@router.get("/case/{case_id}", response_model=List[Dict[str, Any]])
def get_case_investigation_logs(
    case_id: int,
    db: Session = Depends(get_db)
):
    logs = db.query(InvestigationLog).filter(InvestigationLog.case_id == case_id).order_by(
        InvestigationLog.created_at.asc()
    ).all()
    return [l.to_dict() for l in logs]
