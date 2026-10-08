from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import func
from typing import Dict, Any

from app.database import get_db
from app.models.case import Case
from app.models.entity import Entity
from app.models.transaction import Transaction
from app.models.campaign import Campaign
from app.models.indicator import Indicator

router = APIRouter(prefix="/stats", tags=["Dashboard Statistics"])


@router.get("/dashboard")
def get_dashboard_stats(db: Session = Depends(get_db)):
    total_cases = db.query(Case).count()
    high_risk_cases = db.query(Case).filter(Case.risk_score >= 70.0, Case.risk_score < 90.0).count()
    critical_cases = db.query(Case).filter(Case.risk_score >= 90.0).count()
    medium_cases = db.query(Case).filter(Case.risk_score >= 40.0, Case.risk_score < 70.0).count()
    low_cases = db.query(Case).filter(Case.risk_score < 40.0).count()

    total_entities = db.query(Entity).count()
    total_transactions = db.query(Transaction).count()
    total_campaigns = db.query(Campaign).count()

    total_volume_res = db.query(func.sum(Transaction.amount)).scalar()
    total_volume = float(total_volume_res) if total_volume_res else 0.0

    # Entity Breakdown by Type
    type_counts = db.query(Entity.entity_type, func.count(Entity.id)).group_by(Entity.entity_type).all()
    entity_distribution = [{"type": t, "count": c} for t, c in type_counts]

    # Risk Distribution
    risk_distribution = [
        {"level": "LOW", "count": low_cases, "color": "#10B981"},
        {"level": "MEDIUM", "count": medium_cases, "color": "#F59E0B"},
        {"level": "HIGH", "count": high_risk_cases, "color": "#F97316"},
        {"level": "CRITICAL", "count": critical_cases, "color": "#EF4444"},
    ]

    # Top Recent High-Risk Cases
    top_cases = db.query(Case).order_by(Case.risk_score.desc(), Case.created_at.desc()).limit(5).all()

    # Active Campaigns
    active_campaigns = db.query(Campaign).order_by(Campaign.risk_score.desc()).limit(3).all()

    return {
        "kpis": {
            "total_cases": total_cases,
            "high_risk_cases": high_risk_cases,
            "critical_cases": critical_cases,
            "linked_entities": total_entities,
            "detected_campaigns": total_campaigns,
            "transactions_analyzed": total_transactions,
            "total_volume_analyzed": total_volume,
        },
        "total_cases": total_cases,
        "total_entities": total_entities,
        "high_risk_cases": high_risk_cases,
        "critical_cases": critical_cases,
        "total_campaigns": total_campaigns,
        "total_transactions": total_transactions,
        "total_volume": total_volume,
        "risk_distribution": risk_distribution,
        "entity_distribution": entity_distribution,
        "recent_high_risk_cases": [c.to_dict() for c in top_cases],
        "active_campaigns": [c.to_dict() for c in active_campaigns],
    }
