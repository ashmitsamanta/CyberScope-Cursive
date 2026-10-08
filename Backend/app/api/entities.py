from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from typing import List, Optional, Dict, Any

from app.database import get_db
from app.models.entity import Entity
from app.models.relationship import Relationship
from app.models.transaction import Transaction
from app.models.indicator import Indicator
from app.schemas.entity import EntityResponse, EntityDetailResponse
from app.services.entity_service import EntityService

router = APIRouter(prefix="/entities", tags=["Entities"])


@router.get("", response_model=List[EntityResponse])
def list_entities(
    db: Session = Depends(get_db),
    entity_type: Optional[str] = Query(None, description="Filter by type (PHONE, DOMAIN, UPI_ID, BANK_ACCOUNT, etc.)"),
    min_risk: Optional[float] = Query(None, description="Minimum risk score"),
    search: Optional[str] = Query(None, description="Search by value or normalized value"),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0)
):
    query = db.query(Entity)
    if entity_type:
        query = query.filter(Entity.entity_type == entity_type.upper())
    if min_risk is not None:
        query = query.filter(Entity.risk_score >= min_risk)
    if search:
        s_pat = f"%{search.strip().lower()}%"
        query = query.filter(Entity.normalized_value.ilike(s_pat))

    entities = query.order_by(Entity.risk_score.desc(), Entity.last_seen.desc()).offset(offset).limit(limit).all()
    results = []
    for e in entities:
        d = e.to_dict()
        rel_count = db.query(Relationship).filter(
            (Relationship.source_entity_id == e.id) | (Relationship.target_entity_id == e.id)
        ).count()
        d["degree"] = rel_count
        d["case_count"] = max(1, rel_count // 2) if e.entity_type != "CASE" else 1
        results.append(d)
    return results


@router.get("/{entity_id}", response_model=EntityDetailResponse)
def get_entity(entity_id: int, db: Session = Depends(get_db)):
    entity = db.query(Entity).filter(Entity.id == entity_id).first()
    if not entity:
        raise HTTPException(status_code=404, detail="Entity not found")

    connected_cases = EntityService.find_connected_cases(db, entity_id)
    neighbors = EntityService.get_entity_neighbors(db, entity_id)

    # Transaction statistics
    sent_txs = db.query(Transaction).filter(Transaction.sender_entity_id == entity_id).all()
    received_txs = db.query(Transaction).filter(Transaction.receiver_entity_id == entity_id).all()

    tx_summary = {
        "sent_count": len(sent_txs),
        "sent_volume": sum(t.amount for t in sent_txs),
        "received_count": len(received_txs),
        "received_volume": sum(t.amount for t in received_txs),
    }

    # Indicators
    indicators = db.query(Indicator).filter(Indicator.entity_id == entity_id).all()
    ind_list = [i.to_dict() for i in indicators]

    ent_dict = entity.to_dict()
    ent_dict.update({
        "connected_cases": connected_cases,
        "neighbors": neighbors,
        "transaction_summary": tx_summary,
        "indicators": ind_list
    })

    return ent_dict


@router.get("/{entity_id}/neighbors")
def get_entity_neighbors(entity_id: int, db: Session = Depends(get_db)):
    entity = db.query(Entity).filter(Entity.id == entity_id).first()
    if not entity:
        raise HTTPException(status_code=404, detail="Entity not found")

    neighbors = EntityService.get_entity_neighbors(db, entity_id)
    return {"entity_id": entity_id, "neighbors": neighbors}
