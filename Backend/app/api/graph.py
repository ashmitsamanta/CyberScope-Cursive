from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from typing import Optional, Dict, Any, List

from app.database import get_db
from app.schemas.graph import GraphData
from app.services.graph_service import graph_service

router = APIRouter(prefix="/graph", tags=["Fraud Graph"])


@router.get("", response_model=GraphData)
def get_fraud_graph(
    db: Session = Depends(get_db),
    limit: int = Query(150, ge=1, le=500),
    entity_type: Optional[str] = Query(None, description="Filter by entity type (e.g. DOMAIN, PHONE, BANK_ACCOUNT)"),
    search: Optional[str] = Query(None, description="Search filter for label or normalized value"),
    min_risk: Optional[float] = Query(None, description="Minimum risk score threshold")
):
    """Returns overview graph with top nodes and active edges, with optional filtering."""
    return graph_service.get_full_graph(
        db,
        limit=limit,
        entity_type=entity_type,
        search=search,
        min_risk=min_risk
    )


@router.get("/case/{case_identifier}", response_model=GraphData)
def get_case_subgraph(
    case_identifier: str,
    db: Session = Depends(get_db),
    hops: int = Query(2, ge=1, le=4)
):
    """Extracts graph subgraph relevant to a specific case by integer ID or case number string (e.g. CS-1024)."""
    return graph_service.get_case_graph(db, case_identifier=case_identifier, hops=hops)


@router.get("/entity/{entity_identifier:path}", response_model=GraphData)
def get_entity_neighborhood(
    entity_identifier: str,
    db: Session = Depends(get_db),
    hops: int = Query(2, ge=1, le=3)
):
    """Expands graph around an entity up to k-hops by integer ID or normalized value (e.g. +919686579303, secure-kyc-update.com)."""
    return graph_service.get_neighborhood(db, entity_identifier=entity_identifier, hops=hops)


@router.get("/shortest-path")
def find_shortest_path(
    source_id: int = Query(..., description="Source entity ID"),
    target_id: int = Query(..., description="Target entity ID"),
    db: Session = Depends(get_db)
):
    """Finds shortest investigative path between two entities."""
    path = graph_service.find_shortest_path(db, source_id, target_id)
    if not path:
        return {"found": False, "path": [], "message": "No direct or multi-hop path found"}
    return {"found": True, "path": path, "hops": len(path) - 1}


@router.get("/circular-flows")
def detect_circular_flows(db: Session = Depends(get_db)):
    """Detects cycles in fund movement (A -> B -> C -> A)."""
    cycles = graph_service.detect_circular_flows(db)
    return {"cycles_count": len(cycles), "cycles": cycles}


@router.get("/shared-infrastructure")
def get_shared_infrastructure(db: Session = Depends(get_db)):
    """Finds infrastructure nodes connected to 2 or more distinct cases."""
    shared = graph_service.find_shared_infrastructure(db)
    return {"count": len(shared), "shared_infrastructure": shared}
