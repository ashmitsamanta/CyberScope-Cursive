import re
from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from typing import Dict, Any, List

from app.database import get_db
from app.models.case import Case
from app.models.entity import Entity
from app.models.transaction import Transaction
from app.models.relationship import Relationship
from app.utils.normalization import normalize_domain, normalize_phone, normalize_upi

router = APIRouter(prefix="/search", tags=["Search"])


@router.get("")
def natural_language_search(
    q: str = Query(..., description="Natural language search prompt"),
    db: Session = Depends(get_db)
):
    """
    Controlled natural language search router.
    Translates intent deterministically into safe parameterized database queries.
    Never executes raw LLM-generated SQL.
    """
    raw_query = q.strip().lower()

    # 1. Accounts connected to a domain or indicator
    domain_match = re.search(r"(?:connected to|linked to|domain)\s+([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})", raw_query)
    if domain_match:
        dom = normalize_domain(domain_match.group(1))
        dom_ent = db.query(Entity).filter(Entity.entity_type == "DOMAIN", Entity.normalized_value == dom).first()
        if not dom_ent:
            return {"intent": "DOMAIN_ACCOUNTS", "query": q, "results": [], "message": f"Domain '{dom}' not found in registry."}

        # Query related accounts
        rels = db.query(Relationship, Entity).join(
            Entity, (Relationship.source_entity_id == Entity.id) | (Relationship.target_entity_id == Entity.id)
        ).filter(
            (Relationship.source_entity_id == dom_ent.id) | (Relationship.target_entity_id == dom_ent.id)
        ).all()

        accounts = [ent.to_dict() for _, ent in rels if ent.id != dom_ent.id]
        return {
            "intent": "DOMAIN_ACCOUNTS",
            "matched_domain": dom,
            "count": len(accounts),
            "results": accounts,
            "explanation": f"Retrieved {len(accounts)} entities directly associated with domain '{dom}'."
        }

    # 2. Shared phone search
    if "phone" in raw_query and ("share" in raw_query or "same" in raw_query or "common" in raw_query):
        # Find phones appearing in multiple cases
        shared_phones = []
        all_phones = db.query(Entity).filter(Entity.entity_type == "PHONE").all()
        for p in all_phones:
            case_count = db.query(Relationship).filter(
                (Relationship.source_entity_id == p.id) | (Relationship.target_entity_id == p.id),
                Relationship.relationship_type == "REPORTED_IN"
            ).count()
            if case_count >= 2:
                shared_phones.append({
                    **p.to_dict(),
                    "case_count": case_count
                })

        return {
            "intent": "SHARED_PHONES",
            "count": len(shared_phones),
            "results": shared_phones,
            "explanation": f"Found {len(shared_phones)} phone numbers shared across multiple case investigations."
        }

    # 3. High value transactions search (e.g. above 50,000)
    amt_match = re.search(r"(?:above|greater than|over|more than)\s*(?:₹|rs\.?|inr)?\s*([0-9,]+)", raw_query)
    if amt_match:
        threshold = float(amt_match.group(1).replace(",", ""))
        txs = db.query(Transaction).filter(Transaction.amount >= threshold).order_by(Transaction.amount.desc()).limit(20).all()
        return {
            "intent": "TRANSACTIONS_BY_AMOUNT",
            "threshold": threshold,
            "count": len(txs),
            "results": [t.to_dict() for t in txs],
            "explanation": f"Found {len(txs)} transactions exceeding ₹{threshold:,.2f}."
        }

    # 4. Search by Case Number or Entity ID
    case_match = re.search(r"(cs-\d{4})", raw_query)
    if case_match:
        case_no = case_match.group(1).upper()
        case = db.query(Case).filter(Case.case_number == case_no).first()
        if case:
            return {
                "intent": "CASE_LOOKUP",
                "count": 1,
                "results": [case.to_dict()],
                "explanation": f"Direct match found for {case_no}."
            }

    # 5. Fallback generic substring search
    search_term = f"%{q.strip().lower()}%"
    matched_cases = db.query(Case).filter(
        (Case.case_number.ilike(search_term)) | (Case.title.ilike(search_term))
    ).limit(10).all()

    matched_entities = db.query(Entity).filter(
        (Entity.value.ilike(search_term)) | (Entity.normalized_value.ilike(search_term))
    ).limit(10).all()

    return {
        "intent": "GENERAL_SEARCH",
        "query": q,
        "cases": [c.to_dict() for c in matched_cases],
        "entities": [e.to_dict() for e in matched_entities],
        "explanation": f"Matched {len(matched_cases)} cases and {len(matched_entities)} entities."
    }
