from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from typing import List, Optional, Dict, Any

from app.database import get_db
from app.models.transaction import Transaction
from app.models.entity import Entity
from app.models.case import Case
from app.schemas.transaction import TransactionResponse, MoneyFlowTraceRequest, MoneyFlowTraceResponse
from app.analyzers.transaction_analyzer import TransactionAnalyzer
from app.services.transaction_service import TransactionService

router = APIRouter(prefix="/transactions", tags=["Transactions"])


@router.get("", response_model=List[TransactionResponse])
def list_transactions(
    db: Session = Depends(get_db),
    channel: Optional[str] = Query(None, description="Channel (UPI, NEFT, IMPS)"),
    min_amount: Optional[float] = Query(None, description="Minimum amount"),
    case_id: Optional[int] = Query(None, description="Filter by case ID"),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0)
):
    query = db.query(Transaction)
    if channel:
        query = query.filter(Transaction.channel == channel.upper())
    if min_amount is not None:
        query = query.filter(Transaction.amount >= min_amount)
    if case_id is not None:
        query = query.filter(Transaction.case_id == case_id)

    txs = query.order_by(Transaction.timestamp.desc()).offset(offset).limit(limit).all()

    results = []
    for tx in txs:
        snd = db.query(Entity).filter(Entity.id == tx.sender_entity_id).first()
        rcv = db.query(Entity).filter(Entity.id == tx.receiver_entity_id).first()
        c = db.query(Case).filter(Case.id == tx.case_id).first() if tx.case_id else None

        eval_res = TransactionAnalyzer.evaluate_transaction(
            tx.to_dict(),
            sender_entity=snd.to_dict() if snd else None,
            receiver_entity=rcv.to_dict() if rcv else None
        )

        tx_dict = tx.to_dict()
        is_susp = bool(eval_res["signals"]) or tx.status == "FLAGGED"
        tx_dict.update({
            "sender_value": snd.value if snd else None,
            "receiver_value": rcv.value if rcv else None,
            "sender_type": snd.entity_type if snd else None,
            "receiver_type": rcv.entity_type if rcv else None,
            "case_number": c.case_number if c else None,
            "risk_signals": eval_res["signals"],
            "tx_hash": tx.transaction_ref,
            "from_account": snd.value if snd else f"ENT-{tx.sender_entity_id}",
            "to_account": rcv.value if rcv else f"ENT-{tx.receiver_entity_id}",
            "is_suspicious": is_susp
        })
        results.append(tx_dict)

    return results


@router.get("/{tx_id}", response_model=TransactionResponse)
def get_transaction(tx_id: int, db: Session = Depends(get_db)):
    tx = db.query(Transaction).filter(Transaction.id == tx_id).first()
    if not tx:
        raise HTTPException(status_code=404, detail="Transaction not found")

    snd = db.query(Entity).filter(Entity.id == tx.sender_entity_id).first()
    rcv = db.query(Entity).filter(Entity.id == tx.receiver_entity_id).first()
    c = db.query(Case).filter(Case.id == tx.case_id).first() if tx.case_id else None

    eval_res = TransactionAnalyzer.evaluate_transaction(
        tx.to_dict(),
        sender_entity=snd.to_dict() if snd else None,
        receiver_entity=rcv.to_dict() if rcv else None
    )

    tx_dict = tx.to_dict()
    is_susp = bool(eval_res["signals"]) or tx.status == "FLAGGED"
    tx_dict.update({
        "sender_value": snd.value if snd else None,
        "receiver_value": rcv.value if rcv else None,
        "sender_type": snd.entity_type if snd else None,
        "receiver_type": rcv.entity_type if rcv else None,
        "case_number": c.case_number if c else None,
        "risk_signals": eval_res["signals"],
        "tx_hash": tx.transaction_ref,
        "from_account": snd.value if snd else f"ENT-{tx.sender_entity_id}",
        "to_account": rcv.value if rcv else f"ENT-{tx.receiver_entity_id}",
        "is_suspicious": is_susp
    })
    return tx_dict


@router.post("/trace-funds", response_model=MoneyFlowTraceResponse)
def trace_money_flow(
    payload: MoneyFlowTraceRequest,
    db: Session = Depends(get_db)
):
    """Traces recursive fund movements from an account or initial fraudulent transfer."""
    res = TransactionService.trace_funds(
        db=db,
        start_entity_id=payload.start_account_id,
        start_transaction_id=payload.start_transaction_id,
        max_hops=payload.max_hops,
        time_window_hours=payload.time_window_hours or 72,
        min_amount=payload.min_amount or 0.0
    )
    return res
