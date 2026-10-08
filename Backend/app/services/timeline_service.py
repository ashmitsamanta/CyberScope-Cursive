from typing import List, Dict, Any
from sqlalchemy.orm import Session
from datetime import datetime
from app.models.case import Case
from app.models.message import Message
from app.models.transaction import Transaction
from app.models.indicator import Indicator
from app.models.entity import Entity


class TimelineService:
    """Constructs a unified chronological evidence timeline for an investigation case."""

    @staticmethod
    def get_case_timeline(db: Session, case_id: int) -> List[Dict[str, Any]]:
        events = []

        case = db.query(Case).filter(Case.id == case_id).first()
        if not case:
            return []

        # 1. Case Opened event
        events.append({
            "id": f"event-case-created-{case.id}",
            "timestamp": case.created_at.isoformat() if case.created_at else "2026-09-01T10:00:00Z",
            "event_type": "CASE_INITIALIZED",
            "title": f"Incident Reported: {case.case_number}",
            "description": case.description or f"Initial case filing regarding {case.title}.",
            "severity": case.severity,
            "entities": [{"type": "CASE", "value": case.case_number}],
            "metadata": {"source": case.source}
        })

        # 2. Communications / Scam Messages
        messages = db.query(Message).filter(Message.case_id == case_id).all()
        for msg in messages:
            events.append({
                "id": f"event-msg-{msg.id}",
                "timestamp": msg.timestamp.isoformat(),
                "event_type": "COMMUNICATION_RECEIVED",
                "title": f"Scam Communication: {msg.channel}",
                "description": f"Victim received message from '{msg.sender_phone or 'Unknown'}': \"{msg.content[:140]}...\"",
                "severity": "HIGH",
                "entities": [
                    {"type": "PHONE", "value": msg.sender_phone} if msg.sender_phone else None,
                    {"type": "URL", "value": msg.url} if msg.url else None,
                ],
                "metadata": {"channel": msg.channel, "url": msg.url}
            })

        # 3. Indicators detected
        indicators = db.query(Indicator).filter(Indicator.case_id == case_id).all()
        for ind in indicators:
            ent = db.query(Entity).filter(Entity.id == ind.entity_id).first() if ind.entity_id else None
            events.append({
                "id": f"event-ind-{ind.id}",
                "timestamp": ind.detected_at.isoformat(),
                "event_type": "INDICATOR_FLAGGED",
                "title": f"Threat Signal: {ind.indicator_type}",
                "description": ind.description,
                "severity": ind.severity,
                "entities": [{"type": ent.entity_type if ent else "INDICATOR", "value": ent.value if ent else "Flag"}],
                "metadata": {"indicator_type": ind.indicator_type}
            })

        # 4. Financial Transactions
        transactions = db.query(Transaction).filter(Transaction.case_id == case_id).all()
        for tx in transactions:
            snd = db.query(Entity).filter(Entity.id == tx.sender_entity_id).first()
            rcv = db.query(Entity).filter(Entity.id == tx.receiver_entity_id).first()
            
            snd_val = snd.value if snd else f"Account {tx.sender_entity_id}"
            rcv_val = rcv.value if rcv else f"Account {tx.receiver_entity_id}"

            events.append({
                "id": f"event-tx-{tx.id}",
                "timestamp": tx.timestamp.isoformat(),
                "event_type": "FINANCIAL_TRANSACTION",
                "title": f"Transfer: ₹{tx.amount:,.2f} via {tx.channel}",
                "description": f"Ref: {tx.transaction_ref} | {snd_val} transferred ₹{tx.amount:,.2f} to {rcv_val}.",
                "severity": "HIGH" if tx.amount >= 40000 else "MEDIUM",
                "entities": [
                    {"type": "SENDER", "value": snd_val},
                    {"type": "RECEIVER", "value": rcv_val},
                ],
                "metadata": {
                    "amount": tx.amount,
                    "currency": tx.currency,
                    "transaction_ref": tx.transaction_ref,
                    "status": tx.status
                }
            })

        # Filter None from entities
        for ev in events:
            ev["entities"] = [e for e in ev["entities"] if e is not None]

        # Sort chronologically
        def get_ts(ev):
            try:
                return datetime.fromisoformat(ev["timestamp"].replace("Z", "+00:00"))
            except Exception:
                return datetime.min

        sorted_events = sorted(events, key=get_ts)
        return sorted_events
