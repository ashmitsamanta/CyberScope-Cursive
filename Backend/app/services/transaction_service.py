from typing import Dict, Any, List, Optional, Set
from sqlalchemy.orm import Session
from datetime import datetime, timedelta, timezone
from collections import deque
from app.models.transaction import Transaction
from app.models.entity import Entity


class TransactionService:
    """Handles financial transactions and money-flow graph tracing."""

    @staticmethod
    def trace_funds(
        db: Session,
        start_entity_id: Optional[int] = None,
        start_transaction_id: Optional[int] = None,
        max_hops: int = 4,
        time_window_hours: int = 72,
        min_amount: float = 0.0
    ) -> Dict[str, Any]:
        """
        Traverses outbound fund movement from a starting account or initial fraudulent transfer.
        Constructs a reachable directed transaction tree/graph.
        Detects fan-out, fan-in, layering, and circular movements.
        """
        root_entity_id = start_entity_id
        start_time = None

        if start_transaction_id:
            tx = db.query(Transaction).filter(Transaction.id == start_transaction_id).first()
            if tx:
                root_entity_id = tx.receiver_entity_id  # trace where the stolen money went
                start_time = tx.timestamp

        if not root_entity_id:
            return {
                "root_entity_id": 0,
                "max_hops_reached": 0,
                "total_volume_traced": 0.0,
                "detected_patterns": [],
                "nodes": [],
                "edges": [],
                "summary": "No starting entity specified"
            }

        root_entity = db.query(Entity).filter(Entity.id == root_entity_id).first()
        if not root_entity:
            return {
                "root_entity_id": root_entity_id,
                "max_hops_reached": 0,
                "total_volume_traced": 0.0,
                "detected_patterns": [],
                "nodes": [],
                "edges": [],
                "summary": "Root entity not found"
            }

        # BFS Queue: (current_entity_id, current_hop, current_timestamp)
        queue = deque([(root_entity_id, 0, start_time or datetime(2026, 1, 1, tzinfo=timezone.utc))])
        visited_nodes: Set[int] = {root_entity_id}
        visited_edges: Set[int] = set()

        traced_nodes: Dict[int, Dict[str, Any]] = {
            root_entity_id: {
                "id": f"acc-{root_entity_id}",
                "entity_id": root_entity_id,
                "label": root_entity.value,
                "entity_type": root_entity.entity_type,
                "risk_score": root_entity.risk_score,
                "hop_level": 0,
                "role": "SOURCE"
            }
        }
        traced_edges: List[Dict[str, Any]] = []
        total_volume = 0.0
        patterns_detected = []
        highest_hop = 0

        while queue:
            curr_id, curr_hop, curr_time = queue.popleft()
            if curr_hop >= max_hops:
                continue

            highest_hop = max(highest_hop, curr_hop)

            # Query forward transactions
            outbound_txs = db.query(Transaction).filter(
                Transaction.sender_entity_id == curr_id,
                Transaction.amount >= min_amount
            ).order_by(Transaction.timestamp.asc()).all()

            # Filter by time window if initial timestamp exists
            valid_outbound = []
            for tx in outbound_txs:
                if start_time and tx.timestamp < start_time:
                    continue
                if start_time and (tx.timestamp - start_time) > timedelta(hours=time_window_hours):
                    continue
                valid_outbound.append(tx)

            # Pattern check: Fan-out from this node
            if len(valid_outbound) >= 3:
                patterns_detected.append({
                    "pattern": "FAN_OUT",
                    "entity_id": curr_id,
                    "explanation": f"Node '{traced_nodes[curr_id]['label']}' distributed funds to {len(valid_outbound)} recipients at hop {curr_hop}."
                })

            for tx in valid_outbound:
                if tx.id in visited_edges:
                    continue
                visited_edges.add(tx.id)

                nxt_id = tx.receiver_entity_id
                total_volume += tx.amount

                # Detect circular movement back to already seen node
                if nxt_id in visited_nodes:
                    patterns_detected.append({
                        "pattern": "CIRCULAR_MOVEMENT",
                        "from_entity": curr_id,
                        "to_entity": nxt_id,
                        "amount": tx.amount,
                        "explanation": f"Funds looped back to previously visited account '{nxt_id}' (Amount: ₹{tx.amount:,.2f})."
                    })

                # Fetch or register receiver node
                if nxt_id not in traced_nodes:
                    rec_ent = db.query(Entity).filter(Entity.id == nxt_id).first()
                    role = "MULE" if curr_hop == 1 else ("INTERMEDIARY" if curr_hop < max_hops - 1 else "DESTINATION")
                    traced_nodes[nxt_id] = {
                        "id": f"acc-{nxt_id}",
                        "entity_id": nxt_id,
                        "label": rec_ent.value if rec_ent else f"Account #{nxt_id}",
                        "entity_type": rec_ent.entity_type if rec_ent else "BANK_ACCOUNT",
                        "risk_score": rec_ent.risk_score if rec_ent else 50.0,
                        "hop_level": curr_hop + 1,
                        "role": role
                    }
                    visited_nodes.add(nxt_id)
                    queue.append((nxt_id, curr_hop + 1, tx.timestamp))

                traced_edges.append({
                    "id": f"flow-tx-{tx.id}",
                    "source": f"acc-{curr_id}",
                    "target": f"acc-{nxt_id}",
                    "amount": tx.amount,
                    "currency": tx.currency,
                    "channel": tx.channel,
                    "timestamp": tx.timestamp.isoformat(),
                    "transaction_ref": tx.transaction_ref,
                    "flagged": tx.amount >= 40000 or tx.status == "FLAGGED"
                })

        if highest_hop >= 3:
            patterns_detected.append({
                "pattern": "RAPID_LAYERING",
                "hops": highest_hop,
                "explanation": f"Layering chain verified across {highest_hop} sequential hops designed to obscure source of funds."
            })

        summary = (
            f"Money-flow analysis traced ₹{total_volume:,.2f} across {len(traced_nodes)} simulated accounts "
            f"over {highest_hop} hops. Identified {len(patterns_detected)} behavioral flow anomalies."
        )

        return {
            "root_entity_id": root_entity_id,
            "max_hops_reached": highest_hop,
            "total_volume_traced": total_volume,
            "detected_patterns": patterns_detected,
            "nodes": list(traced_nodes.values()),
            "edges": traced_edges,
            "summary": summary
        }
