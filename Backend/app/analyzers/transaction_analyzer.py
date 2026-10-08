from typing import Dict, Any, List, Optional


class TransactionAnalyzer:
    """Analyzes individual and pairwise transactions for fraud indicators."""

    @staticmethod
    def evaluate_transaction(
        transaction: Dict[str, Any],
        sender_entity: Optional[Dict[str, Any]] = None,
        receiver_entity: Optional[Dict[str, Any]] = None,
        recent_sender_txs: Optional[List[Dict[str, Any]]] = None
    ) -> Dict[str, Any]:
        """
        Calculates an investigation risk score and itemized signals for a single transaction.
        """
        signals = []
        amount = transaction.get("amount", 0.0)
        channel = transaction.get("channel", "UPI")

        # 1. High-value transaction threshold
        if amount >= 100000:
            signals.append({
                "code": "LARGE_VALUE_TRANSFER",
                "points": 15.0,
                "explanation": f"High value transaction of ₹{amount:,.2f} exceeding ₹1,00,000 threshold."
            })
        elif amount >= 45000:
            signals.append({
                "code": "SIGNIFICANT_TRANSFER",
                "points": 8.0,
                "explanation": f"Substantial transfer of ₹{amount:,.2f}."
            })

        # 2. Risk from counterparties
        if receiver_entity and receiver_entity.get("risk_score", 0.0) >= 60.0:
            signals.append({
                "code": "HIGH_RISK_BENEFICIARY",
                "points": 25.0,
                "explanation": f"Beneficiary entity '{receiver_entity.get('value')}' has high risk score ({receiver_entity.get('risk_score')}/100)."
            })

        if sender_entity and sender_entity.get("risk_score", 0.0) >= 60.0:
            signals.append({
                "code": "HIGH_RISK_ORIGINATOR",
                "points": 20.0,
                "explanation": f"Originator entity '{sender_entity.get('value')}' has elevated risk score ({sender_entity.get('risk_score')}/100)."
            })

        # 3. Micro-structuring (just below reporting thresholds e.g. 48,000 - 49,999)
        if 48000 <= amount <= 49999:
            signals.append({
                "code": "POTENTIAL_STRUCTURING",
                "points": 12.0,
                "explanation": f"Amount ₹{amount:,.2f} closely benchmarks the ₹50,000 regulatory reporting threshold, indicating possible structuring."
            })

        # 4. Immediate Layering / Velocity
        if recent_sender_txs:
            # Check if sender made > 3 transactions in the last 15 minutes
            if len(recent_sender_txs) >= 3:
                signals.append({
                    "code": "BURST_TRANSFER",
                    "points": 15.0,
                    "explanation": f"Rapid sequence of {len(recent_sender_txs)} outbound transfers within short time window."
                })

        total_points = sum(s["points"] for s in signals)
        risk_score = min(100.0, total_points)

        return {
            "risk_score": risk_score,
            "status": "FLAGGED" if risk_score >= 40.0 else "SUCCESS",
            "signals": signals,
            "is_flagged": risk_score >= 40.0
        }
