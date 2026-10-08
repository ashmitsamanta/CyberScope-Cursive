from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta, timezone


class BehavioralAnalyzer:
    """
    Detects financial fraud behavioral anomalies:
    - Burst velocity (transactions within 15 mins)
    - Fan-out (single account broadcasting to many accounts)
    - Fan-in (many accounts funneling into single aggregator account)
    - Dormancy-to-burst (sudden awakening after inactivity)
    - Amount anomalies (deviations from historical mean/median)
    - Rapid redistribution / Mule behavior (inflow dispersed rapidly)
    """

    @staticmethod
    def analyze_account_transactions(
        account_id: int,
        transactions: List[Dict[str, Any]],
        reference_time: Optional[datetime] = None
    ) -> Dict[str, Any]:
        """
        Analyzes the transaction history for an account.
        transactions: list of dicts with: id, timestamp, sender_entity_id, receiver_entity_id, amount, status
        """
        if not transactions:
            return {
                "velocity_risk": 0.0,
                "fan_out_ratio": 0.0,
                "fan_in_ratio": 0.0,
                "signals": [],
                "patterns_detected": []
            }

        # Ensure sorted by timestamp
        def parse_ts(t):
            val = t.get("timestamp")
            if isinstance(val, str):
                try:
                    return datetime.fromisoformat(val.replace("Z", "+00:00"))
                except Exception:
                    return datetime.now(timezone.utc)
            elif isinstance(val, datetime):
                return val
            return datetime.now(timezone.utc)

        sorted_txs = sorted(transactions, key=parse_ts)
        signals = []
        patterns = []

        now = reference_time or (parse_ts(sorted_txs[-1]) if sorted_txs else datetime.now(timezone.utc))

        # Separate inbound vs outbound
        inbound = [tx for tx in sorted_txs if tx.get("receiver_entity_id") == account_id]
        outbound = [tx for tx in sorted_txs if tx.get("sender_entity_id") == account_id]

        # 1. Velocity Analysis: 15-minute burst window
        window_15m_start = now - timedelta(minutes=15)
        recent_15m = [tx for tx in sorted_txs if parse_ts(tx) >= window_15m_start]

        if len(recent_15m) >= 4:
            signals.append({
                "code": "RAPID_TRANSACTION_BURST",
                "points": 15.0,
                "explanation": f"Observed burst velocity of {len(recent_15m)} transactions within 15 minutes."
            })
            patterns.append("BURST_VELOCITY")

        # 2. Fan-Out Pattern (One -> Many)
        window_1h_start = now - timedelta(hours=1)
        recent_outbound_1h = [tx for tx in outbound if parse_ts(tx) >= window_1h_start]
        distinct_recipients = set(tx.get("receiver_entity_id") for tx in recent_outbound_1h)

        if len(distinct_recipients) >= 3 and len(recent_outbound_1h) >= 3:
            signals.append({
                "code": "HIGH_FAN_OUT",
                "points": 15.0,
                "explanation": f"Account distributed funds rapidly to {len(distinct_recipients)} distinct beneficiaries within 1 hour."
            })
            patterns.append("FAN_OUT")

        # 3. Fan-In Pattern (Many -> One)
        recent_inbound_1h = [tx for tx in inbound if parse_ts(tx) >= window_1h_start]
        distinct_senders = set(tx.get("sender_entity_id") for tx in recent_inbound_1h)

        if len(distinct_senders) >= 3 and len(recent_inbound_1h) >= 3:
            signals.append({
                "code": "HIGH_FAN_IN",
                "points": 15.0,
                "explanation": f"Account aggregated incoming funds from {len(distinct_senders)} distinct senders within 1 hour."
            })
            patterns.append("FAN_IN")

        # 4. Rapid Fund Dispersion / Mule Behavior:
        # Check if an inflow is followed by outbound transfers of >= 80% volume within 30 minutes
        for in_tx in inbound:
            in_time = parse_ts(in_tx)
            in_amt = in_tx.get("amount", 0.0)
            if in_amt < 1000:
                continue

            # Outbound transactions within 30 mins after this inflow
            quick_outbounds = [
                tx for tx in outbound
                if in_time <= parse_ts(tx) <= in_time + timedelta(minutes=30)
            ]
            total_quick_out = sum(tx.get("amount", 0.0) for tx in quick_outbounds)

            if total_quick_out >= in_amt * 0.75 and len(quick_outbounds) >= 2:
                signals.append({
                    "code": "RAPID_FUND_DISPERSION",
                    "points": 20.0,
                    "explanation": f"Simulated mule pattern: Inflow of ₹{in_amt:,.2f} rapidly redistributed (₹{total_quick_out:,.2f} dispersed to {len(quick_outbounds)} recipients within 30 mins)."
                })
                patterns.append("MULE_BEHAVIOR")
                break

        # 5. Dormancy to Sudden Burst:
        # Check if gap between previous transaction and current burst > 30 days
        if len(sorted_txs) >= 2:
            for i in range(len(sorted_txs) - 1):
                t1 = parse_ts(sorted_txs[i])
                t2 = parse_ts(sorted_txs[i + 1])
                gap_days = (t2 - t1).total_seconds() / 86400.0
                if gap_days >= 30 and len([t for t in sorted_txs if parse_ts(t) >= t2]) >= 3:
                    signals.append({
                        "code": "DORMANCY_TO_BURST",
                        "points": 15.0,
                        "explanation": f"Account was dormant for {int(gap_days)} days before exhibiting sudden high-velocity transfers."
                    })
                    patterns.append("DORMANCY_BURST")
                    break

        # 6. Amount Anomaly:
        # If current transaction is > 3.5x historical median
        amounts = [tx.get("amount", 0.0) for tx in sorted_txs if tx.get("amount", 0.0) > 0]
        if len(amounts) >= 4:
            sorted_amts = sorted(amounts[:-1])  # all except latest
            median_amt = sorted_amts[len(sorted_amts) // 2]
            latest_amt = amounts[-1]
            if median_amt > 0 and latest_amt >= median_amt * 3.5 and latest_amt > 15000:
                signals.append({
                    "code": "UNUSUAL_AMOUNT",
                    "points": 10.0,
                    "explanation": f"Latest transaction amount of ₹{latest_amt:,.2f} is significantly higher than historical median (₹{median_amt:,.2f})."
                })
                patterns.append("AMOUNT_ANOMALY")

        total_points = sum(s["points"] for s in signals)
        return {
            "behavior_risk_score": min(100.0, total_points),
            "signals": signals,
            "patterns_detected": list(set(patterns)),
            "total_transactions": len(sorted_txs),
            "inbound_count": len(inbound),
            "outbound_count": len(outbound),
        }
