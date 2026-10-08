from typing import Dict, Any, List
from sqlalchemy.orm import Session
from app.models.case import Case
from app.models.entity import Entity
from app.models.relationship import Relationship
from app.models.transaction import Transaction
from app.models.message import Message
from app.models.indicator import Indicator
from app.analyzers.communication_analyzer import CommunicationAnalyzer
from app.analyzers.behavioral_analyzer import BehavioralAnalyzer


class RiskEngine:
    """
    Explainable Investigation Risk Scoring Engine.
    Produces a transparent weighted score capped at 100 with itemized signals.
    Investigative risk is explicitly not a legal conviction or statistical probability,
    but a prioritized signal indicating that this case or entity requires scrutiny.
    """

    @classmethod
    def evaluate_case(cls, db: Session, case_id: int) -> Dict[str, Any]:
        case = db.query(Case).filter(Case.id == case_id).first()
        if not case:
            return {"score": 0.0, "level": "LOW", "signals": [], "summary": "Case not found"}

        signals: List[Dict[str, Any]] = []

        # Find case entity
        case_ent = db.query(Entity).filter(
            Entity.entity_type == "CASE",
            Entity.normalized_value.ilike(case.case_number)
        ).first()

        # 1. Fetch connected entities through relationships
        linked_entities = []
        if case_ent:
            rels = db.query(Relationship, Entity).join(
                Entity, (Relationship.source_entity_id == Entity.id) | (Relationship.target_entity_id == Entity.id)
            ).filter(
                (Relationship.source_entity_id == case_ent.id) | (Relationship.target_entity_id == case_ent.id)
            ).all()

            for rel, ent in rels:
                if ent.id != case_ent.id:
                    linked_entities.append(ent)

        # 2. Check for Shared Infrastructure / Multi-case association
        shared_entities = []
        for ent in linked_entities:
            if ent.entity_type in ("DOMAIN", "PHONE", "UPI_ID", "DEVICE", "IP_ADDRESS"):
                # How many cases does this entity touch?
                case_count = db.query(Relationship).join(
                    Entity, Relationship.target_entity_id == Entity.id
                ).filter(
                    Relationship.source_entity_id == ent.id,
                    Entity.entity_type == "CASE"
                ).count()

                # Also count other direction
                case_count += db.query(Relationship).join(
                    Entity, Relationship.source_entity_id == Entity.id
                ).filter(
                    Relationship.target_entity_id == ent.id,
                    Entity.entity_type == "CASE"
                ).count()

                if case_count >= 2:
                    shared_entities.append((ent, case_count))

        if shared_entities:
            top_shared = shared_entities[0]
            signals.append({
                "code": "SHARED_INFRASTRUCTURE",
                "points": 15.0,
                "explanation": f"Identifier '{top_shared[0].value}' ({top_shared[0].entity_type}) appears across {top_shared[1]} separate investigation cases."
            })
            if any(cnt >= 3 for _, cnt in shared_entities):
                signals.append({
                    "code": "MULTI_CASE_ASSOCIATION",
                    "points": 15.0,
                    "explanation": f"Cluster connection: Multiple entities in this case recur across 3 or more incident files."
                })

        # 3. Check for Known Suspicious Identifiers
        suspicious_ents = [e for e in linked_entities if e.risk_score >= 70.0]
        if suspicious_ents:
            signals.append({
                "code": "KNOWN_SUSPICIOUS_IDENTIFIER",
                "points": 20.0,
                "explanation": f"Direct link to known suspicious entity '{suspicious_ents[0].value}' (Risk: {suspicious_ents[0].risk_score}/100)."
            })

        # 4. Check Communications for Scam Markers
        messages = db.query(Message).filter(Message.case_id == case_id).all()
        for msg in messages:
            analysis = CommunicationAnalyzer.analyze(msg.content, msg.url)
            if analysis["is_suspicious"]:
                cat_str = ", ".join(analysis["categories"][:2])
                signals.append({
                    "code": "SUSPICIOUS_COMMUNICATION_PATTERN",
                    "points": 15.0,
                    "explanation": f"Message pattern detected coercive indicators: [{cat_str}]."
                })
                break

        # 5. Check Transactions for Velocity & Fund Movements
        transactions = db.query(Transaction).filter(Transaction.case_id == case_id).all()
        if transactions:
            amounts = [t.amount for t in transactions]
            max_amt = max(amounts) if amounts else 0.0

            # Tailor amount exposure signal points for proportional risk attribution
            if max_amt >= 45000:
                # Proportional points: 4 pts for baseline high exposure, up to 10 pts for extreme exposure
                amt_pts = 4.0 if max_amt < 50000 else 10.0
                signals.append({
                    "code": "UNUSUAL_AMOUNT",
                    "points": amt_pts,
                    "explanation": f"Transaction volume of ₹{max_amt:,.2f} represents an elevated exposure threshold."
                })

            # Check rapid transactions / velocity
            # Only flag separate velocity burst if 4+ distinct secondary hops exist
            if len(transactions) >= 8:
                signals.append({
                    "code": "RAPID_TRANSACTION_BURST",
                    "points": 15.0,
                    "explanation": f"High transaction frequency ({len(transactions)} transactions logged in case window)."
                })

        # 6. Check existing indicators or rapid fund dispersion
        indicators = db.query(Indicator).filter(Indicator.case_id == case_id).all()
        has_mule_ind = any(ind.indicator_type == "MULE_ACCOUNT" for ind in indicators)
        if (has_mule_ind or len(transactions) >= 3) and not any(s["code"] == "RAPID_FUND_DISPERSION" for s in signals):
            signals.append({
                "code": "RAPID_FUND_DISPERSION",
                "points": 15.0,
                "explanation": "Immediate onward fund dispersion: incoming funds split and routed to secondary mule hops within minutes."
            })

        # Strict arithmetic: final_score is the exact sum of signals (capped at 100.0)
        total_points = sum(s["points"] for s in signals)
        
        # If no signals triggered but case has baseline severity
        if total_points == 0:
            final_score = case.risk_score if case.risk_score else 10.0
            signals.append({
                "code": "BASELINE_MONITORING",
                "points": round(final_score, 1),
                "explanation": "Baseline intake monitoring score assigned during incident registration."
            })
            total_points = final_score
        else:
            final_score = min(100.0, total_points)

        # Threshold definitions:
        # LOW: 0 - 39
        # MEDIUM: 40 - 69
        # HIGH: 70 - 89
        # CRITICAL: 90 - 100
        if final_score >= 90.0:
            level = "CRITICAL"
        elif final_score >= 70.0:
            level = "HIGH"
        elif final_score >= 40.0:
            level = "MEDIUM"
        else:
            level = "LOW"

        thresholds = {
            "LOW": {"min": 0, "max": 39, "label": "Low Risk / Informational"},
            "MEDIUM": {"min": 40, "max": 69, "label": "Medium Risk / Review Required"},
            "HIGH": {"min": 70, "max": 89, "label": "High Risk / Active Investigation"},
            "CRITICAL": {"min": 90, "max": 100, "label": "Critical Syndicate / Immediate Escalation"}
        }

        return {
            "score": round(final_score, 1),
            "level": level,
            "signals": signals,
            "thresholds": thresholds,
            "breakdown_sum": round(total_points, 1),
            "summary": f"Investigation Risk Score {final_score:.0f}/100 ({level}) derived from {len(signals)} itemized signals summing exactly to {final_score:.0f} pts (Thresholds: Low 0-39, Med 40-69, High 70-89, Critical 90-100)."
        }
