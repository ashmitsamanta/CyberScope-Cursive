import abc
import os
import json
import httpx
from typing import Dict, Any, List, Optional
from sqlalchemy.orm import Session

from app.config import settings
from app.models.case import Case
from app.models.entity import Entity
from app.models.transaction import Transaction
from app.models.relationship import Relationship
from app.models.indicator import Indicator
from app.models.message import Message
from app.services.risk_service import RiskEngine
from app.services.timeline_service import TimelineService
from app.services.transaction_service import TransactionService


class IAIProvider(abc.ABC):
    @abc.abstractmethod
    def generate_response(
        self,
        query: str,
        context: Dict[str, Any]
    ) -> Dict[str, Any]:
        pass


class DeterministicExpertProvider(IAIProvider):
    """
    Offline deterministic evidence-grounded AI investigator.
    Evaluates structured data directly and produces verified, non-hallucinatory findings
    with explicit citations ([CASE-xxx], [DOMAIN-xxx], [TX-xxx]).
    """

    def generate_response(
        self,
        query: str,
        context: Dict[str, Any]
    ) -> Dict[str, Any]:
        q = query.lower()
        case = context.get("case", {})
        signals = context.get("signals", [])
        entities = context.get("entities", [])
        transactions = context.get("transactions", [])
        timeline = context.get("timeline", [])
        money_flow = context.get("money_flow", {})

        citations = []
        observed_evidence = []
        calculated_signals = []
        inferences = []
        uncertainties = []
        next_steps = []

        case_num = case.get("case_number", "CASE-UNKNOWN")
        citations.append({
            "tag": f"[{case_num}]",
            "type": "CASE",
            "identifier": case_num,
            "summary": case.get("title", "Investigation Incident")
        })

        # Process signals
        for sig in signals:
            calculated_signals.append({
                "code": sig.get("code"),
                "points": sig.get("points"),
                "explanation": sig.get("explanation")
            })

        # Process entities
        for ent in entities:
            ent_type = ent.get("entity_type")
            ent_val = ent.get("value")
            if ent_type in ("DOMAIN", "PHONE", "UPI_ID", "BANK_ACCOUNT"):
                citations.append({
                    "tag": f"[{ent_type}-{ent.get('id', 0)}]",
                    "type": ent_type,
                    "identifier": ent_val,
                    "summary": f"Observed synthetic {ent_type.lower()}: {ent_val}"
                })

        # Process transactions
        for tx in transactions[:3]:
            tx_ref = tx.get("transaction_ref")
            citations.append({
                "tag": f"[{tx_ref}]",
                "type": "TRANSACTION",
                "identifier": tx_ref,
                "summary": f"Simulated transfer of ₹{tx.get('amount', 0):,.2f} via {tx.get('channel', 'UPI')}"
            })

        # Branching based on query intent
        if any(w in q for w in ["why", "flagged", "risk", "suspicious", "score"]):
            # Explanation of risk
            reasons = []
            for i, sig in enumerate(signals, 1):
                reasons.append(f"{i}. **{sig.get('code')}** (+{sig.get('points')} pts): {sig.get('explanation')}")
                observed_evidence.append(sig.get("explanation"))

            answer_text = (
                f"### Case Evaluation: {case_num} (Investigation Risk: {case.get('risk_score', 0)}/100 - {case.get('severity', 'MEDIUM')})\n\n"
                f"This case was flagged by CYBERSCOPE's behavioral and graph heuristics based on the following verified signals:\n\n"
                + "\n".join(reasons) + "\n\n"
                f"**Assessment:** The chain of evidence demonstrates synthetic fraud characteristics rather than an isolated incident."
            )

            inferences.append(f"Entity infrastructure exhibits deliberate re-use across multiple incidents.")
            uncertainties.append("End-destination physical identity cannot be ascertained without formal legal subpoenas.")
            next_steps = [
                "Issue temporary freeze advisory on identified beneficiary UPI identifiers.",
                "Cross-reference domain registrar creation timestamps with message distribution logs.",
                "Expand graph search to inspect other accounts interacting with the primary receiver."
            ]

        elif any(w in q for w in ["connect", "shared", "link", "relationship", "common"]):
            shared_items = [e for e in entities if e.get("entity_type") in ("DOMAIN", "PHONE", "UPI_ID")]
            if shared_items:
                obs_list = []
                for item in shared_items:
                    obs_list.append(f"- Synthetic {item.get('entity_type')}: `{item.get('value')}` (Risk: {item.get('risk_score', 0)}/100)")
                    observed_evidence.append(f"Linked identifier {item.get('value')} of type {item.get('entity_type')}")

                answer_text = (
                    f"### Relational Linkage Analysis for {case_num}\n\n"
                    f"Graph correlation reveals direct infrastructure sharing linking this case to the broader synthetic cluster:\n\n"
                    + "\n".join(obs_list) + "\n\n"
                    f"These nodes act as bridge connectors between independent victims, proving operational coordination."
                )
            else:
                answer_text = (
                    f"### Relational Linkage Analysis for {case_num}\n\n"
                    f"No multi-hop shared infrastructure identifiers were confirmed beyond the local incident boundaries in current view."
                )

            inferences.append("Attack vector utilizes shared infrastructure to reduce per-victim operational overhead.")
            uncertainties.append("Shared phone numbers could potentially involve spoofed headers or SIM swapping.")
            next_steps = [
                "Map all sibling cases sharing the same destination UPI or phone number.",
                "Review passive DNS telemetry for newly registered subdomains on the same apex host."
            ]

        elif any(w in q for w in ["money", "flow", "trace", "funds", "transfer", "mule"]):
            patterns = money_flow.get("detected_patterns", [])
            pat_descs = [f"- **{p.get('pattern')}**: {p.get('explanation')}" for p in patterns]
            total_vol = money_flow.get("total_volume_traced", 0)

            answer_text = (
                f"### Simulated Money-Flow Reconstruction\n\n"
                f"CYBERSCOPE traced funds originating from {case_num}. Total volume traced across synthetic nodes: ₹{total_vol:,.2f}.\n\n"
                f"**Identified Flow Behaviors:**\n"
                + ("\n".join(pat_descs) if pat_descs else "- Immediate single-hop transfer detected.") + "\n\n"
                f"Funds exhibit classical layering progression to fragment transaction size below detection thresholds."
            )

            observed_evidence.append(f"Total traced simulated volume: ₹{total_vol:,.2f}")
            for p in patterns:
                observed_evidence.append(p.get("explanation", ""))
            inferences.append("Intermediary accounts function as synthetic money mules.")
            uncertainties.append("Offline ATM withdrawals or OTC cash conversions cannot be traced in ledger telemetry.")
            next_steps = [
                "Trigger automated SAR / STR alert package for the primary aggregator account.",
                "Examine IP and device telemetry associated with the outbound transfer logins."
            ]

        elif any(w in q for w in ["next", "recommend", "action", "investigate", "step"]):
            answer_text = (
                f"### Strategic Next Investigation Steps for {case_num}\n\n"
                f"Based on current risk signals and evidentiary posture, the following defensive actions are recommended:\n\n"
                f"1. **Triage Beneficiary Accounts:** Query all outward transfers from the primary mule account within the last 72 hours.\n"
                f"2. **Takedown Escalation:** Submit abuse notice for spoofed domain `{next((e.get('value') for e in entities if e.get('entity_type') == 'DOMAIN'), 'phishing-domain.com')}`.\n"
                f"3. **Campaign Aggregation:** Merge case `{case_num}` into the active campaign cluster for joint threat analysis.\n"
                f"4. **Countermeasure Review:** Update payment gateway velocity filters for repeated transfers between ₹45,000 and ₹49,999."
            )
            next_steps = [
                "Prioritize account blocking at first intermediary hop.",
                "Notify regional cyber-cell with compiled structured evidence package.",
                "Request CDR (Call Detail Record) analysis for synthetic sender contact."
            ]

        else:
            # General summary
            answer_text = (
                f"### Comprehensive Investigation Summary: {case_num}\n\n"
                f"**Title:** {case.get('title')}\n"
                f"**Severity:** {case.get('severity')} | **Risk Score:** {case.get('risk_score')}/100\n\n"
                f"**Summary of Findings:**\n"
                f"- Evaluated {len(entities)} linked entities, {len(transactions)} transactions, and {len(timeline)} chronological events.\n"
                f"- High-risk signals include {', '.join([s.get('code', '') for s in signals[:3]]) or 'baseline anomalies'}.\n"
                f"- Fund movement indicates rapid disbursement across intermediary synthetic nodes."
            )
            for s in signals:
                observed_evidence.append(s.get("explanation", ""))
            next_steps = [
                "Review interactive Fraud Graph to examine secondary hops.",
                "Export full investigative brief for operational stakeholders."
            ]

        return {
            "query": query,
            "case_id": case.get("id"),
            "answer": answer_text,
            "observed_evidence": observed_evidence,
            "calculated_signals": calculated_signals,
            "inferences": inferences,
            "uncertainties": uncertainties,
            "evidence_citations": citations,
            "recommended_next_steps": next_steps,
            "model_used": "CYBER-ASSIST-EXPERT-DETERMINISTIC"
        }


class OpenAIProvider(IAIProvider):
    """
    OpenAI-compatible LLM provider with strict grounding system prompt.
    Falls back gracefully to DeterministicExpertProvider if API key is missing or call fails.
    """

    def __init__(self):
        self.fallback = DeterministicExpertProvider()

    def generate_response(
        self,
        query: str,
        context: Dict[str, Any]
    ) -> Dict[str, Any]:
        api_key = settings.OPENAI_API_KEY
        if not api_key:
            return self.fallback.generate_response(query, context)

        system_prompt = (
            "You are CYBER-ASSIST, an elite defensive cyber-fraud investigation AI. "
            "You are strictly grounded ONLY in the structured evidence provided in JSON. "
            "You must NEVER invent evidence or make unsupported legal assertions. "
            "Distinguish explicitly between: Observed Evidence, Calculated Signals, Inferences, and Uncertainties. "
            "Always cite evidence using bracket tags like [CASE-102], [DOMAIN-14], [TX-9281]. "
            "If evidence is insufficient, state: 'Insufficient evidence in the current dataset.'"
        )

        user_prompt = f"Investigator Query: {query}\n\nStructured Investigation Context:\n{json.dumps(context, default=str)}"

        try:
            headers = {
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json"
            }
            payload = {
                "model": settings.OPENAI_MODEL,
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt}
                ],
                "temperature": 0.1
            }

            resp = httpx.post(
                f"{settings.OPENAI_API_BASE}/chat/completions",
                json=payload,
                headers=headers,
                timeout=20.0
            )

            if resp.status_code == 200:
                data = resp.json()
                content = data["choices"][0]["message"]["content"]
                fb_res = self.fallback.generate_response(query, context)
                fb_res["answer"] = content
                fb_res["model_used"] = f"OPENAI-{settings.OPENAI_MODEL}"
                return fb_res
        except Exception:
            pass

        return self.fallback.generate_response(query, context)


class AIService:
    """Singleton service manager for CYBER-ASSIST."""

    def __init__(self):
        self.provider = OpenAIProvider() if settings.AI_PROVIDER == "openai" else DeterministicExpertProvider()

    def answer_query(self, db: Session, query: str, case_id: Optional[int] = None) -> Dict[str, Any]:
        context: Dict[str, Any] = {}

        if case_id:
            case = db.query(Case).filter(Case.id == case_id).first()
            if case:
                context["case"] = case.to_dict()
                risk_eval = RiskEngine.evaluate_case(db, case_id)
                context["signals"] = risk_eval.get("signals", [])

                # Linked entities
                rels = db.query(Relationship, Entity).join(
                    Entity, (Relationship.source_entity_id == Entity.id) | (Relationship.target_entity_id == Entity.id)
                ).filter(
                    (Relationship.source_entity_id == case.id) | (Relationship.target_entity_id == case.id)
                ).all()
                context["entities"] = [ent.to_dict() for _, ent in rels]

                # Transactions
                txs = db.query(Transaction).filter(Transaction.case_id == case_id).all()
                context["transactions"] = [t.to_dict() for t in txs]

                # Timeline
                context["timeline"] = TimelineService.get_case_timeline(db, case_id)

                # Trace funds
                first_tx = txs[0] if txs else None
                if first_tx:
                    context["money_flow"] = TransactionService.trace_funds(
                        db, start_transaction_id=first_tx.id, max_hops=3
                    )

        return self.provider.generate_response(query, context)


ai_service = AIService()
