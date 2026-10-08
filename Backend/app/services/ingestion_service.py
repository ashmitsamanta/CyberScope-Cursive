from typing import Dict, Any, List, Optional
from sqlalchemy.orm import Session
from datetime import datetime, timezone

from app.models.case import Case
from app.models.entity import Entity
from app.models.message import Message
from app.models.indicator import Indicator
from app.utils.normalization import EntityExtractor
from app.services.entity_service import EntityService
from app.analyzers.communication_analyzer import CommunicationAnalyzer
from app.services.risk_service import RiskEngine
from app.services.graph_service import graph_service


class IngestionService:
    """Ingests synthetic fraud reports, extracting entities and constructing graph edges."""

    @staticmethod
    def ingest_report(
        db: Session,
        title: str,
        content: str,
        channel: str = "SMS",
        sender_phone: Optional[str] = None,
        source: str = "SYNTHETIC_FEED"
    ) -> Dict[str, Any]:
        now = datetime.now(timezone.utc)
        
        # 1. Generate unique case number
        existing_cases = {c[0] for c in db.query(Case.case_number).all()}
        counter = 1000 + len(existing_cases) + 1
        while f"CS-{counter}" in existing_cases:
            counter += 1
        case_number = f"CS-{counter}"

        # 2. Extract entities deterministically from raw text
        extracted = EntityExtractor.extract_all(content)

        # 3. Analyze communications
        comm_analysis = CommunicationAnalyzer.analyze(content)

        # 4. Create Case record
        case = Case(
            case_number=case_number,
            title=title,
            description=content,
            status="NEW",
            severity="HIGH" if comm_analysis["is_suspicious"] else "MEDIUM",
            source=source,
            risk_score=comm_analysis["suspicion_score"],
            created_at=now,
            updated_at=now
        )
        db.add(case)
        db.commit()
        db.refresh(case)

        # 5. Create Case Entity for Graph
        case_entity, _ = EntityService.get_or_create(
            db=db,
            entity_type="CASE",
            value=case.case_number,
            risk_score=case.risk_score,
            metadata={"title": case.title, "case_id": case.id}
        )

        created_entities: List[Entity] = []

        # 6. Ingest Sender Phone if present
        if sender_phone:
            p_ent, _ = EntityService.get_or_create(
                db=db,
                entity_type="PHONE",
                value=sender_phone,
                risk_score=40.0 if comm_analysis["is_suspicious"] else 10.0
            )
            created_entities.append(p_ent)
            EntityService.create_relationship(
                db=db,
                source_id=p_ent.id,
                target_id=case_entity.id,
                relationship_type="REPORTED_IN"
            )

        # 7. Ingest Extracted Phones
        for phone in extracted["phones"]:
            ent, _ = EntityService.get_or_create(db=db, entity_type="PHONE", value=phone, risk_score=35.0)
            created_entities.append(ent)
            EntityService.create_relationship(db=db, source_id=ent.id, target_id=case_entity.id, relationship_type="REPORTED_IN")

        # 8. Ingest Extracted Domains & URLs
        for dom in extracted["domains"]:
            ent, _ = EntityService.get_or_create(db=db, entity_type="DOMAIN", value=dom, risk_score=45.0)
            created_entities.append(ent)
            EntityService.create_relationship(db=db, source_id=ent.id, target_id=case_entity.id, relationship_type="REPORTED_IN")

        for url in extracted["urls"]:
            ent, _ = EntityService.get_or_create(db=db, entity_type="URL", value=url, risk_score=50.0)
            created_entities.append(ent)
            EntityService.create_relationship(db=db, source_id=ent.id, target_id=case_entity.id, relationship_type="REPORTED_IN")

        # 9. Ingest Extracted UPI IDs
        for upi in extracted["upi_ids"]:
            ent, _ = EntityService.get_or_create(db=db, entity_type="UPI_ID", value=upi, risk_score=40.0)
            created_entities.append(ent)
            EntityService.create_relationship(db=db, source_id=ent.id, target_id=case_entity.id, relationship_type="REPORTED_IN")

        # 10. Ingest Message
        primary_url = extracted["urls"][0] if extracted["urls"] else None
        msg = Message(
            timestamp=now,
            sender_phone=sender_phone or (extracted["phones"][0] if extracted["phones"] else None),
            receiver_phone="+919876543210",  # simulated victim
            channel=channel,
            subject=title,
            content=content,
            url=primary_url,
            case_id=case.id
        )
        db.add(msg)

        # 11. Record Indicators
        for finding in comm_analysis.get("findings", []):
            ind = Indicator(
                case_id=case.id,
                entity_id=case_entity.id,
                indicator_type=finding["category"],
                severity="HIGH",
                description=finding["explanation"],
                detected_at=now
            )
            db.add(ind)

        db.commit()

        # 12. Re-evaluate case risk score
        risk_result = RiskEngine.evaluate_case(db, case.id)
        case.risk_score = risk_result["score"]
        case.severity = risk_result["level"]
        case_entity.risk_score = risk_result["score"]
        db.commit()

        # Invalidate graph sync
        graph_service.sync_from_db(db, force=True)

        return {
            "id": case.id,
            "case_id": case.id,
            "case_number": case.case_number,
            "title": case.title,
            "description": case.description,
            "risk_score": case.risk_score,
            "severity": case.severity,
            "extracted_entities": [e.to_dict() for e in created_entities],
            "risk_summary": risk_result["summary"]
        }
