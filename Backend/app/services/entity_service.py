from typing import Optional, Dict, Any, List, Tuple
from sqlalchemy.orm import Session
from datetime import datetime, timezone
from app.models.entity import Entity
from app.models.relationship import Relationship
from app.models.case import Case
from app.utils.normalization import normalize_entity_value


class EntityService:
    """Handles entity persistence, normalization, deduplication, and resolution."""

    @staticmethod
    def get_or_create(
        db: Session,
        entity_type: str,
        value: str,
        risk_score: float = 0.0,
        metadata: Optional[Dict[str, Any]] = None,
        timestamp: Optional[datetime] = None
    ) -> Tuple[Entity, bool]:
        """
        Deduplicates entities deterministically by (entity_type, normalized_value).
        Returns (Entity, was_created).
        """
        norm_val = normalize_entity_value(entity_type, value)
        now = timestamp or datetime.now(timezone.utc)

        existing = db.query(Entity).filter(
            Entity.entity_type == entity_type.upper(),
            Entity.normalized_value == norm_val
        ).first()

        if existing:
            # Update last seen safely across naive/aware database timestamps
            if existing.last_seen:
                comp_now = now.replace(tzinfo=None) if existing.last_seen.tzinfo is None else (now if now.tzinfo else now.replace(tzinfo=timezone.utc))
                existing.last_seen = max(existing.last_seen, comp_now)
            else:
                existing.last_seen = now

            if risk_score > existing.risk_score:
                existing.risk_score = risk_score
            if metadata:
                existing.meta_data = {**(existing.meta_data or {}), **metadata}
            db.commit()
            db.refresh(existing)
            return existing, False

        new_entity = Entity(
            entity_type=entity_type.upper(),
            value=value.strip(),
            normalized_value=norm_val,
            risk_score=risk_score,
            first_seen=now,
            last_seen=now,
            meta_data=metadata or {}
        )
        db.add(new_entity)
        db.commit()
        db.refresh(new_entity)
        return new_entity, True

    @staticmethod
    def create_relationship(
        db: Session,
        source_id: int,
        target_id: int,
        relationship_type: str,
        confidence: float = 1.0,
        metadata: Optional[Dict[str, Any]] = None,
        timestamp: Optional[datetime] = None
    ) -> Relationship:
        """Creates or updates a relationship between two entities."""
        now = timestamp or datetime.now(timezone.utc)
        existing = db.query(Relationship).filter(
            Relationship.source_entity_id == source_id,
            Relationship.target_entity_id == target_id,
            Relationship.relationship_type == relationship_type
        ).first()

        if existing:
            existing.last_seen = now
            if metadata:
                existing.meta_data = {**(existing.meta_data or {}), **metadata}
            db.commit()
            db.refresh(existing)
            return existing

        rel = Relationship(
            source_entity_id=source_id,
            target_entity_id=target_id,
            relationship_type=relationship_type,
            confidence=confidence,
            first_seen=now,
            last_seen=now,
            meta_data=metadata or {}
        )
        db.add(rel)
        db.commit()
        db.refresh(rel)
        return rel

    @staticmethod
    def get_entity_neighbors(db: Session, entity_id: int) -> List[Dict[str, Any]]:
        """Retrieves outgoing and incoming neighbors for an entity."""
        neighbors = []

        # Outgoing
        out_rels = db.query(Relationship, Entity).join(
            Entity, Relationship.target_entity_id == Entity.id
        ).filter(Relationship.source_entity_id == entity_id).all()

        for rel, target in out_rels:
            neighbors.append({
                "id": target.id,
                "entity_type": target.entity_type,
                "value": target.value,
                "normalized_value": target.normalized_value,
                "risk_score": target.risk_score,
                "relationship_type": rel.relationship_type,
                "confidence": rel.confidence,
                "direction": "outgoing"
            })

        # Incoming
        in_rels = db.query(Relationship, Entity).join(
            Entity, Relationship.source_entity_id == Entity.id
        ).filter(Relationship.target_entity_id == entity_id).all()

        for rel, source in in_rels:
            neighbors.append({
                "id": source.id,
                "entity_type": source.entity_type,
                "value": source.value,
                "normalized_value": source.normalized_value,
                "risk_score": source.risk_score,
                "relationship_type": rel.relationship_type,
                "confidence": rel.confidence,
                "direction": "incoming"
            })

        return neighbors

    @staticmethod
    def find_connected_cases(db: Session, entity_id: int) -> List[Dict[str, Any]]:
        """
        Finds all cases connected directly or through relationships to this entity.
        """
        # Look for case entities linked to this entity
        cases = []
        rels = db.query(Relationship, Entity).join(
            Entity, (Relationship.source_entity_id == Entity.id) | (Relationship.target_entity_id == Entity.id)
        ).filter(
            (Relationship.source_entity_id == entity_id) | (Relationship.target_entity_id == entity_id)
        ).all()

        case_numbers = set()
        for rel, other in rels:
            if other.id != entity_id and other.entity_type == "CASE":
                case_numbers.add(other.value)

        # Also search cases table where this entity might be referenced
        if case_numbers:
            case_records = db.query(Case).filter(Case.case_number.in_(list(case_numbers))).all()
            for c in case_records:
                cases.append({
                    "id": c.id,
                    "case_number": c.case_number,
                    "title": c.title,
                    "status": c.status,
                    "severity": c.severity,
                    "risk_score": c.risk_score,
                })

        return cases
