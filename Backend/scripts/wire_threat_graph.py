"""
CyberScope Threat Graph Topology Wiring
Delegates to ThreatMapService to wire attacker IP topology, victim linkage
(ACCESSED_FROM / TARGETED_BY / CONTACTED), and transaction IP telemetry
into the Fraud Graph for each known database.
"""
import os
import sys
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
ROOT_DIR = os.path.abspath(os.path.join(BASE_DIR, ".."))
sys.path.insert(0, BASE_DIR)

from app.models.entity import Entity
from app.models.relationship import Relationship
from app.models.transaction import Transaction
from app.services.threat_map_service import ThreatMapService


def wire_database(db_path: str):
    print("\n==================================================")
    print(f"Wiring Threat Graph Topology for: {db_path}")
    print("==================================================")

    abs_path = os.path.abspath(db_path)
    if not os.path.exists(abs_path):
        print(f"Database {abs_path} does not exist. Skipping.")
        return

    engine = create_engine(f"sqlite:///{abs_path}", connect_args={"check_same_thread": False})
    Session = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    db = Session()
    try:
        ThreatMapService.ensure_seeded(db)

        ip_ids = {e.id for e in db.query(Entity).filter(Entity.entity_type == "IP_ADDRESS").all()}
        ip_rels = db.query(Relationship).filter(
            (Relationship.source_entity_id.in_(ip_ids)) |
            (Relationship.target_entity_id.in_(ip_ids))
        ).count()
        victim_links = db.query(Relationship).filter(
            Relationship.relationship_type.in_(("ACCESSED_FROM", "TARGETED_BY", "CONTACTED"))
        ).count()
        txs_with_ip = db.query(Transaction).filter(Transaction.ip_id != None).count()

        print(f" -> Relationships touching attacker IPs: {ip_rels}")
        print(f" -> Victim linkage edges (ACCESSED_FROM / TARGETED_BY / CONTACTED): {victim_links}")
        print(f" -> Transactions bound to attacker IPs: {txs_with_ip}")
    finally:
        db.close()


def main():
    db_paths = [
        os.path.join(BASE_DIR, "cyberscope.db"),
        os.path.join(ROOT_DIR, "cyberscope.db")
    ]
    for p in db_paths:
        wire_database(p)

    print("\n[SUCCESS] Threat graph topology successfully wired across all databases.")


if __name__ == "__main__":
    main()
