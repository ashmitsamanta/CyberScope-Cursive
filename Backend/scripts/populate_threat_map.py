import os
import sys
from datetime import datetime, timezone
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

# Add backend directory to sys.path
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
ROOT_DIR = os.path.abspath(os.path.join(BASE_DIR, ".."))
sys.path.insert(0, BASE_DIR)

from app.database import Base
from app.models.threat_node import ThreatNode
from app.models.entity import Entity
from app.models.relationship import Relationship
from app.models.transaction import Transaction
from app.services.threat_map_service import ThreatMapService, INITIAL_THREAT_NODES


def populate_sqlite_db(db_path: str):
    print(f"\n[+] Synchronizing threat intelligence database: {db_path}")
    abs_path = os.path.abspath(db_path)
    if not os.path.exists(abs_path):
        print(f"File {abs_path} does not exist, creating and initializing tables...")

    engine = create_engine(f"sqlite:///{abs_path}", connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=engine)

    # Migrate table schema if pincode column is missing in existing threat_nodes table
    with engine.connect() as conn:
        try:
            col_info = conn.execute(text("PRAGMA table_info(threat_nodes);")).fetchall()
            col_names = [c[1] for c in col_info]
            if col_names and "pincode" not in col_names:
                conn.execute(text("ALTER TABLE threat_nodes ADD COLUMN pincode VARCHAR(20) DEFAULT '110001';"))
                conn.commit()
                print(" -> Added missing 'pincode' column to threat_nodes table.")
        except Exception as e:
            print(f" -> Schema migration note: {e}")

    Session = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    db = Session()

    try:
        count = ThreatMapService.ensure_seeded(db)
        total_threats = db.query(ThreatNode).count()
        total_entities = db.query(Entity).count()
        total_relationships = db.query(Relationship).count()
        total_tx_with_ip = db.query(Transaction).filter(Transaction.ip_id != None).count()
        
        # Verify IP 198.51.100.10 specifically
        p_node = db.query(ThreatNode).filter(ThreatNode.ip == "198.51.100.10").first()
        if p_node:
            print(f" -> Verified Preexisting IP 198.51.100.10: {p_node.city}, {p_node.state} (PIN: {p_node.pincode})")

        print(f" -> Successfully populated {db_path} | Threat Nodes: {total_threats} | Entities: {total_entities} | Relationships: {total_relationships} | Tx Linked to IPs: {total_tx_with_ip}")
    except Exception as e:
        print(f" [!] Error populating {db_path}: {e}")
        db.rollback()
    finally:
        db.close()


def main():
    db_paths = [
        os.path.join(BASE_DIR, "cyberscope.db"),
        os.path.join(ROOT_DIR, "cyberscope.db")
    ]
    for p in db_paths:
        populate_sqlite_db(p)

    print("\n[OK] All CyberScope threat intelligence databases updated with authentic Indian attacker infrastructure.")


if __name__ == "__main__":
    main()
