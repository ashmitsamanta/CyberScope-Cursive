import os
import sys
from datetime import datetime, timezone

# Add backend directory to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.database import engine, Base, SessionLocal
from app.models.case import Case
from app.models.entity import Entity
from app.models.relationship import Relationship
from app.models.transaction import Transaction
from app.models.message import Message
from app.models.indicator import Indicator
from app.models.campaign import Campaign
from app.models.investigation import InvestigationLog
from app.models.user import User
from app.models.threat_node import ThreatNode
from app.services.auth_service import hash_password
from scripts.generate_dataset import generate_synthetic_dataset
from app.services.graph_service import graph_service
from app.services.threat_map_service import ThreatMapService


import time

def seed_database(db_session=None, drop_existing=True):
    print("==================================================")
    print("CYBERSCOPE: Initializing Demo Seeding (Operation Phantom KYC)")
    print("==================================================")

    # 1. Connection retry loop (ensures Docker Postgres container readiness)
    max_retries = 10
    connected = False
    for attempt in range(1, max_retries + 1):
        try:
            if drop_existing:
                Base.metadata.drop_all(bind=engine)
            Base.metadata.create_all(bind=engine)
            connected = True
            break
        except Exception as e:
            print(f"[WARN] Database connection attempt {attempt}/{max_retries} failed: {e}. Retrying in 2s...")
            time.sleep(2)

    if not connected:
        raise RuntimeError("Could not connect to database after multiple retries.")

    db = db_session if db_session is not None else SessionLocal()

    # 2. Generate dataset
    data = generate_synthetic_dataset(profile="demo")

    print("Checking / Seeding Demo Investigator User...")
    demo_user_password = os.environ.get("DEMO_USER_PASSWORD")
    if os.environ.get("APP_ENV") == "development" and demo_user_password:
        demo_user = db.query(User).filter(User.email == "investigator@cyberscope.io").first()
        if not demo_user:
            demo_user = User(
                email="investigator@cyberscope.io",
                password_hash=hash_password(demo_user_password),
                name="Investigator Demo",
                phone="+919876543210",
                role="Investigator",
                organization="TetraByte Cyber Defense",
                is_verified_email=True,
                is_verified_phone=True,
                is_active=True
            )
            db.add(demo_user)
            db.commit()
            print(" - Demo Investigator User seeded.")
    else:
        print(" - Demo Investigator User seeding skipped.")

    # 4. Seed Campaigns
    print("Inserting Campaigns...")
    camp_map = {}
    for c in data["campaigns"]:
        camp_obj = Campaign(
            campaign_id=c["campaign_id"],
            name=c["name"],
            description=c["description"],
            risk_score=c["risk_score"],
            case_count=c["case_count"],
            entity_count=c["entity_count"],
            status=c["status"],
            first_seen=datetime.fromisoformat(c["first_seen"]),
            last_seen=datetime.fromisoformat(c["last_seen"]),
            shared_indicators=c.get("shared_indicators", {})
        )
        db.add(camp_obj)
        db.flush()
        camp_map[c["id"]] = camp_obj.id

    # 4. Seed Entities
    print("Inserting Entities...")
    ent_map = {}
    for e in data["entities"]:
        ent_obj = Entity(
            entity_type=e["entity_type"],
            value=e["value"],
            normalized_value=e["normalized_value"],
            risk_score=e["risk_score"],
            first_seen=datetime.now(timezone.utc),
            last_seen=datetime.now(timezone.utc),
            meta_data=e.get("metadata", {})
        )
        db.add(ent_obj)
        db.flush()
        ent_map[e["id"]] = ent_obj.id

    # 5. Seed Cases
    print("Inserting Cases...")
    case_map = {}
    for cs in data["cases"]:
        c_id = cs.get("campaign_id")
        mapped_camp_id = camp_map.get(c_id) if c_id else None

        case_obj = Case(
            case_number=cs["case_number"],
            title=cs["title"],
            description=cs["description"],
            status=cs["status"],
            severity=cs["severity"],
            source=cs["source"],
            risk_score=cs["risk_score"],
            campaign_id=mapped_camp_id,
            created_at=datetime.fromisoformat(cs["created_at"]),
            updated_at=datetime.fromisoformat(cs["updated_at"]),
            meta_data=cs.get("metadata", {})
        )
        db.add(case_obj)
        db.flush()
        case_map[cs["id"]] = case_obj.id

    # 6. Seed Relationships
    print("Inserting Graph Relationships...")
    for r in data["relationships"]:
        src_id = ent_map.get(r["source_entity_id"])
        tgt_id = ent_map.get(r["target_entity_id"])
        if src_id and tgt_id:
            rel_obj = Relationship(
                source_entity_id=src_id,
                target_entity_id=tgt_id,
                relationship_type=r["relationship_type"],
                confidence=r.get("confidence", 1.0),
                first_seen=datetime.now(timezone.utc),
                last_seen=datetime.now(timezone.utc),
                meta_data=r.get("metadata", {})
            )
            db.add(rel_obj)

    # 7. Seed Transactions
    print("Inserting Transactions...")
    for tx in data["transactions"]:
        s_id = ent_map.get(tx["sender_entity_id"])
        r_id = ent_map.get(tx["receiver_entity_id"])
        cs_ref = tx.get("case_id")
        m_case_id = case_map.get(cs_ref) if cs_ref else None

        if s_id and r_id:
            tx_obj = Transaction(
                transaction_ref=tx["transaction_ref"],
                timestamp=datetime.fromisoformat(tx["timestamp"]),
                sender_entity_id=s_id,
                receiver_entity_id=r_id,
                amount=tx["amount"],
                currency=tx.get("currency", "INR"),
                channel=tx.get("channel", "UPI"),
                case_id=m_case_id,
                status=tx.get("status", "SUCCESS"),
                meta_data=tx.get("metadata", {})
            )
            db.add(tx_obj)

    # 8. Seed Messages
    print("Inserting Communication Logs...")
    for msg in data.get("messages", []):
        m_cs_id = case_map.get(msg["case_id"]) if msg.get("case_id") else None
        msg_obj = Message(
            timestamp=datetime.fromisoformat(msg["timestamp"]),
            sender_phone=msg.get("sender_phone"),
            receiver_phone=msg.get("receiver_phone"),
            channel=msg.get("channel", "SMS"),
            subject=msg.get("subject"),
            content=msg["content"],
            url=msg.get("url"),
            case_id=m_cs_id
        )
        db.add(msg_obj)

    db.commit()

    # 8.5 Seed Threat Intelligence Attacker Infrastructure
    print("Inserting Threat Intelligence Attacker Infrastructure...")
    ThreatMapService.ensure_seeded(db)

    # 9. Sync Fraud Graph
    print("Building In-Memory Fraud Graph...")
    graph_service.sync_from_db(db, force=True)

    # 10. Verification Statistics
    total_cases = db.query(Case).count()
    crit_cases = db.query(Case).filter(Case.risk_score >= 90.0).count()
    high_cases = db.query(Case).filter(Case.risk_score >= 70.0, Case.risk_score < 90.0).count()
    camps = db.query(Campaign).count()
    ents = db.query(Entity).count()
    txs = db.query(Transaction).count()
    users_count = db.query(User).count()
    threat_nodes_count = db.query(ThreatNode).count()

    if db_session is None:
        db.close()

    print("\n[OK] SEEDING COMPLETE! Verification KPIs:")
    print(f" - Total Cases: {total_cases} (Expected: 42)")
    print(f" - Critical Cases: {crit_cases} (Expected: 2)")
    print(f" - High Risk Cases: {high_cases} (Expected: 10)")
    print(f" - Detected Campaigns: {camps} (Expected: 6)")
    print(f" - Linked Entities: {ents}")
    print(f" - Threat Attacker Nodes: {threat_nodes_count} (Expected: 26)")
    print(f" - Financial Transactions: {txs}")
    print(f" - Registered Users: {users_count}")
    print("Primary Demo Scenario: 'Operation Phantom KYC' loaded on case CS-1024.\n")


if __name__ == "__main__":
    seed_database()
