import pytest
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)


def test_stats_dashboard_frontend_contract():
    res = client.get("/api/stats/dashboard")
    assert res.status_code == 200
    data = res.json()
    assert "total_cases" in data
    assert "total_entities" in data
    assert "high_risk_cases" in data
    assert "total_campaigns" in data
    assert "kpis" in data
    assert "total_cases" in data["kpis"]


def test_cases_list_frontend_contract():
    res = client.get("/api/cases?limit=4")
    assert res.status_code == 200
    cases = res.json()
    assert isinstance(cases, list)
    if cases:
        c = cases[0]
        assert "id" in c
        assert "case_number" in c
        assert "entity_count" in c
        assert "severity" in c
        assert "status" in c


def test_cases_ingest_frontend_contract():
    payload = {
        "title": "Suspicious KYC SMS",
        "content": "Dear Customer, update your KYC at http://secure-kyc-verify.net or your account 9876543210 will be blocked.",
        "channel": "SMS",
        "sender_phone": "+919876543210"
    }
    res = client.post("/api/cases/ingest", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert "id" in data
    assert "case_id" in data
    assert "case_number" in data


def test_case_detail_frontend_contract():
    res = client.get("/api/cases")
    cases = res.json()
    assert len(cases) > 0
    case_id = cases[0]["id"]

    res_detail = client.get(f"/api/cases/{case_id}")
    assert res_detail.status_code == 200
    detail = res_detail.json()
    assert "risk_score" in detail
    assert "entity_count" in detail
    assert "connected_paths" in detail


def test_entities_frontend_contract():
    res = client.get("/api/entities?limit=10")
    assert res.status_code == 200
    entities = res.json()
    assert isinstance(entities, list)
    if entities:
        e = entities[0]
        assert "entity_type" in e
        assert "value" in e
        assert "risk_score" in e
        assert "case_count" in e
        assert "degree" in e


def test_transactions_frontend_contract():
    res = client.get("/api/transactions?limit=10")
    assert res.status_code == 200
    txs = res.json()
    assert isinstance(txs, list)
    if txs:
        t = txs[0]
        assert "transaction_ref" in t
        assert "tx_hash" in t
        assert "from_account" in t
        assert "to_account" in t
        assert "amount" in t


def test_campaigns_frontend_contract():
    res = client.get("/api/campaigns")
    assert res.status_code == 200
    camps = res.json()
    assert isinstance(camps, list)
    if camps:
        c = camps[0]
        assert "campaign_id" in c
        assert "code" in c
        assert "entity_count" in c
        assert "shared_entity_count" in c


def test_fraud_graph_frontend_contract():
    res = client.get("/api/graph?limit=50")
    assert res.status_code == 200
    graph = res.json()
    assert "nodes" in graph
    assert "edges" in graph


def test_chat_proxy_fallback_contract():
    res = client.post("/api/chat", json={
        "messages": [{"role": "user", "content": "ping"}]
    })
    assert res.status_code == 200
    data = res.json()
    assert "choices" in data
    assert len(data["choices"]) > 0
    assert "message" in data["choices"][0]


import uuid

def test_register_frontend_contract():
    # Test duplicate detection contract
    dup_res = client.post("/api/auth/check-email", json={"email": "investigator@cyberscope.io"})
    assert dup_res.status_code == 200
    assert dup_res.json()["exists"] is True

    test_email = f"integration_{uuid.uuid4().hex[:8]}@agency.gov.in"

    # Test registration initiation contract
    init_res = client.post("/api/auth/register/initiate", json={
        "name": "Integration Test Officer",
        "phone": "9123456780",
        "email": test_email,
        "password": "TestPassword123!",
        "role": "Investigator",
        "organization": "Fraud Unit"
    })
    assert init_res.status_code == 200
    init_data = init_res.json()
    assert init_data["status"] == "verification_initiated"
    assert "preview" not in init_data
    assert "delivery" in init_data

    from app.services.notification_service import notification_service
    outbox = notification_service.get_test_outbox()
    email_entry = next(e for e in reversed(outbox["emails"]) if e["to_email"] == test_email)

    # Test verification contract
    verify_res = client.post("/api/auth/register/verify", json={
        "email": test_email,
        "email_otp": email_entry["code"]
    })
    assert verify_res.status_code == 200
    verify_data = verify_res.json()
    assert verify_data["status"] == "verified"
    assert "access_token" in verify_data
    assert verify_data["user"]["email"] == test_email


def test_threat_map_frontend_contract():
    # 1. Attacker telemetry endpoint
    res_attackers = client.get("/api/threat-map/attackers?limit=10")
    assert res_attackers.status_code == 200
    attackers = res_attackers.json()
    assert isinstance(attackers, list)
    assert len(attackers) > 0
    attacker = attackers[0]
    for key in ("id", "ip", "hostname", "latitude", "longitude", "city", "state", "attack_type", "severity", "risk_score", "status"):
        assert key in attacker, f"Missing key '{key}' in attacker node"
    
    # 2. Threat stats endpoint
    res_stats = client.get("/api/threat-map/stats")
    assert res_stats.status_code == 200
    stats = res_stats.json()
    for key in ("total_attackers", "active_attacks", "critical_threats", "top_attack_types", "top_hotspots", "total_blocked_requests"):
        assert key in stats, f"Missing key '{key}' in threat stats"

    # 3. Live feed endpoint
    res_feed = client.get("/api/threat-map/live-feed?limit=5")
    assert res_feed.status_code == 200
    feed = res_feed.json()
    assert isinstance(feed, list)
    assert len(feed) > 0
    event = feed[0]
    for key in ("id", "timestamp", "attacker_ip", "city", "state", "attack_type", "severity", "target", "action_taken"):
        assert key in event, f"Missing key '{key}' in live feed event"


