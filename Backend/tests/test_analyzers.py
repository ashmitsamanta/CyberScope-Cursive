import pytest
from datetime import datetime, timezone, timedelta
from app.utils.normalization import (
    normalize_phone, normalize_domain, normalize_url, normalize_upi, EntityExtractor
)
from app.analyzers.communication_analyzer import CommunicationAnalyzer
from app.analyzers.behavioral_analyzer import BehavioralAnalyzer
from app.analyzers.graph_analyzer import GraphAnalyzer
from app.analyzers.transaction_analyzer import TransactionAnalyzer


def test_phone_normalization():
    assert normalize_phone("+91 90000 00001") == "+919000000001"
    assert normalize_phone("9000000001") == "+919000000001"
    assert normalize_phone("09000000001") == "+919000000001"
    assert normalize_phone("+919000000001") == "+919000000001"


def test_domain_and_url_normalization():
    assert normalize_domain("HTTP://Example.com") == "example.com"
    assert normalize_domain("example.com/") == "example.com"
    assert normalize_domain("https://www.example.com/login") == "example.com"
    assert normalize_url("http://example.com/test/") == "http://example.com/test"


def test_upi_normalization():
    assert normalize_upi("CentralMule99@OKAXIS") == "centralmule99@okaxis"
    assert normalize_upi("  test@upi  ") == "test@upi"


def test_entity_extractor():
    text = "Verify your account at https://secure-kyc-update.com and transfer ₹48,500 to centralmule99@okaxis or call 9000000001."
    res = EntityExtractor.extract_all(text)
    assert "secure-kyc-update.com" in res["domains"]
    assert "centralmule99@okaxis" in res["upi_ids"]
    assert 48500.0 in res["amounts"]
    assert "+919000000001" in res["phones"]


def test_communication_analyzer():
    content = "URGENT: Your SBI bank account will be blocked within 2 hours. Update KYC now at https://fake-bank-auth.xyz or share OTP."
    analysis = CommunicationAnalyzer.analyze(content, url="https://fake-bank-auth.xyz")
    assert analysis["is_suspicious"] is True
    assert analysis["suspicion_score"] >= 50.0
    assert "URGENCY" in analysis["categories"]
    assert "ACCOUNT_THREAT" in analysis["categories"]
    assert "VERIFICATION_SCAM" in analysis["categories"]


def test_behavioral_analyzer_fan_out():
    now = datetime.now(timezone.utc)
    account_id = 100
    txs = [
        {"id": 1, "timestamp": (now - timedelta(minutes=5)).isoformat(), "sender_entity_id": account_id, "receiver_entity_id": 201, "amount": 1000.0},
        {"id": 2, "timestamp": (now - timedelta(minutes=4)).isoformat(), "sender_entity_id": account_id, "receiver_entity_id": 202, "amount": 1000.0},
        {"id": 3, "timestamp": (now - timedelta(minutes=2)).isoformat(), "sender_entity_id": account_id, "receiver_entity_id": 203, "amount": 1000.0},
        {"id": 4, "timestamp": (now - timedelta(minutes=1)).isoformat(), "sender_entity_id": account_id, "receiver_entity_id": 204, "amount": 1000.0},
    ]
    res = BehavioralAnalyzer.analyze_account_transactions(account_id, txs, reference_time=now)
    assert "FAN_OUT" in res["patterns_detected"]
    assert "BURST_VELOCITY" in res["patterns_detected"]


def test_graph_analyzer_circular_flow():
    analyzer = GraphAnalyzer()
    entities = [
        {"id": 1, "value": "A", "normalized_value": "a", "entity_type": "BANK_ACCOUNT", "risk_score": 50},
        {"id": 2, "value": "B", "normalized_value": "b", "entity_type": "BANK_ACCOUNT", "risk_score": 50},
        {"id": 3, "value": "C", "normalized_value": "c", "entity_type": "BANK_ACCOUNT", "risk_score": 50},
    ]
    relationships = [
        {"id": 1, "source_entity_id": 1, "target_entity_id": 2, "relationship_type": "TRANSFERRED_TO"},
        {"id": 2, "source_entity_id": 2, "target_entity_id": 3, "relationship_type": "TRANSFERRED_TO"},
        {"id": 3, "source_entity_id": 3, "target_entity_id": 1, "relationship_type": "TRANSFERRED_TO"},
    ]
    analyzer.build_from_records(entities, relationships)
    cycles = analyzer.detect_circular_flows()
    assert len(cycles) >= 1
    assert cycles[0]["length"] == 3


def test_transaction_analyzer():
    tx = {"amount": 48500.0, "channel": "UPI"}
    sender = {"value": "victim", "risk_score": 10.0}
    receiver = {"value": "mule", "risk_score": 85.0}
    res = TransactionAnalyzer.evaluate_transaction(tx, sender, receiver)
    assert res["is_flagged"] is True
    assert res["risk_score"] >= 40.0
    codes = [s["code"] for s in res["signals"]]
    assert "HIGH_RISK_BENEFICIARY" in codes
    assert "POTENTIAL_STRUCTURING" in codes


def test_security_redos_resistance():
    """Validates that regex extractors are resistant to catastrophic backtracking (ReDoS)."""
    import time
    from app.utils.normalization import EntityExtractor

    # 1. Pathological URL pattern with deep dot-chains
    adversarial_url_text = "Check link: http://" + "sub." * 500 + "bank-portal-verify.com/login and www." + "a" * 5000 + ".evil.com"
    
    # 2. Pathological email/UPI pattern
    adversarial_upi_text = "Contact: " + "a" * 10000 + "@" + "b" * 1000 + ".com and payee@" + "c" * 5000

    # 3. Pathological phone pattern
    adversarial_phone_text = "Call: +91" + "9" * 10000 + " now!"

    t0 = time.perf_counter()
    res1 = EntityExtractor.extract_all(adversarial_url_text)
    res2 = EntityExtractor.extract_all(adversarial_upi_text)
    res3 = EntityExtractor.extract_all(adversarial_phone_text)
    duration = time.perf_counter() - t0

    # Must complete in under 150ms even with 20,000+ pathological characters
    assert duration < 0.15, f"ReDoS vulnerability detected: execution took {duration:.4f}s"
    assert isinstance(res1, dict)
    assert isinstance(res2, dict)
    assert isinstance(res3, dict)


def test_graph_analyzer_neighborhood_and_centrality():
    analyzer = GraphAnalyzer()
    entities = [
        {"id": 1, "value": "victim", "normalized_value": "victim", "entity_type": "PERSON", "risk_score": 10},
        {"id": 2, "value": "hub_mule", "normalized_value": "hub_mule", "entity_type": "BANK_ACCOUNT", "risk_score": 85},
        {"id": 3, "value": "leaf1", "normalized_value": "leaf1", "entity_type": "BANK_ACCOUNT", "risk_score": 60},
        {"id": 4, "value": "leaf2", "normalized_value": "leaf2", "entity_type": "BANK_ACCOUNT", "risk_score": 60},
        {"id": 5, "value": "leaf3", "normalized_value": "leaf3", "entity_type": "BANK_ACCOUNT", "risk_score": 60},
    ]
    relationships = [
        {"id": 1, "source_entity_id": 1, "target_entity_id": 2, "relationship_type": "TRANSFERRED_TO"},
        {"id": 2, "source_entity_id": 2, "target_entity_id": 3, "relationship_type": "TRANSFERRED_TO"},
        {"id": 3, "source_entity_id": 2, "target_entity_id": 4, "relationship_type": "TRANSFERRED_TO"},
        {"id": 4, "source_entity_id": 2, "target_entity_id": 5, "relationship_type": "TRANSFERRED_TO"},
    ]
    analyzer.build_from_records(entities, relationships)

    # Test neighborhood centered at hub_mule (e-2)
    nh = analyzer.get_neighborhood("e-2", max_hops=1)
    assert len(nh["nodes"]) == 5
    assert len(nh["edges"]) == 4

    # Test centrality anomaly detection (hub has degree 4)
    anomalies = analyzer.calculate_centrality_anomalies(top_k=5)
    assert len(anomalies) == 1
    assert anomalies[0]["node_id"] == "e-2"
    assert anomalies[0]["degree"] == 4
