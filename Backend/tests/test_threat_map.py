import pytest
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)


def test_get_attackers_list(auth_headers):
    response = client.get("/api/threat-map/attackers", headers=auth_headers)
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)
    assert len(data) >= 25

    first = data[0]
    expected_fields = [
        "id", "ip", "hostname", "asn", "isp", "city", "state", "pincode",
        "latitude", "longitude", "lat", "lng", "attack_type", "severity", "risk_score",
        "attack_count", "target_sector", "malicious_request_sample",
        "active_campaign", "primary_case_id", "primary_case_number",
        "linked_case_ids", "linked_case_numbers", "status", "last_seen"
    ]
    for field in expected_fields:
        assert field in first, f"Missing {field} in response"


def test_case_linkage_and_redirection(auth_headers):
    response = client.get("/api/threat-map/attackers", headers=auth_headers)
    assert response.status_code == 200
    attackers = response.json()
    assert len(attackers) >= 25

    for node in attackers:
        assert "lat" in node and isinstance(node["lat"], (int, float))
        assert "lng" in node and isinstance(node["lng"], (int, float))
        assert "latitude" in node and isinstance(node["latitude"], (int, float))
        assert "longitude" in node and isinstance(node["longitude"], (int, float))
        assert node["lat"] == node["latitude"]
        assert node["lng"] == node["longitude"]

        assert "primary_case_id" in node and isinstance(node["primary_case_id"], int)
        assert "primary_case_number" in node and isinstance(node["primary_case_number"], str)
        assert "linked_case_ids" in node and isinstance(node["linked_case_ids"], list)
        assert len(node["linked_case_ids"]) > 0
        assert all(isinstance(cid, int) for cid in node["linked_case_ids"])
        assert "linked_case_numbers" in node and isinstance(node["linked_case_numbers"], list)
        assert len(node["linked_case_numbers"]) > 0

    first_node = attackers[0]
    cid = first_node["primary_case_id"]
    cnum = first_node["primary_case_number"]
    case_resp_id = client.get(f"/api/cases/{cid}", headers=auth_headers)
    assert case_resp_id.status_code == 200, f"Case ID {cid} not found"
    case_resp_num = client.get(f"/api/cases/{cnum}", headers=auth_headers)
    assert case_resp_num.status_code == 200, f"Case number {cnum} not found"


def test_preexisting_db_ip_198_51_100_10_jamtara(auth_headers):
    response = client.get("/api/threat-map/attackers?search=198.51.100.10", headers=auth_headers)
    assert response.status_code == 200
    nodes = response.json()
    assert len(nodes) >= 1
    target = next((n for n in nodes if n["ip"] == "198.51.100.10"), None)
    assert target is not None
    assert target["city"] == "Jamtara"
    assert target["state"] == "Jharkhand"
    assert target["pincode"] == "815351"
    assert "Phantom KYC" in target["active_campaign"]
    assert target["severity"] == "CRITICAL"
    assert target["risk_score"] >= 90.0


def test_verified_authentic_indian_pincodes(auth_headers):
    response = client.get("/api/threat-map/attackers?limit=100", headers=auth_headers)
    assert response.status_code == 200
    nodes = response.json()
    assert len(nodes) >= 25

    verified_hotspot_pins = {
        "Jamtara": "815351",
        "Karmatanr": "815352",
        "Deoghar": "814112",
        "Bharatpur": "321001",
        "Alwar": "301001",
        "Jaipur": "302001",
        "Gurugram": "122001",
        "Salt Lake Sector V, Kolkata": "700091",
        "Asansol": "713301",
        "Surat": "395003",
        "Ahmedabad": "380001",
        "Bengaluru": "560001",
        "Mumbai": "400051",
        "Pune": "411057",
        "Hyderabad": "500081",
        "Patna": "800001",
        "Indore": "452001",
        "Bhopal": "462001",
        "Chandigarh": "160017",
        "Guwahati": "781001",
        "New Delhi": "110001",
        "Chennai": "600001",
        "Lucknow": "226001",
        "Kochi": "682001",
        "Bhubaneswar": "751001"
    }

    for node in nodes:
        pin = node.get("pincode")
        assert pin is not None, f"Node {node['ip']} missing pincode"
        assert len(pin) == 6 and pin.isdigit(), f"Invalid pincode format '{pin}' for {node['ip']} ({node['city']})"
        city = node.get("city")
        if city in verified_hotspot_pins:
            assert pin == verified_hotspot_pins[city], f"Expected {verified_hotspot_pins[city]} for {city}, got {pin}"


def test_get_attackers_filtering(auth_headers):
    resp_crit = client.get("/api/threat-map/attackers?severity=CRITICAL", headers=auth_headers)
    assert resp_crit.status_code == 200
    for node in resp_crit.json():
        assert node["severity"] == "CRITICAL"

    resp_phish = client.get("/api/threat-map/attackers?attack_type=PHISHING_HOST", headers=auth_headers)
    assert resp_phish.status_code == 200
    for node in resp_phish.json():
        assert node["attack_type"] == "PHISHING_HOST"

    resp_risk = client.get("/api/threat-map/attackers?min_risk=85.0", headers=auth_headers)
    assert resp_risk.status_code == 200
    for node in resp_risk.json():
        assert node["risk_score"] >= 85.0

    resp_pin = client.get("/api/threat-map/attackers?pincode=815351", headers=auth_headers)
    assert resp_pin.status_code == 200
    pins_data = resp_pin.json()
    assert len(pins_data) >= 1
    assert all(n["pincode"] == "815351" for n in pins_data)


def test_threat_stats(auth_headers):
    response = client.get("/api/threat-map/stats", headers=auth_headers)
    assert response.status_code == 200
    stats = response.json()
    assert "total_attackers" in stats
    assert "active_attacks" in stats
    assert "critical_threats" in stats
    assert "top_attack_types" in stats
    assert "top_hotspots" in stats
    assert "total_blocked_requests" in stats
    assert "avg_risk_score" in stats
    assert stats["total_attackers"] >= 25
    for h in stats["top_hotspots"]:
        assert "city" in h
        assert "pincode" in h


def test_live_feed(auth_headers):
    response = client.get("/api/threat-map/live-feed?limit=15", headers=auth_headers)
    assert response.status_code == 200
    feed = response.json()
    assert len(feed) == 15
    first_evt = feed[0]
    for key in ["id", "timestamp", "attacker_ip", "city", "state", "pincode", "attack_type", "target", "blocked_status"]:
        assert key in first_evt


def test_block_attacker(auth_headers):
    response = client.post("/api/threat-map/block", json={"ip": "115.110.201.78", "reason": "Sim Box automated suppression"}, headers=auth_headers)
    assert response.status_code == 200
    body = response.json()
    assert body["success"] is True
    assert body["attacker"]["status"] == "BLOCKED_BY_FIREWALL"
    assert "firewall_rule_id" in body


def test_strict_privacy_no_victim_data(auth_headers):
    resp_attackers = client.get("/api/threat-map/attackers", headers=auth_headers).json()
    resp_feed = client.get("/api/threat-map/live-feed", headers=auth_headers).json()
    combined = str(resp_attackers) + str(resp_feed)

    victim_identifiers = [
        "Rajiv Sharma", "Meera Sen", "Anand Verma", "Sunita Patil", "Kavita Rao",
        "SIM-ACC-VICTIM", "VICTIM_COMPLAINT_PORTAL"
    ]
    for identifier in victim_identifiers:
        assert identifier not in combined
