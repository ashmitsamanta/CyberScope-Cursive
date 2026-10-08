"""
Victim <-> attacker-IP linkage contract tests.

Verifies the fraud graph connects case victims to attacker infrastructure
through forensic edges (ACCESSED_FROM sessions, TARGETED_BY lures, CONTACTED
handsets) and that transaction telemetry is bound to attacker IPs while
normal traffic stays unbound.
"""
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

VICTIM_CASES = [
    "CS-1024", "CS-1025", "CS-1026", "CS-1027", "CS-1028", "CS-1029",
    "CS-1030", "CS-1031", "CS-1032", "CS-1033", "CS-1034", "CS-1035",
]

VICTIM_NAMES = [
    "Rajiv Sharma", "Meera Sen", "Anand Verma", "Sunita Patil", "Kavita Rao",
    "Arjun Mehta", "Deepak Yadav", "Farida Khan", "Rohit Malhotra",
    "Priyanka Deshmukh", "Imran Sheikh", "Lakshmi Prasad",
]


def _full_graph():
    res = client.get("/api/graph?limit=500")
    assert res.status_code == 200
    return res.json()


def test_every_attacker_ip_is_connected():
    """No floating IP entities: every attacker IP participates in the graph."""
    graph = _full_graph()
    ip_nodes = {n["id"] for n in graph["nodes"] if n["entity_type"] == "IP_ADDRESS"}
    assert len(ip_nodes) >= 25

    connected = set()
    for e in graph["edges"]:
        connected.add(e["source"])
        connected.add(e["target"])
    assert ip_nodes <= connected, f"Orphan IP nodes: {ip_nodes - connected}"


def test_victim_accounts_accessed_from_attacker_ips():
    """Every case victim's account carries an attacker-side session edge."""
    graph = _full_graph()
    nodes = {n["id"]: n for n in graph["nodes"]}

    victim_sessions = []
    for e in graph["edges"]:
        if e["relationship_type"] != "ACCESSED_FROM":
            continue
        src, tgt = nodes.get(e["source"]), nodes.get(e["target"])
        if (
            src and tgt
            and src["entity_type"] == "BANK_ACCOUNT"
            and "SIM-ACC-VICTIM" in str(src["label"])
            and tgt["entity_type"] == "IP_ADDRESS"
        ):
            victim_sessions.append((src["label"], tgt["label"]))

    assert len(victim_sessions) >= len(VICTIM_CASES)


def test_victims_targeted_by_lure_infrastructure():
    """Victims are linked to the lure domain (or SIM-swap device) that targeted them."""
    graph = _full_graph()
    nodes = {n["id"]: n for n in graph["nodes"]}

    targeted = []
    for e in graph["edges"]:
        if e["relationship_type"] != "TARGETED_BY":
            continue
        src, tgt = nodes.get(e["source"]), nodes.get(e["target"])
        if src and tgt and src["entity_type"] == "PERSON" and src["label"] in VICTIM_NAMES:
            targeted.append((src["label"], tgt["entity_type"]))

    assert len(targeted) >= len(VICTIM_CASES)
    assert all(t in ("DOMAIN", "DEVICE") for _, t in targeted)


def test_lure_handsets_contact_victim_handsets():
    """SMS lure delivery is represented as CONTACTED edges from attacker handsets."""
    graph = _full_graph()
    nodes = {n["id"]: n for n in graph["nodes"]}

    contacts = []
    for e in graph["edges"]:
        if e["relationship_type"] != "CONTACTED":
            continue
        src, tgt = nodes.get(e["source"]), nodes.get(e["target"])
        if src and tgt and src["entity_type"] == "PHONE" and tgt["entity_type"] == "PHONE":
            if float(src.get("risk_score", 0)) >= 70 > float(tgt.get("risk_score", 0)):
                contacts.append((src["label"], tgt["label"]))

    assert len(contacts) >= len(VICTIM_CASES)


def test_fraud_transactions_bound_to_attacker_ips():
    """FLAGGED transactions carry attacker IP telemetry; normal traffic stays unbound."""
    res = client.get("/api/transactions?limit=200")
    assert res.status_code == 200
    txs = res.json()

    flagged = [t for t in txs if t.get("status") == "FLAGGED"]
    normal = [t for t in txs if t.get("status") == "SUCCESS"]

    assert len(flagged) >= 20
    assert all(t.get("ip_id") for t in flagged)
    assert not any(t.get("ip_id") for t in normal)

    # C2-driven sessions (Phantom KYC / executive ATO) also expose the trojan device
    c2_device_txs = [t for t in flagged if t.get("device_id")]
    assert len(c2_device_txs) >= 5


def test_case_graph_shows_victim_to_ip_chain():
    """The CS-1024 case subgraph reaches both the victim and the attacking C2 IP."""
    res = client.get("/api/graph/case/CS-1024?hops=3")
    assert res.status_code == 200
    graph = res.json()

    labels = {n["label"] for n in graph["nodes"]}
    types = {n["entity_type"] for n in graph["nodes"]}
    assert "Rajiv Sharma" in labels
    assert "198.51.100.10" in labels
    assert "PERSON" in types and "IP_ADDRESS" in types

    nodes = {n["id"]: n for n in graph["nodes"]}
    session_edges = [
        e for e in graph["edges"]
        if e["relationship_type"] == "ACCESSED_FROM"
        and nodes.get(e["source"], {}).get("entity_type") == "BANK_ACCOUNT"
        and nodes.get(e["target"], {}).get("label") == "198.51.100.10"
    ]
    assert session_edges, "Expected victim-account ACCESSED_FROM C2 edge in case subgraph"


def test_threat_map_privacy_after_victim_linkage():
    """Victim identities stay out of the public threat-map surface."""
    attackers = client.get("/api/threat-map/attackers?limit=100").json()
    feed = client.get("/api/threat-map/live-feed?limit=15").json()
    combined = str(attackers) + str(feed)

    for name in VICTIM_NAMES:
        assert name not in combined
    assert "SIM-ACC-VICTIM" not in combined
