import pytest
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)


def test_health_endpoint():
    response = client.get("/api/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"


def test_dashboard_stats(auth_headers):
    response = client.get("/api/stats/dashboard", headers=auth_headers)
    assert response.status_code == 200
    data = response.json()
    assert "kpis" in data
    assert data["kpis"]["total_cases"] >= 40
    assert data["kpis"]["detected_campaigns"] >= 3


def test_list_cases_and_filter(auth_headers):
    response = client.get("/api/cases?limit=10", headers=auth_headers)
    assert response.status_code == 200
    data = response.json()
    assert len(data) > 0
    first_case = data[0]
    assert "case_number" in first_case
    assert "risk_score" in first_case

    # Filter by severity
    high_resp = client.get("/api/cases?severity=HIGH", headers=auth_headers)
    assert high_resp.status_code == 200
    for c in high_resp.json():
        assert c["severity"] == "HIGH"


def test_get_case_detail_and_timeline(auth_headers):
    list_resp = client.get("/api/cases?limit=1", headers=auth_headers)
    first_id = list_resp.json()[0]["id"]

    detail_resp = client.get(f"/api/cases/{first_id}", headers=auth_headers)
    assert detail_resp.status_code == 200
    data = detail_resp.json()
    assert "risk_breakdown" in data
    assert "signals" in data["risk_breakdown"]

    timeline_resp = client.get(f"/api/cases/{first_id}/timeline", headers=auth_headers)
    assert timeline_resp.status_code == 200
    assert "events" in timeline_resp.json()


def test_graph_endpoints(auth_headers):
    graph_resp = client.get("/api/graph?limit=50", headers=auth_headers)
    assert graph_resp.status_code == 200
    g_data = graph_resp.json()
    assert "nodes" in g_data
    assert "edges" in g_data
    assert len(g_data["nodes"]) > 0
    first_node = g_data["nodes"][0]
    assert "metadata" in first_node
    assert "degree" in first_node["metadata"]
    assert "connected_case_count" in first_node["metadata"]

    shared_resp = client.get("/api/graph/shared-infrastructure", headers=auth_headers)
    assert shared_resp.status_code == 200
    assert "shared_infrastructure" in shared_resp.json()


def test_graph_case_subgraph_by_number_and_id(auth_headers):
    case_str_resp = client.get("/api/graph/case/CS-1024", headers=auth_headers)
    assert case_str_resp.status_code == 200
    cs_data = case_str_resp.json()
    assert "nodes" in cs_data
    assert "edges" in cs_data
    assert "stats" in cs_data
    assert len(cs_data["nodes"]) > 0
    assert len(cs_data["edges"]) > 0
    assert cs_data["stats"]["case_number"] == "CS-1024"
    assert cs_data["stats"]["case_id"] == 1
    assert "nodes_count" in cs_data["stats"]

    case_id_resp = client.get("/api/graph/case/1", headers=auth_headers)
    assert case_id_resp.status_code == 200
    id_data = case_id_resp.json()
    assert len(id_data["nodes"]) == len(cs_data["nodes"])
    assert len(id_data["edges"]) == len(cs_data["edges"])

    cs1027_resp = client.get("/api/graph/case/CS-1027", headers=auth_headers)
    assert cs1027_resp.status_code == 200
    assert len(cs1027_resp.json()["nodes"]) > 0


def test_graph_filtering_and_search(auth_headers):
    dom_resp = client.get("/api/graph?entity_type=DOMAIN", headers=auth_headers)
    assert dom_resp.status_code == 200
    dom_data = dom_resp.json()
    assert len(dom_data["nodes"]) > 0
    assert all(n["entity_type"] == "DOMAIN" for n in dom_data["nodes"])
    dom_node_ids = {n["id"] for n in dom_data["nodes"]}
    for edge in dom_data["edges"]:
        assert edge["source"] in dom_node_ids
        assert edge["target"] in dom_node_ids

    kyc_resp = client.get("/api/graph?search=kyc", headers=auth_headers)
    assert kyc_resp.status_code == 200
    kyc_data = kyc_resp.json()
    assert len(kyc_data["nodes"]) > 0
    assert kyc_data["stats"]["filters"]["search"] == "kyc"
    kyc_node_ids = {n["id"] for n in kyc_data["nodes"]}
    for edge in kyc_data["edges"]:
        assert edge["source"] in kyc_node_ids
        assert edge["target"] in kyc_node_ids

    risk_resp = client.get("/api/graph?min_risk=80", headers=auth_headers)
    assert risk_resp.status_code == 200
    risk_data = risk_resp.json()
    assert len(risk_data["nodes"]) > 0
    assert all(n["risk_score"] >= 80.0 for n in risk_data["nodes"])


def test_graph_neighborhood_by_identifier(auth_headers):
    dom_resp = client.get("/api/graph/entity/secure-kyc-update.com", headers=auth_headers)
    assert dom_resp.status_code == 200
    dom_data = dom_resp.json()
    assert len(dom_data["nodes"]) > 0
    assert dom_data["stats"]["center_node"] == "e-1"

    phone_resp = client.get("/api/graph/entity/+919686579303", headers=auth_headers)
    assert phone_resp.status_code == 200
    phone_data = phone_resp.json()
    assert len(phone_data["nodes"]) > 0
    assert phone_data["stats"]["center_node"] == "e-4"

    id_resp = client.get("/api/graph/entity/1", headers=auth_headers)
    assert id_resp.status_code == 200
    assert len(id_resp.json()["nodes"]) > 0


def test_transactions_and_trace(auth_headers):
    tx_resp = client.get("/api/transactions?limit=10", headers=auth_headers)
    assert tx_resp.status_code == 200
    txs = tx_resp.json()
    assert len(txs) > 0

    first_tx = txs[0]
    trace_payload = {
        "start_transaction_id": first_tx["id"],
        "max_hops": 3
    }
    trace_resp = client.post("/api/transactions/trace-funds", json=trace_payload, headers=auth_headers)
    assert trace_resp.status_code == 200
    t_data = trace_resp.json()
    assert "nodes" in t_data
    assert "edges" in t_data


def test_campaigns(auth_headers):
    camp_resp = client.get("/api/campaigns", headers=auth_headers)
    assert camp_resp.status_code == 200
    camps = camp_resp.json()
    assert len(camps) >= 3
    first_camp = camps[0]

    detail_resp = client.get(f"/api/campaigns/{first_camp['id']}", headers=auth_headers)
    assert detail_resp.status_code == 200
    c_data = detail_resp.json()
    assert "cases" in c_data


def test_investigations_cyber_assist(auth_headers):
    query_payload = {
        "case_id": 1,
        "query": "Why was this case flagged?"
    }
    resp = client.post("/api/investigations/query", json=query_payload, headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert "answer" in data
    assert "evidence_citations" in data
    assert "recommended_next_steps" in data
    assert len(data["evidence_citations"]) > 0


def test_natural_language_search(auth_headers):
    search_resp = client.get("/api/search?q=secure-kyc-update.com", headers=auth_headers)
    assert search_resp.status_code == 200
    data = search_resp.json()
    assert "results" in data or "cases" in data


def test_security_xss_sanitization(auth_headers):
    xss_payload = {
        "title": "<script>alert('xss-title')</script> Fake Bank Alert",
        "content": "Urgent: Account locked! <img src=x onerror=alert(document.cookie)> Update at https://secure-login.test",
        "channel": "SMS"
    }
    resp = client.post("/api/cases/ingest", json=xss_payload, headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert "case_id" in data

    assert "<script>" not in data["title"]
    assert "&lt;script&gt;" in data["title"]
    assert "<img" not in data["description"]
    assert "&lt;img" in data["description"]


def test_security_upload_abuse_prevention(auth_headers):
    huge_content = "A" * 60000
    resp_huge = client.post("/api/cases/ingest", json={
        "title": "Abuse Test",
        "content": huge_content
    }, headers=auth_headers)
    assert resp_huge.status_code == 413
    assert "exceeds maximum allowed size" in resp_huge.json()["detail"]

    huge_title = "T" * 300
    resp_title = client.post("/api/cases/ingest", json={
        "title": huge_title,
        "content": "Normal content"
    }, headers=auth_headers)
    assert resp_title.status_code == 400
    assert "exceeds maximum permitted limit" in resp_title.json()["detail"]
