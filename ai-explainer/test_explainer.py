import pytest
from fastapi.testclient import TestClient
from main import app, INTERNAL_SERVICE_SECRET

client = TestClient(app)
AUTH_HEADERS = {"X-Internal-Secret": INTERNAL_SERVICE_SECRET}
BEARER_HEADERS = {"Authorization": f"Bearer {INTERNAL_SERVICE_SECRET}"}


def test_health_endpoint():
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert data["auth_enforced"] is True


def test_root_endpoint():
    response = client.get("/")
    assert response.status_code == 200
    data = response.json()
    assert data["service"] == "Compliance AI Explainer"
    assert data["status"] == "ok"


def test_explain_auth_enforcement():
    payload = {
        "tx": "0x123",
        "decision": "BLOCK",
        "risk_score": 98,
        "reasons": ["SANCTIONED_SENDER"],
    }

    # Missing header -> 401
    res_no_auth = client.post("/explain", json=payload)
    assert res_no_auth.status_code == 401

    # Invalid secret -> 401
    res_bad_auth = client.post(
        "/explain", json=payload, headers={"X-Internal-Secret": "wrong-secret"}
    )
    assert res_bad_auth.status_code == 401

    # Valid X-Internal-Secret -> 200
    res_valid = client.post("/explain", json=payload, headers=AUTH_HEADERS)
    assert res_valid.status_code == 200

    # Valid Bearer token -> 200
    res_bearer = client.post("/explain", json=payload, headers=BEARER_HEADERS)
    assert res_bearer.status_code == 200


def test_explain_block_narrative():
    payload = {
        "tx": "0xblock_test_tx",
        "decision": "BLOCK",
        "risk_score": 98,
        "reasons": ["SANCTIONED_SENDER", "SANCTIONED_RECIPIENT"],
    }
    response = client.post("/explain", json=payload, headers=AUTH_HEADERS)
    assert response.status_code == 200
    data = response.json()
    assert data["tx"] == "0xblock_test_tx"
    assert data["decision"] == "BLOCK"
    assert data["risk_score"] == 98
    assert "narrative" in data
    assert len(data["narrative"]) > 0


def test_explain_flag_narrative():
    payload = {
        "tx": "0xflag_test_tx",
        "decision": "FLAG",
        "risk_score": 55,
        "reasons": ["INDIRECT_SENDER_EXPOSURE"],
    }
    response = client.post("/explain", json=payload, headers=AUTH_HEADERS)
    assert response.status_code == 200
    data = response.json()
    assert data["decision"] == "FLAG"
    assert data["risk_score"] == 55
    assert len(data["narrative"]) > 0


def test_explain_allow_narrative():
    payload = {
        "tx": "0xallow_test_tx",
        "decision": "ALLOW",
        "risk_score": 0,
        "reasons": [],
    }
    response = client.post("/explain", json=payload, headers=AUTH_HEADERS)
    assert response.status_code == 200
    data = response.json()
    assert data["decision"] == "ALLOW"
    assert data["risk_score"] == 0
    assert len(data["narrative"]) > 0


def test_summarize_bid_compliant():
    payload = {
        "slot": 100,
        "builder_id": "builder-clean",
        "value_eth": 2.5,
        "verdict": "COMPLIANT",
        "reasons": [],
    }
    response = client.post("/summarize_bid", json=payload, headers=AUTH_HEADERS)
    assert response.status_code == 200
    data = response.json()
    assert data["slot"] == 100
    assert data["builder_id"] == "builder-clean"
    assert data["verdict"] == "COMPLIANT"
    assert "COMPLIANT" in data["summary"] or "compliant" in data["summary"].lower()


def test_summarize_bid_exposed_tx():
    payload = {
        "slot": 101,
        "builder_id": "builder-sanctioned",
        "value_eth": 3.0,
        "verdict": "EXPOSED_TX",
        "reasons": ["Tx blocked: SANCTIONED_SENDER"],
    }
    response = client.post("/summarize_bid", json=payload, headers=AUTH_HEADERS)
    assert response.status_code == 200
    data = response.json()
    assert data["verdict"] == "EXPOSED_TX"
    assert "excluded" in data["summary"].lower() or "prohibited" in data["summary"].lower()


def test_summarize_bid_exposed_builder():
    payload = {
        "slot": 102,
        "builder_id": "builder-bad-coinbase",
        "value_eth": 1.8,
        "verdict": "EXPOSED_BUILDER",
        "reasons": ["Fee recipient is sanctioned"],
    }
    response = client.post("/summarize_bid", json=payload, headers=AUTH_HEADERS)
    assert response.status_code == 200
    data = response.json()
    assert data["verdict"] == "EXPOSED_BUILDER"
    assert "fee recipient" in data["summary"].lower() or "sanctioned" in data["summary"].lower()


def test_invalid_input_schema():
    # Missing required field 'tx'
    bad_payload = {
        "decision": "BLOCK",
        "risk_score": 98,
        "reasons": [],
    }
    response = client.post("/explain", json=bad_payload, headers=AUTH_HEADERS)
    assert response.status_code == 422
