from __future__ import annotations

from fastapi.testclient import TestClient

import paca
from paca_executor import app


client = TestClient(app)


def _payload(target: str = "/acme/reports/summary.txt") -> dict:
    return {
        "action": "read_file",
        "args": {"path": target},
        "capability": {
            "id": "api-test-capability",
            "principal": "api-test-user",
            "tenant": "api-test-tenant",
            "task": "api-test-task",
            "role": "assistant",
            "grants": {"read_file": ["/acme/reports/summary.txt"]},
            "expires": 30,
        },
    }


def test_health_endpoint_reports_service_status() -> None:
    response = client.get("/health")

    assert response.status_code == 200
    assert app.version == paca.__version__
    assert response.json() == {
        "status": "ok",
        "service": "paca-reference-decision-api",
    }


def test_decide_endpoint_returns_allow_without_executing_an_effect() -> None:
    response = client.post("/decide", json=_payload())

    assert response.status_code == 200
    body = response.json()
    assert body["verdict"] == "allow"
    assert body["reference_token_verified"] is True
    assert body["effect_executed"] is False
    assert body["digest"]


def test_decide_endpoint_denies_target_outside_capability_scope() -> None:
    response = client.post("/decide", json=_payload("/acme/private/secret.txt"))

    assert response.status_code == 200
    body = response.json()
    assert body["verdict"] == "deny"
    assert "C1" in body["checks"]
    assert body["effect_executed"] is False


def test_decide_endpoint_rejects_invalid_capability_schema() -> None:
    payload = _payload()
    payload["capability"]["expires"] = 0

    response = client.post("/decide", json=payload)

    assert response.status_code == 422


def test_decide_endpoint_rejects_extra_capability_fields() -> None:
    payload = _payload()
    payload["capability"]["trusted"] = True

    response = client.post("/decide", json=payload)

    assert response.status_code == 422


def test_decide_endpoint_enforces_capability_call_budget_across_requests() -> None:
    payload = _payload()
    payload["capability"]["id"] = "api-test-one-call-capability"
    payload["capability"]["task"] = "api-test-one-call-task"
    payload["capability"]["max_calls"] = 1

    first = client.post("/decide", json=payload)
    second = client.post("/decide", json=payload)

    assert first.status_code == 200
    assert first.json()["verdict"] == "allow"
    assert second.status_code == 200
    assert second.json()["verdict"] == "deny"
    assert "C2" in second.json()["checks"]


def test_decide_endpoint_rejects_changed_authority_for_same_capability_id() -> None:
    payload = _payload()
    payload["capability"]["id"] = "api-test-immutable-capability"
    first = client.post("/decide", json=payload)
    assert first.status_code == 200

    payload["capability"]["grants"] = {"read_file": ["/acme/*"]}
    second = client.post("/decide", json=payload)

    assert second.status_code == 409
