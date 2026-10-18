import os
from datetime import date, timedelta

import pytest
from fastapi.testclient import TestClient

os.environ["AE_API_KEY"] = "test-key-not-a-real-secret"

from app.main import AUDIT, app  # noqa: E402

client = TestClient(app)
HEADERS = {"X-API-Key": "test-key-not-a-real-secret"}

VALID = {
    "patient": {"initials": "JD", "age_years": 54, "sex": "F"},
    "reporter": {"type": "physician", "country": "US"},
    "suspect_product": "Drug X 10mg tablet",
    "reaction": "Severe skin rash",
    "onset_date": "2026-09-01",
    "seriousness": ["hospitalisation"],
}


def test_health():
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


def test_security_headers_present():
    r = client.get("/health")
    assert r.headers["X-Content-Type-Options"] == "nosniff"
    assert r.headers["X-Frame-Options"] == "DENY"


def test_rejects_missing_api_key():
    r = client.post("/api/v1/adverse-events", json=VALID)
    assert r.status_code == 401


def test_rejects_wrong_api_key():
    r = client.post("/api/v1/adverse-events", json=VALID, headers={"X-API-Key": "wrong"})
    assert r.status_code == 401


def test_serious_case_is_expedited_15_days():
    r = client.post("/api/v1/adverse-events", json=VALID, headers=HEADERS)
    assert r.status_code == 201
    body = r.json()
    assert body["is_serious"] is True
    assert body["expedited"] is True
    assert body["case_id"].startswith("AE-")
    received = date.fromisoformat(body["received_at"][:10])
    assert date.fromisoformat(body["regulatory_due_date"]) == received + timedelta(days=15)


def test_non_serious_case_not_expedited():
    payload = {**VALID, "seriousness": []}
    r = client.post("/api/v1/adverse-events", json=payload, headers=HEADERS)
    assert r.status_code == 201
    assert r.json()["expedited"] is False


def test_rejects_unidentifiable_patient():
    payload = {**VALID, "patient": {"sex": "U"}}
    r = client.post("/api/v1/adverse-events", json=payload, headers=HEADERS)
    assert r.status_code == 422


@pytest.mark.parametrize(
    "patch",
    [
        {"suspect_product": ""},
        {"reaction": ""},
        {"onset_date": (date.today() + timedelta(days=5)).isoformat()},
        {"unexpected_field": "x"},  # extra fields are forbidden (mass-assignment protection)
        {"reporter": {"type": "physician", "country": "usa"}},
    ],
)
def test_input_validation(patch):
    r = client.post("/api/v1/adverse-events", json={**VALID, **patch}, headers=HEADERS)
    assert r.status_code == 422


def test_get_case_and_404():
    case_id = client.post("/api/v1/adverse-events", json=VALID, headers=HEADERS).json()["case_id"]
    assert client.get(f"/api/v1/adverse-events/{case_id}", headers=HEADERS).status_code == 200
    assert client.get("/api/v1/adverse-events/AE-NOPE", headers=HEADERS).status_code == 404


def test_audit_trail_is_hash_chained_and_tamper_evident():
    client.post("/api/v1/adverse-events", json=VALID, headers=HEADERS)
    r = client.get("/api/v1/audit", headers=HEADERS)
    assert r.status_code == 200
    assert r.json()["chain_valid"] is True
    assert len(r.json()["entries"]) >= 1

    # Tamper with an entry -> chain must break.
    AUDIT._entries[0]["actor"] = "attacker"
    assert AUDIT.verify() is False
