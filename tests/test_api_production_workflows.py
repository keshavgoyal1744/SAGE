from fastapi.testclient import TestClient

from sentinelgraph.app import app


client = TestClient(app)


def test_api_production_workflow_routes():
    client.post("/demo/reset")

    scanner = client.post("/controls/scanner-chaos", json={"repo": "payments-platform"})
    assert scanner.status_code == 200
    assert scanner.json()["actions"][0]["status"] == "planned"

    audit = client.post("/security/policy-audit", json={"repo": "payments-platform"})
    assert audit.status_code == 200

    incidents = client.get("/incidents?repo=payments-platform").json()
    regression = client.post(
        "/regression/investigate",
        json={"repo": "payments-platform", "incident_id": incidents[0]["id"]},
    )
    assert regression.status_code == 200
    assert regression.json()["patches"]

    ci = client.post("/ci/optimize", json={"repo": "payments-platform"})
    assert ci.status_code == 200
    assert ci.json()["actions"]

    memory = client.post("/memory/ask", json={"question": "auth gateway", "repo": "payments-platform"})
    assert memory.status_code == 200
    assert memory.json()["matches"]

    rep = client.post(
        "/reputation/feedback",
        json={"repo": "payments-platform", "mr_id": "128", "outcome": "closed", "features": {"touches_auth": 1}},
    )
    assert rep.status_code == 200
    assert rep.json()["trained"]

    html = client.get("/memory/dashboard.html")
    assert html.status_code == 200
    assert "SentinelGraph Dashboard" in html.text
