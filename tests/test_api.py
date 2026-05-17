from fastapi.testclient import TestClient

from sentinelgraph.app import app


client = TestClient(app)


def test_api_demo_dashboard_sarif_and_graph_search():
    demo = client.post("/demo/reset")
    assert demo.status_code == 200
    assert demo.json()["risk"]["level"] == "critical"

    health = client.get("/health")
    assert health.status_code == 200
    assert health.json()["status"] == "ok"

    dashboard = client.get("/dashboard?repo=payments-platform")
    assert dashboard.status_code == 200
    assert dashboard.json()["high_findings"]

    sarif = client.get("/sarif?repo=payments-platform")
    assert sarif.status_code == 200
    assert sarif.json()["runs"][0]["results"]

    search = client.get("/graph/search?q=auth+bypass+gateway&types=incident,finding,decision")
    assert search.status_code == 200
    assert search.json()["nodes"]
