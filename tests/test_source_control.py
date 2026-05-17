import json
from pathlib import Path

from fastapi.testclient import TestClient

from sentinelgraph.app import app
from sentinelgraph.factory import build_engines
from sentinelgraph.models import FixtureImportRequest, SourceChangeRecord
from sentinelgraph.source_control import HistoryImporter, extract_decisions, normalize_record
from sentinelgraph.storage import Store


FIXTURE = Path(__file__).resolve().parent.parent / "data" / "source_history_fixture.json"


def load_records():
    data = json.loads(FIXTURE.read_text())
    return [SourceChangeRecord(**record) for record in data["records"]]


def test_history_importer_imports_decisions_and_analyzes_records(tmp_path):
    engines = build_engines(Store(tmp_path / "history.db"))
    importer = HistoryImporter(engines)
    records = load_records()

    result = importer.import_records(records)

    assert result.imported == 2
    assert result.analyzed == 2
    assert result.decisions_imported == 1
    assert result.high_or_critical >= 1
    assert engines.store.counts()["analyses"] == 2
    assert engines.store.list_entities("integration")
    assert engines.store.list_entities("decision")


def test_normalize_record_extracts_ai_and_dependency_context():
    record = load_records()[0]

    mr = normalize_record(record)

    assert mr.ai_assisted is True
    assert mr.deployment_window == "Friday after-hours"
    assert mr.metadata["dependencies"]


def test_extract_decisions_from_review_comments():
    decisions = extract_decisions(load_records()[0])

    assert len(decisions) == 1
    assert decisions[0].security_relevant is True
    assert "auth" in decisions[0].tags


def test_api_import_records_and_webhook():
    client = TestClient(app)
    data = json.loads(FIXTURE.read_text())

    imported = client.post("/integrations/import-records", json=data)
    assert imported.status_code == 200
    assert imported.json()["imported"] == 2

    webhook = client.post(
        "/webhooks/github",
        json={
            "action": "opened",
            "number": 77,
            "repository": {"full_name": "payments-platform"},
            "pull_request": {
                "number": 77,
                "title": "Bypass gateway token check temporarily",
                "body": "Generated auth change that skips token validation.",
                "user": {"login": "dev"},
                "head": {"ref": "tmp-auth"},
                "base": {"ref": "main"},
                "state": "open",
                "created_at": "2026-05-15T23:00:00+00:00",
                "labels": [{"name": "security-sensitive"}],
                "html_url": "https://example.invalid/pull/77"
            },
        },
    )
    assert webhook.status_code == 200
    assert webhook.json()["imported"] == 1
