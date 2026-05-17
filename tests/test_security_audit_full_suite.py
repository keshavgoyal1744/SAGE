from fastapi.testclient import TestClient

from sentinelgraph.app import app
from sentinelgraph.factory import build_engines
from sentinelgraph.models import (
    FullSecurityAuditRequest,
    RemediationVerificationRequest,
    ScannerChaosRequest,
    VulnerabilityTriageRequest,
)
from sentinelgraph.security_audit import PAYLOAD_CATALOG, assignees_for_owner, normalize_provider_finding, triage_finding
from sentinelgraph.storage import Store


def test_scanner_validation_has_full_payload_matrix_and_owasp_mapping(tmp_path):
    engines = build_engines(Store(tmp_path / "audit-suite.db"))

    result = engines.scanner_chaos.run(
        ScannerChaosRequest(repo="payments-platform", trigger_issue_id="12")
    )

    assert len(PAYLOAD_CATALOG) == 15
    assert len(result["files"]) == 15
    assert result["owasp_coverage"]["payloads"] == 15
    assert result["owasp_coverage"]["covered"] >= 6
    assert any(action["action"] == "comment_on_issue" for action in result["actions"])


def test_vulnerability_triage_classifies_prioritizes_and_plans_reports(tmp_path):
    engines = build_engines(Store(tmp_path / "triage.db"))
    raw = {
        "source": "github-code-scanning",
        "rule": {"name": "SQL injection"},
        "severity": "critical",
        "most_recent_instance": {"location": {"path": "services/api/users.py", "start_line": 42}},
    }
    normalized = normalize_provider_finding(raw)
    triaged = triage_finding(normalized, "alice")

    assert triaged["priority"] == "P0"
    assert triaged["classification"] == "true-positive"
    assert "parameterized" in triaged["suggested_fix"]
    assert assignees_for_owner("@alice") == ["alice"]

    result = engines.vulnerability_triage.run(
        VulnerabilityTriageRequest(repo="payments-platform", trigger_issue_id="20")
    )

    assert result["summary"]["total"] == 0
    assert any(action["action"] == "create_issue" for action in result["actions"])
    assert any(action["action"] == "comment_on_issue" for action in result["actions"])


def test_remediation_verification_dry_run_creates_report_and_trigger_comment(tmp_path):
    engines = build_engines(Store(tmp_path / "verify.db"))

    result = engines.remediation_verification.run(
        RemediationVerificationRequest(repo="payments-platform", trigger_issue_id="21")
    )

    assert result["summary"]["total"] == 0
    assert any(action["action"] == "create_issue" for action in result["actions"])
    assert any(action["action"] == "comment_on_issue" for action in result["actions"])


def test_full_security_audit_and_api_routes(tmp_path):
    engines = build_engines(Store(tmp_path / "full.db"))
    result = engines.full_security_audit.run(
        FullSecurityAuditRequest(repo="payments-platform", trigger_issue_id="22")
    )

    assert result["summary"]["policy_score"] == 0
    assert result["summary"]["scanner_confidence"] < 100
    assert result["trigger_actions"]

    client = TestClient(app)
    response = client.post("/security/full-audit", json={"repo": "payments-platform"})
    assert response.status_code == 200
    assert "scanner" in response.json()

    scanner = client.post("/security/scanner-chaos", json={"repo": "payments-platform"})
    assert scanner.status_code == 200
    assert len(scanner.json()["files"]) == 15

    triage = client.post("/security/triage", json={"repo": "payments-platform"})
    assert triage.status_code == 200

    verify = client.post("/security/verify-remediation", json={"repo": "payments-platform"})
    assert verify.status_code == 200
