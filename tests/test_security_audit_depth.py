import base64
import json
import zipfile
from io import BytesIO

from fastapi.testclient import TestClient

from sentinelgraph.app import app
from sentinelgraph.factory import build_engines
from sentinelgraph.models import PolicyAuditRequest, ScannerChaosRequest
from sentinelgraph.scan_reports import parse_security_artifacts
from sentinelgraph.security_audit import remediate_ci_config
from sentinelgraph.storage import Store


def test_parse_gitlab_and_sarif_security_artifacts():
    gitlab_report = {
        "scan": {"type": "sast", "scanner": {"name": "scanner"}},
        "vulnerabilities": [
            {
                "id": "v1",
                "name": "SQL Injection",
                "severity": "High",
                "location": {"file": "app.py", "start_line": 12},
                "identifiers": [{"type": "cwe", "value": "CWE-89"}],
            }
        ],
    }
    sarif_report = {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"rules": [{"id": "CWE-798", "shortDescription": {"text": "Secret"}}]}},
                "results": [
                    {
                        "ruleId": "CWE-798",
                        "level": "error",
                        "message": {"text": "Hardcoded secret"},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "config.py"},
                                    "region": {"startLine": 4},
                                }
                            }
                        ],
                    }
                ],
            }
        ],
    }

    findings = parse_security_artifacts(
        {
            "gl-sast-report.json": json.dumps(gitlab_report),
            "results.sarif": json.dumps(sarif_report),
        }
    )

    assert len(findings) == 2
    assert {finding["cwe"] for finding in findings} == {"CWE-89", "CWE-798"}


def test_ci_remediation_edits_existing_gitlab_yaml():
    existing = """
stages:
  - test
unit:
  stage: test
  script: pytest
"""
    result = remediate_ci_config(existing, "gitlab")

    assert result["changed"]
    assert "Jobs/SAST.gitlab-ci.yml" in result["content"]
    assert "sentinelgraph-security-policy" in result["content"]
    assert "interruptible" in result["content"]


def test_ci_remediation_preserves_github_actions_trigger_key():
    existing = """
name: CI
on:
  pull_request:
    branches: [main]
jobs:
  unit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
"""
    result = remediate_ci_config(existing, "github")

    assert result["changed"]
    assert "true:" not in result["content"]
    assert "security:" in result["content"]
    assert "'on':" in result["content"] or "on:" in result["content"]


def test_policy_audit_returns_ci_remediation_and_provider_security_details(tmp_path):
    engines = build_engines(Store(tmp_path / "audit.db"))

    result = engines.policy_audit.audit(PolicyAuditRequest(repo="payments-platform"))

    assert result["ci_remediation"]["changed"]
    assert "security_findings" in result
    assert any(action["action"] == "commit_files" for action in result["actions"])


def test_scanner_chaos_waits_for_ci_in_dry_run(tmp_path):
    engines = build_engines(Store(tmp_path / "scanner.db"))

    result = engines.scanner_chaos.run(ScannerChaosRequest(repo="payments-platform", wait_for_ci=True))

    assert result["ci"]["completed"] is True
    assert result["artifact_findings"] == []


def test_api_wait_ci_and_parse_artifacts():
    client = TestClient(app)

    wait = client.post("/security/wait-ci", json={"repo": "payments-platform"})
    assert wait.status_code == 200
    assert wait.json()["ci"]["completed"] is True

    parsed = client.post(
        "/security/parse-artifacts",
        json={
            "artifacts": [
                {
                    "filename": "gl-secret-detection-report.json",
                    "content": json.dumps(
                        {
                            "scan": {"type": "secret_detection"},
                            "vulnerabilities": [
                                {"id": "s1", "name": "Leaked token", "severity": "Critical", "location": {"file": "settings.py"}}
                            ],
                        }
                    ),
                }
            ]
        },
    )
    assert parsed.status_code == 200
    assert parsed.json()["count"] == 1

    archive_buffer = BytesIO()
    with zipfile.ZipFile(archive_buffer, "w") as archive:
        archive.writestr(
            "gl-container-scanning-report.json",
            json.dumps(
                {
                    "scan": {"type": "container_scanning"},
                    "vulnerabilities": [
                        {"id": "c1", "name": "Outdated image", "severity": "High", "location": {"image": "api:latest"}}
                    ],
                }
            ),
        )

    zipped = client.post(
        "/security/parse-artifacts",
        json={
            "artifacts": [
                {
                    "filename": "artifacts.zip",
                    "content": base64.b64encode(archive_buffer.getvalue()).decode("ascii"),
                    "encoding": "base64",
                }
            ]
        },
    )
    assert zipped.status_code == 200
    assert zipped.json()["findings"][0]["report_type"] == "container-scanning"
