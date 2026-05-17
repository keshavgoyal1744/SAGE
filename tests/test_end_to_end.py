from sentinelgraph.demo import load_demo
from sentinelgraph.factory import build_engines
from sentinelgraph.models import ControlPayloadResult, ControlRunInput, MergeRequestInput
from sentinelgraph.sarif import findings_to_sarif
from sentinelgraph.storage import Store


def test_demo_loads_full_security_loop(tmp_path):
    engines = build_engines(Store(tmp_path / "test.db"))

    result = load_demo(engines)

    assert result["risk"]["level"] == "critical"
    assert result["control_score"]["confidence_score"] < 80
    assert result["incident"]["hunt"]["siblings_found"] >= 1
    assert result["counts"]["entities"] > 10
    assert result["policy"]
    assert any(policy["status"] == "fail" for policy in result["policy"])


def test_mr_analysis_uses_memory_runtime_controls_and_supply_chain(tmp_path):
    engines = build_engines(Store(tmp_path / "risk.db"))
    load_demo(engines)

    result = engines.risk.analyze_mr(
        MergeRequestInput(
            repo="payments-platform",
            mr_id="200",
            title="Temporarily bypass gateway validation",
            description="AI-assisted auth cleanup.",
            author="casey",
            files_changed=["services/gateway/auth_middleware.py"],
            diff_summary="Removed issuer validation and skips audience check.",
            ai_assisted=True,
            approvals=1,
            deployment_window="Friday after-hours",
            metadata={
                "dependencies": [{"name": "jwt-lite", "risk_level": "critical", "new": True}],
                "developer_behavior": {"review_bypass_attempts": True},
            },
        )
    )

    codes = {reason.code for reason in result.reasons}
    assert result.level == "critical"
    assert "memory-conflict" in codes
    assert "runtime-feedback" in codes
    assert "control-confidence" in codes
    assert "supply-chain-risk" in codes


def test_control_confidence_scores_blind_spots(tmp_path):
    engines = build_engines(Store(tmp_path / "control.db"))
    score = engines.controls.record_run(
        ControlRunInput(
            control_id="scanner-suite",
            control_type="scanner-validation",
            repo="app",
            scanner="default",
            payloads=[
                ControlPayloadResult(payload_id="a", category="sql-injection", detected=True),
                ControlPayloadResult(payload_id="b", category="ssrf", detected=False),
                ControlPayloadResult(payload_id="c", category="secret", detected=False),
            ],
        )
    )

    assert score.detected == 1
    assert score.missed == 2
    assert "ssrf" in score.blind_spots
    assert score.confidence_score < 60


def test_sarif_export_contains_findings(tmp_path):
    engines = build_engines(Store(tmp_path / "sarif.db"))
    load_demo(engines)

    sarif = findings_to_sarif(engines.store.list_findings("payments-platform"))

    assert sarif["version"] == "2.1.0"
    assert sarif["runs"][0]["results"]
