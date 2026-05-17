from sentinelgraph.factory import build_engines
from sentinelgraph.models import (
    CiOptimizeRequest,
    MemoryAskRequest,
    MemorySyncRequest,
    PolicyAuditRequest,
    RegressionRequest,
    ReputationFeedbackInput,
    ScannerChaosRequest,
)
from sentinelgraph.storage import Store


def seeded(tmp_path):
    from sentinelgraph.demo import load_demo

    engines = build_engines(Store(tmp_path / "prod.db"))
    load_demo(engines)
    return engines


def test_scanner_policy_regression_and_ci_workflows_dry_run(tmp_path):
    engines = seeded(tmp_path)

    scanner = engines.scanner_chaos.run(ScannerChaosRequest(repo="payments-platform"))
    assert scanner["actions"][0]["status"] == "planned"
    assert scanner["score"]["missed"] > 0

    audit = engines.policy_audit.audit(PolicyAuditRequest(repo="payments-platform"))
    assert audit["score"] == 0
    assert audit["actions"]

    incident_id = engines.store.list_incidents("payments-platform")[0]["id"]
    regression = engines.regression.investigate(RegressionRequest(repo="payments-platform", incident_id=incident_id))
    assert regression["root_cause"]
    assert regression["patches"]
    assert regression["tests"]
    assert regression["actions"]

    ci = engines.ci_optimizer.optimize(CiOptimizeRequest(repo="payments-platform"))
    assert ci["actions"][0]["status"] == "planned"
    assert "rules:" in ci["content"] or "paths:" in ci["content"]


def test_memory_suite_reports_and_reply(tmp_path):
    engines = seeded(tmp_path)

    validation = engines.memory_suite.validate()
    assert validation["valid"]

    answer = engines.memory_suite.ask(MemoryAskRequest(question="auth gateway validation", repo="payments-platform"))
    assert answer["matches"]

    html = engines.memory_suite.dashboard_html()
    assert "SentinelGraph Dashboard" in html

    onboarding = engines.memory_suite.onboarding("payments-platform")
    assert onboarding["security_decisions"]

    health = engines.memory_suite.health("payments-platform")
    assert health["active_decisions"] >= 1

    sync = engines.memory_suite.sync(MemorySyncRequest(repo="payments-platform"))
    assert "SENTINELGRAPH-INDEX.md" in sync["pages"]

    decision = engines.store.list_entities("decision")[0]
    updated = engines.memory_suite.reply(
        item=__import__("sentinelgraph.models", fromlist=["ReplyCommandInput"]).ReplyCommandInput(
            repo="payments-platform",
            decision_id=decision.id,
            command="intentional",
            reasoning="Accepted with compensating controls.",
            actor="security",
        )
    )
    assert updated["decision"]["attributes"]["status"] == "superseded"


def test_reputation_model_feedback_and_checkpoint(tmp_path):
    engines = seeded(tmp_path)
    mr_payload = engines.store.list_analyses("payments-platform")[0]["payload"]
    features = {
        "touches_auth": 1,
        "touches_validation": 1,
        "ai_assisted": 1,
        "dependency_change": 1,
        "docs_only": 0,
        "approval_count": 0.2,
        "file_count": 0.2,
        "risky_words": 0.8,
    }

    trained = engines.reputation.feedback(
        ReputationFeedbackInput(repo="payments-platform", mr_id=mr_payload["mr_id"], outcome="closed", features=features)
    )
    assert trained["trained"]
    assert trained["sample_count"] == 1

    checkpoint = engines.reputation.checkpoint()
    assert checkpoint["path"].endswith("reputation_model.json")
