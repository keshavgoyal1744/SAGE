from sentinelgraph.demo import load_demo
from sentinelgraph.factory import build_engines
from sentinelgraph.models import (
    AgentExploreRequest,
    BackgroundImportRequest,
    MergeRequestInput,
    OrgConfigInput,
    SourceImportResult,
)
from sentinelgraph.production import BackgroundJobManager, OrgRegistry
from sentinelgraph.regression import optimize_gitlab_ci
from sentinelgraph.storage import Store


def seeded(tmp_path):
    engines = build_engines(Store(tmp_path / "deep.db"))
    load_demo(engines)
    return engines


def test_regression_outputs_code_tests_and_candidate_patches(tmp_path):
    engines = seeded(tmp_path)
    incident_id = engines.store.list_incidents("payments-platform")[0]["id"]

    result = engines.regression.investigate(
        __import__("sentinelgraph.models", fromlist=["RegressionRequest"]).RegressionRequest(
            repo="payments-platform",
            incident_id=incident_id,
            affected_file="services/gateway/auth_middleware.py",
        )
    )

    assert result["root_cause"]
    assert result["tests"][0]["path"].endswith("_security_regression.py")
    assert result["patches"][0]["path"].endswith((".patch", ".py"))


def test_ci_optimizer_edits_existing_gitlab_yaml():
    content, notes = optimize_gitlab_ci(
        """
stages: [test]
unit:
  stage: test
  script: pytest
"""
    )

    assert "unit:" in content
    assert "sentinelgraph-security:" in content
    assert "interruptible" in content
    assert notes


def test_memory_enforcement_and_reputation_agent_context(tmp_path):
    engines = seeded(tmp_path)
    mr = MergeRequestInput(
        repo="payments-platform",
        mr_id="900",
        title="remove auth bypass md5 helper",
        description="temporary bypass",
        author="dev",
        files_changed=["services/gateway/auth.py"],
        diff_summary="md5 bypass select *",
        ai_assisted=True,
    )

    enforcement = engines.memory_suite.enforce_patterns(mr)
    ide = engines.reputation.ide_agent_context(mr)
    exploration = engines.reputation.agent_explore(
        AgentExploreRequest(repo="payments-platform", file_path=None, question="pickle.loads md5 requests.get")
    )

    assert enforcement["status"] in {"pass", "warn", "fail"}
    assert ide["ide_focus"]
    assert exploration["findings"]


def test_org_registry_and_background_import_jobs(tmp_path):
    store = Store(tmp_path / "jobs.db")
    registry = OrgRegistry(store)
    org = registry.upsert(
        OrgConfigInput(org_id="acme", provider="github", repos=["acme/api"], token_env="GITHUB_TOKEN")
    )

    assert org["org_id"] == "acme"
    assert registry.list()["orgs"][0]["repos"] == ["acme/api"]

    class FakeImporter:
        def import_from_request(self, request):
            return SourceImportResult(
                provider=request.provider,
                repo=request.repo,
                imported=0,
                analyzed=0,
                decisions_imported=0,
                high_or_critical=0,
            )

    jobs = BackgroundJobManager(store, FakeImporter())
    started = jobs.start_import(
        BackgroundImportRequest(job_id="import-acme-api", provider="github", repo="acme/api", limit=1)
    )

    assert started["status"] in {"queued", "running", "completed"}
    assert jobs.status()["jobs"]
