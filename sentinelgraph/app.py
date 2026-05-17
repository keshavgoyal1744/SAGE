"""FastAPI application."""

from __future__ import annotations

import os
from base64 import b64decode
from typing import Optional

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import HTMLResponse

from .demo import load_demo
from .factory import build_engines
from .models import (
    ControlRunInput,
    DecisionInput,
    FindingInput,
    FixtureImportRequest,
    IncidentInput,
    CiOptimizeRequest,
    CiWaitRequest,
    MemoryAskRequest,
    MemorySyncRequest,
    MergeRequestInput,
    PackageInput,
    PolicyEvaluationInput,
    PolicyAuditRequest,
    RegressionRequest,
    ReplyCommandInput,
    ReputationFeedbackInput,
    RuntimeEventInput,
    ScannerChaosRequest,
    ScanArtifactParseRequest,
    SchedulerJobInput,
    SourceImportRequest,
)
from .sarif import findings_to_sarif
from .scan_reports import parse_security_artifacts
from .provider_ops import ProviderOps
from .source_control import (
    HistoryImporter,
    ProviderError,
    verify_github_signature,
    verify_gitlab_token,
)
from .scheduler import IncrementalScheduler

engines = build_engines()
history_importer = HistoryImporter(engines)
scheduler = IncrementalScheduler(history_importer)

app = FastAPI(
    title="SentinelGraph",
    description="Organizational security memory and causality engine",
    version="0.1.0",
)


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "counts": engines.store.counts()}


@app.post("/demo/reset")
def demo_reset() -> dict:
    return load_demo(engines)


@app.post("/integrations/import")
def import_history(item: SourceImportRequest) -> dict:
    try:
        return history_importer.import_from_request(item).model_dump()
    except ProviderError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Provider import failed: {exc}")


@app.post("/integrations/import-records")
def import_records(item: FixtureImportRequest) -> dict:
    return history_importer.import_records(
        item.records,
        import_decisions=item.import_decisions,
        analyze=item.analyze,
    ).model_dump()


@app.post("/webhooks/gitlab")
async def gitlab_webhook(request: Request) -> dict:
    body = await request.json()
    secret = os.environ.get("SENTINELGRAPH_GITLAB_WEBHOOK_SECRET")
    if not verify_gitlab_token(request.headers.get("X-Gitlab-Token"), secret):
        raise HTTPException(status_code=401, detail="Invalid webhook token")
    return history_importer.import_webhook("gitlab", body).model_dump()


@app.post("/webhooks/github")
async def github_webhook(request: Request) -> dict:
    body_bytes = await request.body()
    secret = os.environ.get("SENTINELGRAPH_GITHUB_WEBHOOK_SECRET")
    if not verify_github_signature(body_bytes, request.headers.get("X-Hub-Signature-256"), secret):
        raise HTTPException(status_code=401, detail="Invalid webhook signature")
    return history_importer.import_webhook("github", await request.json()).model_dump()


@app.get("/dashboard")
def dashboard(repo: Optional[str] = None) -> dict:
    findings = engines.store.list_findings(repo)
    analyses = engines.store.list_analyses(repo)
    control_context = engines.controls.latest_context(repo) if repo else engines.controls.latest_context("payments-platform")
    incidents = engines.store.list_incidents(repo)
    evidence = engines.store.list_compliance_evidence()
    high_findings = [f for f in findings if f["severity"] in {"high", "critical"}]
    return {
        "counts": engines.store.counts(),
        "latest_risk": analyses[:5],
        "high_findings": high_findings,
        "control_context": control_context,
        "incidents": incidents,
        "compliance_evidence": evidence[:20],
    }


@app.post("/memory/decisions")
def add_decision(item: DecisionInput) -> dict:
    return engines.memory.add_decision(item).model_dump()


@app.post("/ingest/mr")
def ingest_mr(item: MergeRequestInput) -> dict:
    risk = engines.risk.analyze_mr(item)
    policies = engines.policy.evaluate(
        PolicyEvaluationInput(
            repo=item.repo,
            subject_id=item.mr_id,
            context=risk.passport.get("policy_context", {}),
        )
    )
    result = risk.model_dump()
    result["policy"] = [policy.model_dump() for policy in policies]
    return result


@app.post("/ingest/runtime")
def ingest_runtime(item: RuntimeEventInput) -> dict:
    return engines.runtime.ingest(item)


@app.post("/controls/run")
def run_control_validation(item: ControlRunInput) -> dict:
    return engines.controls.record_run(item).model_dump()


@app.post("/controls/scanner-chaos")
def scanner_chaos(item: ScannerChaosRequest) -> dict:
    return engines.scanner_chaos.run(item)


@app.post("/security/policy-audit")
def policy_audit(item: PolicyAuditRequest) -> dict:
    return engines.policy_audit.audit(item)


@app.post("/security/wait-ci")
def wait_ci(item: CiWaitRequest) -> dict:
    ops = ProviderOps(item)
    ci = ops.wait_for_ci(item.ref, item.timeout_seconds, item.poll_seconds)
    artifacts = ops.download_ci_artifacts(ci)
    return {
        "ci": ci,
        "artifact_count": len(artifacts),
        "findings": parse_security_artifacts(artifacts),
    }


@app.post("/security/parse-artifacts")
def parse_artifacts(item: ScanArtifactParseRequest) -> dict:
    artifacts = {}
    for artifact in item.artifacts:
        if artifact.encoding == "base64":
            try:
                artifacts[artifact.filename] = b64decode(artifact.content)
            except Exception as exc:
                raise HTTPException(status_code=400, detail=f"Invalid base64 artifact {artifact.filename}") from exc
        else:
            artifacts[artifact.filename] = artifact.content
    findings = parse_security_artifacts(artifacts)
    return {"findings": findings, "count": len(findings)}


@app.get("/controls/context")
def control_context(repo: str) -> dict:
    return engines.controls.latest_context(repo)


@app.post("/supply-chain/packages")
def analyze_package(item: PackageInput) -> dict:
    return engines.supply_chain.analyze(item)


@app.post("/findings")
def create_finding(item: FindingInput) -> dict:
    finding = engines.findings.create(item)
    finding["compliance_evidence"] = engines.compliance.evidence_for_finding(finding)
    return finding


@app.get("/findings")
def list_findings(repo: Optional[str] = None) -> list[dict]:
    return engines.store.list_findings(repo)


@app.post("/incidents")
def create_incident(item: IncidentInput) -> dict:
    return engines.incidents.create_incident(item)


@app.post("/regression/investigate")
def regression_investigate(item: RegressionRequest) -> dict:
    return engines.regression.investigate(item)


@app.post("/ci/optimize")
def ci_optimize(item: CiOptimizeRequest) -> dict:
    return engines.ci_optimizer.optimize(item)


@app.get("/incidents")
def list_incidents(repo: Optional[str] = None) -> list[dict]:
    return engines.store.list_incidents(repo)


@app.get("/replay/{incident_id}")
def replay(incident_id: str) -> dict:
    events = engines.replay.build(incident_id)
    if not events:
        raise HTTPException(status_code=404, detail="Incident not found")
    return {"incident_id": incident_id, "timeline": [event.model_dump() for event in events]}


@app.post("/policies/evaluate")
def evaluate_policy(item: PolicyEvaluationInput) -> dict:
    return {"results": [result.model_dump() for result in engines.policy.evaluate(item)]}


@app.get("/policies/rego")
def rego_template() -> dict:
    return {"rego": engines.policy.rego_template()}


@app.get("/memory/validate")
def memory_validate() -> dict:
    return engines.memory_suite.validate()


@app.post("/memory/sync")
def memory_sync(item: MemorySyncRequest) -> dict:
    return engines.memory_suite.sync(item)


@app.post("/memory/ask")
def memory_ask(item: MemoryAskRequest) -> dict:
    return engines.memory_suite.ask(item)


@app.get("/memory/dashboard.html", response_class=HTMLResponse)
def memory_dashboard_html() -> str:
    return engines.memory_suite.dashboard_html()


@app.get("/memory/onboarding")
def memory_onboarding(repo: str) -> dict:
    return engines.memory_suite.onboarding(repo)


@app.get("/memory/health")
def memory_health(repo: Optional[str] = None) -> dict:
    return engines.memory_suite.health(repo)


@app.post("/memory/reply")
def memory_reply(item: ReplyCommandInput) -> dict:
    return engines.memory_suite.reply(item)


@app.get("/memory/pattern-rules")
def memory_pattern_rules() -> dict:
    return engines.memory_suite.pattern_rules()


@app.post("/reputation/score")
def reputation_score(item: MergeRequestInput) -> dict:
    return engines.reputation.score_mr(item)


@app.post("/reputation/feedback")
def reputation_feedback(item: ReputationFeedbackInput) -> dict:
    return engines.reputation.feedback(item)


@app.get("/reputation/users")
def reputation_users(repo: Optional[str] = None) -> dict:
    return engines.reputation.user_reputation(repo)


@app.post("/reputation/checkpoint")
def reputation_checkpoint() -> dict:
    return engines.reputation.checkpoint()


@app.post("/scheduler/jobs")
def scheduler_add_job(item: SchedulerJobInput) -> dict:
    return scheduler.add_job(item)


@app.post("/scheduler/jobs/{job_id}/run")
def scheduler_run_once(job_id: str) -> dict:
    if job_id not in scheduler.jobs:
        raise HTTPException(status_code=404, detail="Scheduler job not found")
    return scheduler.run_once(job_id)


@app.post("/scheduler/jobs/{job_id}/start")
def scheduler_start(job_id: str) -> dict:
    if job_id not in scheduler.jobs:
        raise HTTPException(status_code=404, detail="Scheduler job not found")
    return scheduler.start(job_id)


@app.get("/scheduler/status")
def scheduler_status() -> dict:
    return scheduler.status()


@app.get("/sarif")
def sarif(repo: Optional[str] = None) -> dict:
    return findings_to_sarif(engines.store.list_findings(repo))


@app.get("/graph/entities")
def entities(type: Optional[str] = Query(default=None)) -> list[dict]:
    return [entity.model_dump() for entity in engines.store.list_entities(type)]


@app.get("/graph/traverse/{entity_id}")
def traverse(entity_id: str, depth: int = 3) -> dict:
    graph = engines.graph.traverse(entity_id, depth=depth)
    if not graph["nodes"]:
        raise HTTPException(status_code=404, detail="Entity not found")
    return graph


@app.get("/graph/search")
def graph_search(q: str, depth: int = 2, types: Optional[str] = None) -> dict:
    entity_types = types.split(",") if types else None
    keywords = [part.strip() for part in q.split() if part.strip()]
    return engines.graph.causal_search(keywords=keywords, entity_types=entity_types, depth=depth)
