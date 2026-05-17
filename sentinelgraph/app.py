"""FastAPI application."""

from __future__ import annotations

import os
from base64 import b64decode
from typing import Optional

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import HTMLResponse

from .demo import load_demo
from .factory import build_engines
from .commands import dispatch_slash_command, is_slash_command
from .models import (
    AdvisoryEnrichmentRequest,
    AgentExploreRequest,
    BackgroundImportRequest,
    ControlRunInput,
    DecisionInput,
    ExploitabilitySimulationRequest,
    FindingInput,
    FullSecurityAuditRequest,
    FixtureImportRequest,
    IncidentInput,
    CiOptimizeRequest,
    CiWaitRequest,
    MemoryAskRequest,
    MemorySyncRequest,
    MergeRequestInput,
    OrgConfigInput,
    PackageInput,
    PolicyEvaluationInput,
    PolicyAuditRequest,
    RegressionRequest,
    ReplyCommandInput,
    ReputationFeedbackInput,
    RemediationVerificationRequest,
    RuntimeEventInput,
    ScannerChaosRequest,
    ScanArtifactParseRequest,
    SchedulerJobInput,
    SecurityDebateRequest,
    SourceImportRequest,
    SlashCommandRequest,
    VulnerabilityTriageRequest,
)
from .production import BackgroundJobManager, OrgRegistry, dashboard_html as product_dashboard_html
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
org_registry = OrgRegistry(engines.store)
background_jobs = BackgroundJobManager(engines.store, history_importer)

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
    imported = history_importer.import_webhook("gitlab", body).model_dump()
    command = gitlab_command_from_payload(body)
    command_result = dispatch_slash_command(engines, command) if command else None
    return {**imported, "command": command_result}


@app.post("/webhooks/github")
async def github_webhook(request: Request) -> dict:
    body_bytes = await request.body()
    secret = os.environ.get("SENTINELGRAPH_GITHUB_WEBHOOK_SECRET")
    if not verify_github_signature(body_bytes, request.headers.get("X-Hub-Signature-256"), secret):
        raise HTTPException(status_code=401, detail="Invalid webhook signature")
    payload = await request.json()
    imported = history_importer.import_webhook("github", payload).model_dump()
    command = github_command_from_payload(payload)
    command_result = dispatch_slash_command(engines, command) if command else None
    return {**imported, "command": command_result}


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


@app.get("/ui", response_class=HTMLResponse)
def product_ui() -> str:
    return product_dashboard_html()


@app.post("/orgs")
def upsert_org(item: OrgConfigInput) -> dict:
    return org_registry.upsert(item)


@app.get("/orgs")
def list_orgs() -> dict:
    return org_registry.list()


@app.post("/jobs/imports")
def start_background_import(item: BackgroundImportRequest) -> dict:
    return background_jobs.start_import(item)


@app.get("/jobs")
def list_background_jobs() -> dict:
    return background_jobs.status()


@app.get("/jobs/{job_id}")
def background_job_status(job_id: str) -> dict:
    result = background_jobs.status(job_id)
    if not result.get("job"):
        raise HTTPException(status_code=404, detail="Background job not found")
    return result


@app.post("/memory/decisions")
def add_decision(item: DecisionInput) -> dict:
    return engines.memory.add_decision(item).model_dump()


@app.post("/ingest/mr")
def ingest_mr(item: MergeRequestInput) -> dict:
    risk = engines.risk.analyze_mr(item)
    ai_governance = engines.ai_governance.analyze(item)
    policies = engines.policy.evaluate(
        PolicyEvaluationInput(
            repo=item.repo,
            subject_id=item.mr_id,
            context=risk.passport.get("policy_context", {}),
        )
    )
    result = risk.model_dump()
    result["ai_governance"] = ai_governance
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


@app.post("/security/scanner-chaos")
def scanner_validation(item: ScannerChaosRequest) -> dict:
    return engines.scanner_chaos.run(item)


@app.post("/security/policy-audit")
def policy_audit(item: PolicyAuditRequest) -> dict:
    return engines.policy_audit.audit(item)


@app.post("/security/full-audit")
def full_security_audit(item: FullSecurityAuditRequest) -> dict:
    return engines.full_security_audit.run(item)


@app.post("/security/triage")
def vulnerability_triage(item: VulnerabilityTriageRequest) -> dict:
    return engines.vulnerability_triage.run(item)


@app.post("/security/verify-remediation")
def remediation_verification(item: RemediationVerificationRequest) -> dict:
    return engines.remediation_verification.run(item)


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


@app.post("/advisories/enrich")
def enrich_advisory(item: AdvisoryEnrichmentRequest) -> dict:
    return engines.advisory.enrich(item)


@app.post("/commands/slash")
def slash_command(item: SlashCommandRequest) -> dict:
    return dispatch_slash_command(engines, item)


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


@app.post("/exploitability/simulate")
def simulate_exploitability(item: ExploitabilitySimulationRequest) -> dict:
    return engines.exploitability.simulate(item)


@app.post("/ai-governance/analyze")
def ai_governance_analyze(item: MergeRequestInput) -> dict:
    return engines.ai_governance.analyze(item)


@app.post("/security/debate")
def security_debate(item: SecurityDebateRequest) -> dict:
    return engines.security_debate.debate(item)


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


@app.post("/memory/enforce-patterns")
def memory_enforce_patterns(item: MergeRequestInput) -> dict:
    return engines.memory_suite.enforce_patterns(item)


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


@app.post("/reputation/ide-agent")
def reputation_ide_agent(item: MergeRequestInput) -> dict:
    return engines.reputation.ide_agent_context(item)


@app.post("/reputation/explore")
def reputation_explore(item: AgentExploreRequest) -> dict:
    return engines.reputation.agent_explore(item)


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


def gitlab_command_from_payload(payload: dict) -> SlashCommandRequest | None:
    attrs = payload.get("object_attributes") or {}
    note = attrs.get("note") or ""
    if not is_slash_command(note):
        return None
    project = payload.get("project") or {}
    repo = project.get("path_with_namespace") or attrs.get("project_id") or "unknown"
    noteable_type = str(attrs.get("noteable_type") or "").lower()
    issue = payload.get("issue") or {}
    merge_request = payload.get("merge_request") or {}
    return SlashCommandRequest(
        provider="gitlab",
        repo=str(repo),
        command=note,
        actor=(payload.get("user") or {}).get("username") or "unknown",
        dry_run=False,
        trigger_issue_id=str(issue.get("iid")) if noteable_type == "issue" and issue.get("iid") else None,
        trigger_change_id=str(merge_request.get("iid")) if "merge" in noteable_type and merge_request.get("iid") else None,
    )


def github_command_from_payload(payload: dict) -> SlashCommandRequest | None:
    comment = payload.get("comment") or {}
    body = comment.get("body") or ""
    if not is_slash_command(body):
        return None
    repo = (payload.get("repository") or {}).get("full_name") or "unknown"
    issue = payload.get("issue") or {}
    issue_number = issue.get("number")
    is_pull_request = bool(issue.get("pull_request"))
    return SlashCommandRequest(
        provider="github",
        repo=repo,
        command=body,
        actor=(comment.get("user") or {}).get("login") or "unknown",
        dry_run=False,
        trigger_issue_id=str(issue_number) if issue_number and not is_pull_request else None,
        trigger_change_id=str(issue_number) if issue_number and is_pull_request else None,
    )
