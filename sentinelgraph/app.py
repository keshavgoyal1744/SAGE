"""FastAPI application."""

from __future__ import annotations

import os
from typing import Optional

from fastapi import FastAPI, HTTPException, Query, Request

from .demo import load_demo
from .factory import build_engines
from .models import (
    ControlRunInput,
    DecisionInput,
    FindingInput,
    FixtureImportRequest,
    IncidentInput,
    MergeRequestInput,
    PackageInput,
    PolicyEvaluationInput,
    RuntimeEventInput,
    SourceImportRequest,
)
from .sarif import findings_to_sarif
from .source_control import (
    HistoryImporter,
    ProviderError,
    verify_github_signature,
    verify_gitlab_token,
)

engines = build_engines()
history_importer = HistoryImporter(engines)

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
