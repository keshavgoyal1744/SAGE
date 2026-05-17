"""FastAPI application."""

from __future__ import annotations

from typing import Optional

from fastapi import FastAPI, HTTPException, Query

from .demo import load_demo
from .factory import build_engines
from .models import (
    ControlRunInput,
    DecisionInput,
    FindingInput,
    IncidentInput,
    MergeRequestInput,
    PackageInput,
    PolicyEvaluationInput,
    RuntimeEventInput,
)
from .sarif import findings_to_sarif

engines = build_engines()

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
