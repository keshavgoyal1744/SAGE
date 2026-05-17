# SentinelGraph

SentinelGraph is an organizational security memory and causality engine. It connects code changes, services, developers, runtime signals, controls, findings, incidents, dependencies, policies, tests, fixes, and compliance evidence into one queryable security knowledge graph.

It is designed around one loop:

```text
change -> graph context -> risk score -> control confidence -> runtime feedback
       -> incident learning -> regression hunt -> evidence and policy updates
```

## What Works Now

- Security knowledge graph with entity and edge traversal.
- Security decision memory that checks merge requests against active decisions.
- Merge request causality passport and adaptive risk scoring.
- Runtime telemetry ingestion and correlation.
- Control confidence scoring for scanners, policies, and blind spots.
- Supply-chain trust scoring for package releases.
- Incident creation with root-cause candidates and organization-wide regression hunt.
- Finding creation with CVE/GHSA/CWE fields and compliance evidence mapping.
- SARIF 2.1.0 export for existing security dashboards.
- Policy evaluation plus an OPA/Rego starter template.
- Incident replay timeline.
- FastAPI server and CLI.

## Run Locally

```bash
cd /home/grads/keshavgoyal/SideProject/sentinelgraph
python3 -m pytest
python3 -m uvicorn sentinelgraph.app:app --host 127.0.0.1 --port 8088
```

Load the demo:

```bash
curl -X POST http://127.0.0.1:8088/demo/reset
```

Useful endpoints:

```bash
curl http://127.0.0.1:8088/health
curl http://127.0.0.1:8088/dashboard?repo=payments-platform
curl http://127.0.0.1:8088/sarif?repo=payments-platform
curl "http://127.0.0.1:8088/graph/search?q=auth+bypass+gateway&types=incident,finding,decision"
curl http://127.0.0.1:8088/policies/rego
```

Analyze a merge request from JSON:

```bash
python3 -m sentinelgraph.cli demo
python3 -m sentinelgraph.cli analyze-mr examples_mr.json
```

## Core Concepts

**Security Knowledge Graph**

Entities include repositories, services, merge requests, developers, scanners, controls, findings, CVEs, dependencies, incidents, decisions, deployments, runtime events, customer impact, tests, fix patterns, agents, cloud resources, policies, and compliance evidence.

**Causality Passport**

Every analyzed change gets a passport containing risk score, reasons, linked decisions, runtime correlations, control blind spots, affected services, and required actions.

**Control Confidence**

Controls are scored by detection coverage, blind spots, exploit coverage, and policy failures. This treats security tooling as something that must be continuously validated, not blindly trusted.

**Runtime Feedback**

Runtime events from SIEM, WAF, observability, Kubernetes, cloud audit, or eBPF sources can be ingested and linked back to services, changes, findings, and incidents.

**Regression Hunt**

When an incident is created, SentinelGraph searches related services for sibling failure patterns, proposes findings, test ideas, fix patterns, scanner gap checks, and compliance evidence.

## Storage

The MVP uses SQLite in `data/sentinelgraph.db` so it runs immediately. The graph access layer is isolated behind `SecurityGraph` and `Store`, so a production deployment can swap in PostgreSQL, Neo4j, ArangoDB, or another graph backend later.
