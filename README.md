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
- GitLab and GitHub history import with webhook endpoints for ongoing updates.
- Provider writeback for comments, issues, branches, commits, and PR/MR creation.
- Scanner chaos workflow that injects synthetic payloads into a branch.
- Security policy audit with remediation issue creation.
- CI wait/poll support for GitLab pipelines and GitHub Actions workflow runs.
- Security artifact parsing for GitLab SAST, secret detection, dependency/container scanning, and SARIF.
- GitLab vulnerability/dependency security API aggregation.
- GitHub code scanning, Dependabot, and secret scanning API aggregation.
- Protected branch, approval, required status check, and protected environment checks.
- Structured CI remediation for existing GitLab CI and GitHub Actions workflows.
- Root-cause/sibling regression workflow with generated patch and test PR plans.
- CI optimizer for GitLab CI and GitHub Actions.
- Memory validation, sync pages, HTML dashboard, ask endpoint, onboarding, health, carbon, reply commands, and pattern rules.
- Online adaptive reputation model with feedback training and checkpointing.
- Incremental sync scheduler.

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

Import real merge request history:

```bash
# GitLab: repo is group/project. Uses GITLAB_TOKEN when available.
python3 -m sentinelgraph.cli import-history --provider gitlab --repo my-group/my-project --limit 0

# GitHub: repo is owner/repo. Uses GITHUB_TOKEN when available.
python3 -m sentinelgraph.cli import-history --provider github --repo my-org/my-repo --limit 0
```

API import:

```bash
curl -X POST http://127.0.0.1:8088/integrations/import \
  -H 'Content-Type: application/json' \
  -d '{"provider":"github","repo":"my-org/my-repo","token_env":"GITHUB_TOKEN","limit":0}'
```

Use `limit: 0` to backfill all available pages.

Offline fixture import uses the same normalization and analysis pipeline:

```bash
python3 -m sentinelgraph.cli import-fixture data/source_history_fixture.json
```

Webhook endpoints:

```text
POST /webhooks/gitlab
POST /webhooks/github
```

Set `SENTINELGRAPH_GITLAB_WEBHOOK_SECRET` or `SENTINELGRAPH_GITHUB_WEBHOOK_SECRET` to require signed/secret webhooks.

Run production workflows in dry-run mode:

```bash
python3 -m sentinelgraph.cli scanner-chaos --repo my-org/my-repo
python3 -m sentinelgraph.cli policy-audit --repo my-org/my-repo
python3 -m sentinelgraph.cli wait-ci --repo my-org/my-repo --ref main
python3 -m sentinelgraph.cli regression --repo my-org/my-repo --incident-id incident_id
python3 -m sentinelgraph.cli optimize-ci --repo my-org/my-repo
python3 -m sentinelgraph.cli ask "what auth decisions govern gateway?"
python3 -m sentinelgraph.cli validate-memory
python3 -m sentinelgraph.cli reputation-score examples_mr.json
```

Add `--provider gitlab --execute` or `--provider github --execute` to mutate real repos. Use tokens through `GITLAB_TOKEN` or `GITHUB_TOKEN`.

For scanner validation with real CI polling:

```bash
python3 -m sentinelgraph.cli scanner-chaos \
  --provider gitlab \
  --repo my-group/my-project \
  --execute \
  --wait-for-ci \
  --timeout 900 \
  --poll 15
```

Security artifact parsing is also available directly:

```bash
python3 -m sentinelgraph.cli parse-artifacts gl-sast-report.json results.sarif artifacts.zip
python3 -m sentinelgraph.cli policy-audit --provider github --repo my-org/my-repo --default-branch trunk --execute
```

The API `POST /security/parse-artifacts` accepts text JSON/SARIF artifacts and base64-encoded zip archives from GitLab or GitHub CI artifact downloads.

Deployment:

```bash
docker compose up --build
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
