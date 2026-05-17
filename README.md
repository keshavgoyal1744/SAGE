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
- External advisory enrichment through OSV/NVD for CVE, GHSA, and package risk context.
- Incident replay timeline.
- Exploitability simulation that reasons about reachability, runtime evidence, control blind spots, and active decisions.
- FastAPI server and CLI.
- GitLab and GitHub history import with webhook endpoints for ongoing updates.
- Provider writeback for comments, issues, branches, commits, and PR/MR creation.
- Scanner validation workflow that injects the full 15-payload SAST/secret matrix with OWASP Top 10 and CWE mapping.
- Scanner validation branch cleanup hooks and explicit do-not-merge audit comments.
- Security policy audit with remediation issue creation.
- Vulnerability triage that fetches provider findings, filters scanner-test payloads, classifies true/false positives, and opens owner-targeted P0/P1 child issues.
- Remediation verification that inspects open security issues, checks linked fixes, closes verified issues, escalates stale ones, and creates a central report.
- Idempotent issue creation with stable fingerprints to avoid duplicate remediation/report issues.
- Slash-command and GitLab Duo-style workflow metadata with trigger-context comments for every security audit run.
- Live slash-command dispatcher for `/sentinelgraph` and `/sg` comments.
- CI wait/poll support for GitLab pipelines and GitHub Actions workflow runs.
- Security artifact parsing for GitLab SAST, secret detection, dependency/container scanning, and SARIF.
- GitLab vulnerability/dependency security API aggregation.
- GitHub code scanning, Dependabot, and secret scanning API aggregation.
- Protected branch, approval, required status check, and protected environment checks.
- Structured CI remediation for existing GitLab CI and GitHub Actions workflows.
- Root-cause detection that can use provider file history, commit diffs, and linked PRs/MRs.
- Deeper sibling regression discovery from imported history and generated code/test PR plans.
- CI optimizer that edits existing GitLab CI and GitHub Actions workflows instead of replacing them blindly.
- Memory validation, decision dependency validation, sync pages, HTML dashboard, ask endpoint, onboarding, health, carbon, reply commands, and pattern rule enforcement.
- External memory sync to repository docs and GitLab wiki pages.
- AI coding risk governance for generated auth, unsafe crypto, hallucinated dependencies, dropped validation, missing negative tests, and per-model risk profiles.
- Multi-perspective security debate across attacker, defender, compliance, runtime, and exploitability viewpoints.
- Online adaptive reputation model with richer MR/user features, IDE agent context, deep exploration hooks, feedback training, checkpointing, and optional PostgreSQL/GCS checkpoint persistence.
- Incremental sync scheduler, background import jobs, multi-org auth profiles, retry/rate-limit handling for provider pagination, and a frontend dashboard.

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
curl http://127.0.0.1:8088/ui
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
python3 -m sentinelgraph.cli full-audit --repo my-org/my-repo
python3 -m sentinelgraph.cli triage-vulnerabilities --repo my-org/my-repo
python3 -m sentinelgraph.cli verify-remediation --repo my-org/my-repo
python3 -m sentinelgraph.cli wait-ci --repo my-org/my-repo --ref main
python3 -m sentinelgraph.cli regression --repo my-org/my-repo --incident-id incident_id
python3 -m sentinelgraph.cli optimize-ci --repo my-org/my-repo
python3 -m sentinelgraph.cli ask "what auth decisions govern gateway?"
python3 -m sentinelgraph.cli validate-memory
python3 -m sentinelgraph.cli reputation-score examples_mr.json
python3 -m sentinelgraph.cli ide-agent examples_mr.json
python3 -m sentinelgraph.cli enforce-patterns examples_mr.json
```

Add `--provider gitlab --execute` or `--provider github --execute` to mutate real repos. Use tokens through `GITLAB_TOKEN` or `GITHUB_TOKEN`.

For scanner validation with real CI polling:

```bash
python3 -m sentinelgraph.cli scanner-chaos \
  --provider gitlab \
  --repo my-group/my-project \
  --execute \
  --wait-for-ci \
  --trigger-issue-id 42 \
  --timeout 900 \
  --poll 15
```

Security artifact parsing is also available directly:

```bash
python3 -m sentinelgraph.cli parse-artifacts gl-sast-report.json results.sarif artifacts.zip
python3 -m sentinelgraph.cli advisory-enrich --cve CVE-2024-12345
python3 -m sentinelgraph.cli simulate-exploitability --repo my-org/my-repo --severity high --category auth --file services/gateway/auth.py
python3 -m sentinelgraph.cli ai-governance examples_mr.json
python3 -m sentinelgraph.cli security-debate --repo my-org/my-repo --subject-id 123
python3 -m sentinelgraph.cli slash-command --repo my-org/my-repo "/sentinelgraph full-audit"
python3 -m sentinelgraph.cli sync-memory --provider gitlab --repo my-group/my-project --external-target wiki --execute
python3 -m sentinelgraph.cli full-audit --provider gitlab --repo my-group/my-project --execute --trigger-issue-id 42
python3 -m sentinelgraph.cli triage-vulnerabilities --provider github --repo my-org/my-repo --execute --trigger-change-id 17
python3 -m sentinelgraph.cli verify-remediation --provider gitlab --repo my-group/my-project --execute --trigger-issue-id 43
python3 -m sentinelgraph.cli policy-audit --provider github --repo my-org/my-repo --default-branch trunk --execute
python3 -m sentinelgraph.cli regression --provider github --repo my-org/my-repo --affected-file services/api/auth.py --execute
python3 -m sentinelgraph.cli optimize-ci --provider github --repo my-org/my-repo --default-branch trunk --execute
python3 -m sentinelgraph.cli org-config --org-id acme --provider github --repo acme/api --token-env GITHUB_TOKEN
```

The API `POST /security/parse-artifacts` accepts text JSON/SARIF artifacts and base64-encoded zip archives from GitLab or GitHub CI artifact downloads.

Production workflow endpoints:

```text
GET  /ui
POST /orgs
GET  /orgs
POST /jobs/imports
GET  /jobs
POST /security/full-audit
POST /security/scanner-chaos
POST /security/policy-audit
POST /security/triage
POST /security/verify-remediation
POST /security/parse-artifacts
POST /advisories/enrich
POST /commands/slash
POST /exploitability/simulate
POST /ai-governance/analyze
POST /security/debate
POST /memory/enforce-patterns
POST /reputation/ide-agent
POST /reputation/explore
```

Deployment:

```bash
docker compose up --build
```

Optional production extras:

```bash
pip install "sentinelgraph[production]"
export SENTINELGRAPH_MODEL_CHECKPOINT_DIR=/data/checkpoints
export SENTINELGRAPH_REPUTATION_POSTGRES_DSN=postgresql://sentinelgraph:sentinelgraph@localhost:5433/sentinelgraph
export SENTINELGRAPH_GCS_BUCKET=my-security-artifacts
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
