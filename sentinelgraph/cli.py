"""Command line entry point."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .demo import load_demo
from .factory import build_engines
from .models import (
    AdvisoryEnrichmentRequest,
    AgentExploreRequest,
    CiOptimizeRequest,
    CiWaitRequest,
    ExploitabilitySimulationRequest,
    FullSecurityAuditRequest,
    FixtureImportRequest,
    MemoryAskRequest,
    MemorySyncRequest,
    MergeRequestInput,
    OrgConfigInput,
    PolicyAuditRequest,
    RegressionRequest,
    ReputationFeedbackInput,
    RemediationVerificationRequest,
    ScannerChaosRequest,
    ScanArtifactParseRequest,
    SecurityDebateRequest,
    SourceImportRequest,
    SlashCommandRequest,
    VulnerabilityTriageRequest,
)
from .commands import dispatch_slash_command
from .production import OrgRegistry
from .sarif import findings_to_sarif
from .scan_reports import parse_security_artifacts
from .source_control import HistoryImporter, ProviderError
from .provider_ops import ProviderOps


def main() -> None:
    parser = argparse.ArgumentParser(prog="sentinelgraph")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("demo", help="Reset the local database and load demo data")

    analyze = sub.add_parser("analyze-mr", help="Analyze a merge request JSON file")
    analyze.add_argument("path")

    import_history = sub.add_parser("import-history", help="Import real merge request history from a provider")
    import_history.add_argument("--provider", required=True, choices=["gitlab", "github"])
    import_history.add_argument("--repo", required=True, help="Project path such as group/project or owner/repo")
    import_history.add_argument("--token", default=None)
    import_history.add_argument("--token-env", default=None)
    import_history.add_argument("--base-url", default=None)
    import_history.add_argument("--limit", type=int, default=100)
    import_history.add_argument("--open-only", action="store_true")
    import_history.add_argument("--no-decisions", action="store_true")
    import_history.add_argument("--no-analysis", action="store_true")

    import_fixture = sub.add_parser("import-fixture", help="Import normalized source-control history from a JSON fixture")
    import_fixture.add_argument("path")
    import_fixture.add_argument("--no-decisions", action="store_true")
    import_fixture.add_argument("--no-analysis", action="store_true")

    sarif = sub.add_parser("sarif", help="Export findings as SARIF")
    sarif.add_argument("--repo", default=None)

    sub.add_parser("dashboard", help="Print dashboard JSON")

    scanner = sub.add_parser("scanner-chaos", help="Plan or run scanner validation payload workflow")
    scanner.add_argument("--provider", default="fixture", choices=["fixture", "gitlab", "github"])
    scanner.add_argument("--repo", required=True)
    scanner.add_argument("--execute", action="store_true")
    scanner.add_argument("--wait-for-ci", action="store_true")
    scanner.add_argument("--timeout", type=int, default=900)
    scanner.add_argument("--poll", type=int, default=15)
    scanner.add_argument("--cleanup-branch", action="store_true")
    scanner.add_argument("--allow-merge", action="store_true")
    scanner.add_argument("--trigger-change-id", default=None)
    scanner.add_argument("--trigger-issue-id", default=None)

    audit = sub.add_parser("policy-audit", help="Audit repository security policy settings")
    audit.add_argument("--provider", default="fixture", choices=["fixture", "gitlab", "github"])
    audit.add_argument("--repo", required=True)
    audit.add_argument("--default-branch", default="main")
    audit.add_argument("--execute", action="store_true")
    audit.add_argument("--trigger-change-id", default=None)
    audit.add_argument("--trigger-issue-id", default=None)

    full_audit = sub.add_parser("full-audit", help="Run policy, scanner validation, triage, and verification workflows")
    full_audit.add_argument("--provider", default="fixture", choices=["fixture", "gitlab", "github"])
    full_audit.add_argument("--repo", required=True)
    full_audit.add_argument("--default-branch", default="main")
    full_audit.add_argument("--execute", action="store_true")
    full_audit.add_argument("--wait-for-ci", action="store_true")
    full_audit.add_argument("--cleanup-scanner-branch", action="store_true")
    full_audit.add_argument("--trigger-change-id", default=None)
    full_audit.add_argument("--trigger-issue-id", default=None)

    triage = sub.add_parser("triage-vulnerabilities", help="Triage provider security findings and create owner issues")
    triage.add_argument("--provider", default="fixture", choices=["fixture", "gitlab", "github"])
    triage.add_argument("--repo", required=True)
    triage.add_argument("--default-branch", default="main")
    triage.add_argument("--max-findings", type=int, default=100)
    triage.add_argument("--execute", action="store_true")
    triage.add_argument("--trigger-change-id", default=None)
    triage.add_argument("--trigger-issue-id", default=None)

    verify = sub.add_parser("verify-remediation", help="Verify and close tracked security remediation issues")
    verify.add_argument("--provider", default="fixture", choices=["fixture", "gitlab", "github"])
    verify.add_argument("--repo", required=True)
    verify.add_argument("--default-branch", default="main")
    verify.add_argument("--max-issues", type=int, default=50)
    verify.add_argument("--execute", action="store_true")
    verify.add_argument("--trigger-change-id", default=None)
    verify.add_argument("--trigger-issue-id", default=None)

    wait_ci = sub.add_parser("wait-ci", help="Wait for provider CI and parse security artifacts")
    wait_ci.add_argument("--provider", default="fixture", choices=["fixture", "gitlab", "github"])
    wait_ci.add_argument("--repo", required=True)
    wait_ci.add_argument("--ref", default="main")
    wait_ci.add_argument("--timeout", type=int, default=900)
    wait_ci.add_argument("--poll", type=int, default=15)
    wait_ci.add_argument("--execute", action="store_true")

    parse_artifacts = sub.add_parser("parse-artifacts", help="Parse local JSON/SARIF security report artifacts")
    parse_artifacts.add_argument("paths", nargs="+")

    exploit = sub.add_parser("simulate-exploitability", help="Simulate attack reachability for a finding")
    exploit.add_argument("--repo", required=True)
    exploit.add_argument("--finding-id", default=None)
    exploit.add_argument("--title", default="Security finding")
    exploit.add_argument("--category", default="security")
    exploit.add_argument("--severity", default="medium")
    exploit.add_argument("--file", default=None)
    exploit.add_argument("--service", default=None)
    exploit.add_argument("--cve", default=None)
    exploit.add_argument("--ghsa", default=None)
    exploit.add_argument("--require-runtime-evidence", action="store_true")

    ai_gov = sub.add_parser("ai-governance", help="Analyze AI coding risk for an MR JSON file")
    ai_gov.add_argument("path")

    debate = sub.add_parser("security-debate", help="Run multi-perspective security debate for a subject")
    debate.add_argument("--repo", required=True)
    debate.add_argument("--subject-id", default=None)
    debate.add_argument("--subject-type", default="merge_request")
    debate.add_argument("--prompt", default="Assess security risk and required evidence.")

    regression = sub.add_parser("regression", help="Investigate root cause and generate remediation/test PR plan")
    regression.add_argument("--provider", default="fixture", choices=["fixture", "gitlab", "github"])
    regression.add_argument("--repo", required=True)
    regression.add_argument("--incident-id", default=None)
    regression.add_argument("--finding-id", default=None)
    regression.add_argument("--affected-file", default=None)
    regression.add_argument("--default-branch", default="main")
    regression.add_argument("--execute", action="store_true")

    ci = sub.add_parser("optimize-ci", help="Create optimized CI workflow plan")
    ci.add_argument("--provider", default="fixture", choices=["fixture", "gitlab", "github"])
    ci.add_argument("--repo", required=True)
    ci.add_argument("--default-branch", default="main")
    ci.add_argument("--execute", action="store_true")

    ask = sub.add_parser("ask", help="Ask security memory")
    ask.add_argument("question")
    ask.add_argument("--repo", default=None)

    sub.add_parser("validate-memory", help="Validate security memory")
    sub.add_parser("memory-dashboard-html", help="Print memory dashboard HTML")

    sync = sub.add_parser("sync-memory", help="Plan or run memory sync")
    sync.add_argument("--provider", default="fixture", choices=["fixture", "gitlab", "github"])
    sync.add_argument("--repo", required=True)
    sync.add_argument("--execute", action="store_true")
    sync.add_argument("--external-target", default="repo", choices=["repo", "wiki", "both"])

    advisory = sub.add_parser("advisory-enrich", help="Enrich a package or CVE/GHSA with OSV/NVD intelligence")
    advisory.add_argument("--ecosystem", default=None)
    advisory.add_argument("--package", default=None)
    advisory.add_argument("--version", default=None)
    advisory.add_argument("--purl", default=None)
    advisory.add_argument("--cve", default=None)
    advisory.add_argument("--ghsa", default=None)
    advisory.add_argument("--no-nvd", action="store_true")

    slash = sub.add_parser("slash-command", help="Run a SentinelGraph slash-command locally")
    slash.add_argument("--provider", default="fixture", choices=["fixture", "gitlab", "github"])
    slash.add_argument("--repo", required=True)
    slash.add_argument("--execute", action="store_true")
    slash.add_argument("--actor", default="local")
    slash.add_argument("command", nargs=argparse.REMAINDER)

    rep_score = sub.add_parser("reputation-score", help="Score MR JSON with adaptive model")
    rep_score.add_argument("path")

    rep_feedback = sub.add_parser("reputation-feedback", help="Train adaptive model from outcome")
    rep_feedback.add_argument("--repo", required=True)
    rep_feedback.add_argument("--mr-id", required=True)
    rep_feedback.add_argument("--outcome", required=True, choices=["merged", "closed", "abandoned"])

    enforce = sub.add_parser("enforce-patterns", help="Evaluate an MR JSON file against learned review rules")
    enforce.add_argument("path")

    ide = sub.add_parser("ide-agent", help="Build IDE agent context for an MR JSON file")
    ide.add_argument("path")

    explore = sub.add_parser("agent-explore", help="Run heuristic deep code exploration")
    explore.add_argument("--provider", default="fixture", choices=["fixture", "gitlab", "github"])
    explore.add_argument("--repo", required=True)
    explore.add_argument("--file-path", default=None)
    explore.add_argument("--question", default="Find security-sensitive code paths and likely regression risks.")
    explore.add_argument("--execute", action="store_true")

    org = sub.add_parser("org-config", help="Register an org/repo auth profile")
    org.add_argument("--org-id", required=True)
    org.add_argument("--provider", required=True, choices=["gitlab", "github"])
    org.add_argument("--repo", action="append", default=[])
    org.add_argument("--token-env", default=None)
    org.add_argument("--base-url", default=None)
    org.add_argument("--default-branch", default="main")

    args = parser.parse_args()
    engines = build_engines()
    importer = HistoryImporter(engines)

    if args.command == "demo":
        print(json.dumps(load_demo(engines), indent=2))
    elif args.command == "analyze-mr":
        data = json.loads(Path(args.path).read_text())
        result = engines.risk.analyze_mr(MergeRequestInput(**data))
        print(json.dumps(result.model_dump(), indent=2))
    elif args.command == "import-history":
        try:
            result = importer.import_from_request(
                SourceImportRequest(
                    provider=args.provider,
                    repo=args.repo,
                    token=args.token,
                    token_env=args.token_env,
                    base_url=args.base_url,
                    limit=args.limit,
                    include_closed=not args.open_only,
                    import_decisions=not args.no_decisions,
                    analyze=not args.no_analysis,
                )
            )
        except ProviderError as exc:
            print(json.dumps({"error": str(exc)}, indent=2), file=sys.stderr)
            raise SystemExit(2)
        except Exception as exc:
            print(json.dumps({"error": f"Provider import failed: {exc}"}, indent=2), file=sys.stderr)
            raise SystemExit(1)
        print(json.dumps(result.model_dump(), indent=2))
    elif args.command == "import-fixture":
        data = json.loads(Path(args.path).read_text())
        if isinstance(data, dict) and "records" in data:
            payload = FixtureImportRequest(**data)
        else:
            payload = FixtureImportRequest(records=data)
        result = importer.import_records(
            payload.records,
            import_decisions=not args.no_decisions and payload.import_decisions,
            analyze=not args.no_analysis and payload.analyze,
        )
        print(json.dumps(result.model_dump(), indent=2))
    elif args.command == "sarif":
        print(json.dumps(findings_to_sarif(engines.store.list_findings(args.repo)), indent=2))
    elif args.command == "dashboard":
        print(
            json.dumps(
                {
                    "counts": engines.store.counts(),
                    "findings": engines.store.list_findings()[:10],
                    "analyses": engines.store.list_analyses()[:10],
                    "incidents": engines.store.list_incidents()[:10],
                    "compliance_evidence": engines.store.list_compliance_evidence()[:10],
                },
                indent=2,
            )
        )
    elif args.command == "scanner-chaos":
        result = engines.scanner_chaos.run(
            ScannerChaosRequest(
                provider=args.provider,
                repo=args.repo,
                dry_run=not args.execute,
                wait_for_ci=args.wait_for_ci,
                timeout_seconds=args.timeout,
                poll_seconds=args.poll,
                cleanup_branch=args.cleanup_branch,
                block_merge=not args.allow_merge,
                trigger_change_id=args.trigger_change_id,
                trigger_issue_id=args.trigger_issue_id,
            )
        )
        print(json.dumps(result, indent=2))
    elif args.command == "policy-audit":
        result = engines.policy_audit.audit(
            PolicyAuditRequest(
                provider=args.provider,
                repo=args.repo,
                default_branch=args.default_branch,
                dry_run=not args.execute,
                trigger_change_id=args.trigger_change_id,
                trigger_issue_id=args.trigger_issue_id,
            )
        )
        print(json.dumps(result, indent=2))
    elif args.command == "full-audit":
        result = engines.full_security_audit.run(
            FullSecurityAuditRequest(
                provider=args.provider,
                repo=args.repo,
                default_branch=args.default_branch,
                dry_run=not args.execute,
                wait_for_ci=args.wait_for_ci,
                cleanup_scanner_branch=args.cleanup_scanner_branch,
                trigger_change_id=args.trigger_change_id,
                trigger_issue_id=args.trigger_issue_id,
            )
        )
        print(json.dumps(result, indent=2))
    elif args.command == "triage-vulnerabilities":
        result = engines.vulnerability_triage.run(
            VulnerabilityTriageRequest(
                provider=args.provider,
                repo=args.repo,
                default_branch=args.default_branch,
                max_findings=args.max_findings,
                dry_run=not args.execute,
                trigger_change_id=args.trigger_change_id,
                trigger_issue_id=args.trigger_issue_id,
            )
        )
        print(json.dumps(result, indent=2))
    elif args.command == "verify-remediation":
        result = engines.remediation_verification.run(
            RemediationVerificationRequest(
                provider=args.provider,
                repo=args.repo,
                default_branch=args.default_branch,
                max_issues=args.max_issues,
                dry_run=not args.execute,
                trigger_change_id=args.trigger_change_id,
                trigger_issue_id=args.trigger_issue_id,
            )
        )
        print(json.dumps(result, indent=2))
    elif args.command == "wait-ci":
        request = CiWaitRequest(
            provider=args.provider,
            repo=args.repo,
            ref=args.ref,
            timeout_seconds=args.timeout,
            poll_seconds=args.poll,
            dry_run=not args.execute,
        )
        ops = ProviderOps(request)
        ci = ops.wait_for_ci(request.ref, request.timeout_seconds, request.poll_seconds)
        artifacts = ops.download_ci_artifacts(ci)
        print(json.dumps({"ci": ci, "artifact_count": len(artifacts), "findings": parse_security_artifacts(artifacts)}, indent=2))
    elif args.command == "parse-artifacts":
        artifacts = {path: Path(path).read_bytes() for path in args.paths}
        print(json.dumps({"findings": parse_security_artifacts(artifacts)}, indent=2))
    elif args.command == "simulate-exploitability":
        print(
            json.dumps(
                engines.exploitability.simulate(
                    ExploitabilitySimulationRequest(
                        repo=args.repo,
                        finding_id=args.finding_id,
                        title=args.title,
                        category=args.category,
                        severity=args.severity,
                        file=args.file,
                        service=args.service,
                        cve=args.cve,
                        ghsa=args.ghsa,
                        require_runtime_evidence=args.require_runtime_evidence,
                    )
                ),
                indent=2,
            )
        )
    elif args.command == "ai-governance":
        data = json.loads(Path(args.path).read_text())
        print(json.dumps(engines.ai_governance.analyze(MergeRequestInput(**data)), indent=2))
    elif args.command == "security-debate":
        print(
            json.dumps(
                engines.security_debate.debate(
                    SecurityDebateRequest(
                        repo=args.repo,
                        subject_id=args.subject_id,
                        subject_type=args.subject_type,
                        prompt=args.prompt,
                    )
                ),
                indent=2,
            )
        )
    elif args.command == "regression":
        result = engines.regression.investigate(
            RegressionRequest(
                provider=args.provider,
                repo=args.repo,
                incident_id=args.incident_id,
                finding_id=args.finding_id,
                affected_file=args.affected_file,
                default_branch=args.default_branch,
                dry_run=not args.execute,
            )
        )
        print(json.dumps(result, indent=2))
    elif args.command == "optimize-ci":
        result = engines.ci_optimizer.optimize(
            CiOptimizeRequest(provider=args.provider, repo=args.repo, default_branch=args.default_branch, dry_run=not args.execute)
        )
        print(json.dumps(result, indent=2))
    elif args.command == "ask":
        print(json.dumps(engines.memory_suite.ask(MemoryAskRequest(question=args.question, repo=args.repo)), indent=2))
    elif args.command == "validate-memory":
        print(json.dumps(engines.memory_suite.validate(), indent=2))
    elif args.command == "memory-dashboard-html":
        print(engines.memory_suite.dashboard_html())
    elif args.command == "sync-memory":
        result = engines.memory_suite.sync(
            MemorySyncRequest(provider=args.provider, repo=args.repo, dry_run=not args.execute, external_target=args.external_target)
        )
        print(json.dumps(result, indent=2))
    elif args.command == "advisory-enrich":
        print(
            json.dumps(
                engines.advisory.enrich(
                    AdvisoryEnrichmentRequest(
                        ecosystem=args.ecosystem,
                        package=args.package,
                        version=args.version,
                        purl=args.purl,
                        cve=args.cve,
                        ghsa=args.ghsa,
                        include_nvd=not args.no_nvd,
                    )
                ),
                indent=2,
            )
        )
    elif args.command == "slash-command":
        command = " ".join(args.command).strip()
        print(
            json.dumps(
                dispatch_slash_command(
                    engines,
                    SlashCommandRequest(
                        provider=args.provider,
                        repo=args.repo,
                        dry_run=not args.execute,
                        actor=args.actor,
                        command=command,
                    ),
                ),
                indent=2,
            )
        )
    elif args.command == "reputation-score":
        data = json.loads(Path(args.path).read_text())
        print(json.dumps(engines.reputation.score_mr(MergeRequestInput(**data)), indent=2))
    elif args.command == "reputation-feedback":
        print(
            json.dumps(
                engines.reputation.feedback(
                    ReputationFeedbackInput(repo=args.repo, mr_id=args.mr_id, outcome=args.outcome)
                ),
                indent=2,
            )
        )
    elif args.command == "enforce-patterns":
        data = json.loads(Path(args.path).read_text())
        print(json.dumps(engines.memory_suite.enforce_patterns(MergeRequestInput(**data)), indent=2))
    elif args.command == "ide-agent":
        data = json.loads(Path(args.path).read_text())
        print(json.dumps(engines.reputation.ide_agent_context(MergeRequestInput(**data)), indent=2))
    elif args.command == "agent-explore":
        print(
            json.dumps(
                engines.reputation.agent_explore(
                    AgentExploreRequest(
                        provider=args.provider,
                        repo=args.repo,
                        file_path=args.file_path,
                        question=args.question,
                        dry_run=not args.execute,
                    )
                ),
                indent=2,
            )
        )
    elif args.command == "org-config":
        registry = OrgRegistry(engines.store)
        print(
            json.dumps(
                registry.upsert(
                    OrgConfigInput(
                        org_id=args.org_id,
                        provider=args.provider,
                        repos=args.repo,
                        token_env=args.token_env,
                        base_url=args.base_url,
                        default_branch=args.default_branch,
                    )
                ),
                indent=2,
            )
        )


if __name__ == "__main__":
    main()
