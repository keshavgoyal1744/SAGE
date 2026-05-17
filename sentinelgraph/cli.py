"""Command line entry point."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .demo import load_demo
from .factory import build_engines
from .models import (
    CiOptimizeRequest,
    FixtureImportRequest,
    MemoryAskRequest,
    MemorySyncRequest,
    MergeRequestInput,
    PolicyAuditRequest,
    RegressionRequest,
    ReputationFeedbackInput,
    ScannerChaosRequest,
    SourceImportRequest,
)
from .sarif import findings_to_sarif
from .source_control import HistoryImporter, ProviderError


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

    audit = sub.add_parser("policy-audit", help="Audit repository security policy settings")
    audit.add_argument("--provider", default="fixture", choices=["fixture", "gitlab", "github"])
    audit.add_argument("--repo", required=True)
    audit.add_argument("--execute", action="store_true")

    regression = sub.add_parser("regression", help="Investigate root cause and generate remediation/test PR plan")
    regression.add_argument("--provider", default="fixture", choices=["fixture", "gitlab", "github"])
    regression.add_argument("--repo", required=True)
    regression.add_argument("--incident-id", default=None)
    regression.add_argument("--finding-id", default=None)
    regression.add_argument("--execute", action="store_true")

    ci = sub.add_parser("optimize-ci", help="Create optimized CI workflow plan")
    ci.add_argument("--provider", default="fixture", choices=["fixture", "gitlab", "github"])
    ci.add_argument("--repo", required=True)
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

    rep_score = sub.add_parser("reputation-score", help="Score MR JSON with adaptive model")
    rep_score.add_argument("path")

    rep_feedback = sub.add_parser("reputation-feedback", help="Train adaptive model from outcome")
    rep_feedback.add_argument("--repo", required=True)
    rep_feedback.add_argument("--mr-id", required=True)
    rep_feedback.add_argument("--outcome", required=True, choices=["merged", "closed", "abandoned"])

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
            ScannerChaosRequest(provider=args.provider, repo=args.repo, dry_run=not args.execute)
        )
        print(json.dumps(result, indent=2))
    elif args.command == "policy-audit":
        result = engines.policy_audit.audit(
            PolicyAuditRequest(provider=args.provider, repo=args.repo, dry_run=not args.execute)
        )
        print(json.dumps(result, indent=2))
    elif args.command == "regression":
        result = engines.regression.investigate(
            RegressionRequest(
                provider=args.provider,
                repo=args.repo,
                incident_id=args.incident_id,
                finding_id=args.finding_id,
                dry_run=not args.execute,
            )
        )
        print(json.dumps(result, indent=2))
    elif args.command == "optimize-ci":
        result = engines.ci_optimizer.optimize(
            CiOptimizeRequest(provider=args.provider, repo=args.repo, dry_run=not args.execute)
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
            MemorySyncRequest(provider=args.provider, repo=args.repo, dry_run=not args.execute)
        )
        print(json.dumps(result, indent=2))
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


if __name__ == "__main__":
    main()
