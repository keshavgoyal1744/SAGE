"""Command line entry point."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from .demo import load_demo
from .factory import build_engines
from .models import MergeRequestInput
from .sarif import findings_to_sarif


def main() -> None:
    parser = argparse.ArgumentParser(prog="sentinelgraph")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("demo", help="Reset the local database and load demo data")

    analyze = sub.add_parser("analyze-mr", help="Analyze a merge request JSON file")
    analyze.add_argument("path")

    sarif = sub.add_parser("sarif", help="Export findings as SARIF")
    sarif.add_argument("--repo", default=None)

    sub.add_parser("dashboard", help="Print dashboard JSON")

    args = parser.parse_args()
    engines = build_engines()

    if args.command == "demo":
        print(json.dumps(load_demo(engines), indent=2))
    elif args.command == "analyze-mr":
        data = json.loads(Path(args.path).read_text())
        result = engines.risk.analyze_mr(MergeRequestInput(**data))
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


if __name__ == "__main__":
    main()
