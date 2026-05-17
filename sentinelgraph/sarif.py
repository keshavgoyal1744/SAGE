"""SARIF export."""

from __future__ import annotations

from typing import Any, Dict, List


SARIF_LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}


def findings_to_sarif(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    rules: Dict[str, Dict[str, Any]] = {}
    results: List[Dict[str, Any]] = []
    for finding in findings:
        rule_id = finding.get("cwe") or finding.get("category") or "sentinelgraph.finding"
        rules[rule_id] = {
            "id": rule_id,
            "name": finding.get("category", "security-finding"),
            "shortDescription": {"text": finding.get("title", "Security finding")},
            "properties": {
                "severity": finding.get("severity"),
                "cve": finding.get("cve"),
                "ghsa": finding.get("ghsa"),
            },
        }
        location = {
            "physicalLocation": {
                "artifactLocation": {"uri": finding.get("file") or "unknown"},
                "region": {"startLine": int(finding.get("evidence", {}).get("line", 1))},
            }
        }
        results.append(
            {
                "ruleId": rule_id,
                "level": SARIF_LEVEL.get(str(finding.get("severity", "medium")).lower(), "warning"),
                "message": {"text": finding.get("title", "Security finding")},
                "locations": [location],
                "properties": {
                    "id": finding.get("id"),
                    "repo": finding.get("repo"),
                    "service": finding.get("service"),
                    "function": finding.get("function"),
                    "status": finding.get("status"),
                },
            }
        )
    return {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "SentinelGraph",
                        "informationUri": "https://example.local/sentinelgraph",
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
            }
        ],
    }
