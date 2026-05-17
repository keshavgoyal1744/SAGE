"""Compliance and evidence automation."""

from __future__ import annotations

from typing import Dict, List

from .graph import SecurityGraph
from .utils import stable_id


FRAMEWORK_MAP = {
    "access-control": [
        ("SOC2", "CC6.1"),
        ("ISO27001", "A.5.15"),
        ("PCI-DSS", "7.2"),
        ("HIPAA", "164.312(a)(1)"),
    ],
    "vulnerability-management": [
        ("SOC2", "CC7.1"),
        ("ISO27001", "A.8.8"),
        ("PCI-DSS", "6.3"),
        ("FedRAMP", "RA-5"),
    ],
    "change-management": [
        ("SOC2", "CC8.1"),
        ("ISO27001", "A.8.32"),
        ("PCI-DSS", "6.5"),
        ("FedRAMP", "CM-3"),
    ],
    "logging-monitoring": [
        ("SOC2", "CC7.2"),
        ("ISO27001", "A.8.15"),
        ("PCI-DSS", "10.4"),
        ("FedRAMP", "AU-6"),
    ],
}


class ComplianceEngine:
    def __init__(self, graph: SecurityGraph):
        self.graph = graph

    def evidence_for_finding(self, finding: Dict[str, object]) -> List[Dict[str, object]]:
        category = str(finding.get("category", "vulnerability-management"))
        mapped_category = "vulnerability-management"
        if "auth" in category or "access" in category:
            mapped_category = "access-control"
        elif "runtime" in category or "logging" in category:
            mapped_category = "logging-monitoring"
        elif "mr" in category or "change" in category:
            mapped_category = "change-management"
        evidence_items = []
        for framework, control_ref in FRAMEWORK_MAP[mapped_category]:
            payload = {
                "framework": framework,
                "control_ref": control_ref,
                "subject_id": str(finding["id"]),
                "status": "needs-remediation" if finding.get("status") == "open" else "resolved",
                "evidence": {
                    "title": finding.get("title"),
                    "severity": finding.get("severity"),
                    "category": finding.get("category"),
                    "repo": finding.get("repo"),
                    "file": finding.get("file"),
                },
            }
            evidence_id = stable_id("evidence", framework, control_ref, finding["id"])
            self.graph.store.insert_compliance_evidence(evidence_id, payload)
            entity = self.graph.entity(
                "compliance_evidence",
                f"{framework} {control_ref}: {finding.get('title')}",
                id=evidence_id,
                **payload,
            )
            self.graph.link(str(finding["id"]), entity.id, "evidenced_by")
            evidence_items.append({"id": evidence_id, **payload})
        return evidence_items
