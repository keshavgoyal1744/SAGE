"""Incident analysis and autonomous regression hunt."""

from __future__ import annotations

from typing import Dict, List

from .compliance import ComplianceEngine
from .controls import ControlEngine
from .findings import FindingEngine
from .graph import SecurityGraph
from .models import FindingInput, HuntResult, IncidentInput
from .utils import stable_id


class IncidentEngine:
    def __init__(
        self,
        graph: SecurityGraph,
        controls: ControlEngine,
        findings: FindingEngine,
        compliance: ComplianceEngine,
    ):
        self.graph = graph
        self.controls = controls
        self.findings = findings
        self.compliance = compliance

    def create_incident(self, item: IncidentInput) -> Dict[str, object]:
        incident_entity = self.graph.entity(
            "incident",
            item.title,
            id=stable_id("incident", item.incident_id),
            incident_id=item.incident_id,
            repo=item.repo,
            service=item.service,
            severity=item.severity,
            signal=item.signal,
            code_path=item.code_path,
            customer_impact=item.customer_impact,
            runtime_event_ids=item.runtime_event_ids,
            metadata=item.metadata,
        )
        repo_entity = self.graph.upsert_repo(item.repo)
        service_entity = self.graph.upsert_service(item.repo, item.service)
        self.graph.link(repo_entity.id, incident_entity.id, "has_incident")
        self.graph.link(incident_entity.id, service_entity.id, "impacts")
        for runtime_id in item.runtime_event_ids:
            self.graph.link(incident_entity.id, runtime_id, "supported_by_runtime_signal")

        hunt = self.hunt(item)
        report = {
            "id": incident_entity.id,
            "repo": item.repo,
            "service": item.service,
            "title": item.title,
            "severity": item.severity,
            "signal": item.signal,
            "code_path": item.code_path,
            "customer_impact": item.customer_impact,
            "runtime_event_ids": item.runtime_event_ids,
            "root_cause_candidates": self.root_cause_candidates(item),
            "scanner_coverage_gap": hunt.scanner_gaps,
            "hunt": hunt.model_dump(),
            "evidence_summary": "Incident updated the security graph, generated sibling findings, test ideas, fix patterns, and compliance evidence.",
        }
        self.graph.store.insert_incident(incident_entity.id, report)
        return report

    def root_cause_candidates(self, item: IncidentInput) -> List[Dict[str, object]]:
        candidates: List[Dict[str, object]] = []
        analyses = self.graph.store.list_analyses(item.repo)
        for analysis in analyses:
            payload = analysis["payload"]
            passport = payload.get("passport", {})
            services = [svc.get("name") for svc in passport.get("services", [])]
            if item.service in services or (item.code_path and item.code_path in str(payload)):
                candidates.append(
                    {
                        "subject_id": analysis["subject_id"],
                        "score": analysis["score"],
                        "level": analysis["level"],
                        "reason": "Prior change touched the impacted service or code path.",
                    }
                )
        return sorted(candidates, key=lambda row: row["score"], reverse=True)[:5]

    def hunt(self, item: IncidentInput) -> HuntResult:
        category = self._category_from_signal(item.signal)
        siblings: List[Dict[str, object]] = []
        patches: List[Dict[str, object]] = []
        tests: List[Dict[str, object]] = []

        services = self.graph.store.list_entities("service")
        for service in services:
            if service.name == item.service:
                continue
            attrs = service.attributes
            service_text = f"{service.name} {attrs}".lower()
            if self._is_related_service(category, service_text):
                finding = self.findings.create(
                    FindingInput(
                        title=f"Potential sibling {category} issue in {service.name}",
                        repo=item.repo,
                        service=service.name,
                        category=category,
                        severity="high" if item.severity in {"high", "critical"} else "medium",
                        file=attrs.get("file_prefix"),
                        evidence={
                            "source_incident": item.incident_id,
                            "reason": "Service shares a sensitive pattern with the incident signal.",
                        },
                    )
                )
                self.compliance.evidence_for_finding(finding)
                siblings.append(finding)
                patches.append(
                    {
                        "service": service.name,
                        "pattern": self._fix_pattern(category),
                        "status": "proposed",
                    }
                )
                tests.append(
                    {
                        "service": service.name,
                        "test": self._test_pattern(category),
                        "status": "proposed",
                    }
                )

        scanner_gaps = self._scanner_gaps(item.repo, category)
        return HuntResult(
            incident_id=stable_id("incident", item.incident_id),
            siblings_found=len(siblings),
            findings=siblings,
            patches=patches,
            tests=tests,
            scanner_gaps=scanner_gaps,
        )

    def _scanner_gaps(self, repo: str, category: str) -> List[Dict[str, object]]:
        context = self.controls.latest_context(repo)
        gaps = []
        for weak in context.get("weak_controls", []):
            blind_spots = weak.get("blind_spots", [])
            if category in blind_spots or any(part in str(blind_spots).lower() for part in category.split("-")):
                gaps.append(
                    {
                        "control_id": weak.get("control_id"),
                        "score": weak.get("score"),
                        "category": category,
                        "reason": "A real incident maps to a known control blind spot.",
                    }
                )
        if not gaps:
            gaps.append(
                {
                    "control_id": "coverage-review",
                    "category": category,
                    "reason": "No explicit matching control gap found; validate whether current controls would catch this incident.",
                }
            )
        return gaps

    def _category_from_signal(self, signal: str) -> str:
        text = signal.lower()
        if "auth" in text or "token" in text or "session" in text:
            return "auth-bypass"
        if "ssrf" in text or "metadata" in text:
            return "ssrf"
        if "secret" in text or "credential" in text:
            return "secret-exposure"
        if "sql" in text or "query" in text:
            return "sql-injection"
        if "dependency" in text or "package" in text:
            return "supply-chain"
        return "runtime-security-regression"

    def _is_related_service(self, category: str, service_text: str) -> bool:
        if category == "auth-bypass":
            return any(term in service_text for term in ["gateway", "identity", "auth", "session"])
        if category == "ssrf":
            return any(term in service_text for term in ["webhook", "fetch", "integration", "proxy"])
        return True

    def _fix_pattern(self, category: str) -> str:
        patterns = {
            "auth-bypass": "Restore issuer, audience, expiration, and role validation at every boundary.",
            "ssrf": "Require outbound allowlists, block metadata IP ranges, and validate URL schemes.",
            "secret-exposure": "Rotate exposed credentials and add token-shape tests to control validation.",
            "sql-injection": "Replace string concatenation with parameterized queries.",
            "supply-chain": "Pin dependency, require provenance, and verify advisory status.",
        }
        return patterns.get(category, "Add regression guard and verify deployment exposure.")

    def _test_pattern(self, category: str) -> str:
        patterns = {
            "auth-bypass": "Negative tests for forged token, missing audience, expired token, and wrong role.",
            "ssrf": "Tests for cloud metadata endpoint, internal IP, file scheme, and redirect chains.",
            "secret-exposure": "Synthetic token payloads for every accepted credential format.",
            "sql-injection": "Injection payload tests across query parameters and request bodies.",
            "supply-chain": "Policy tests for unsigned packages, missing provenance, and ownership change.",
        }
        return patterns.get(category, "Regression test proving the incident condition cannot recur.")
