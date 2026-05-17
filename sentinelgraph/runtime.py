"""Runtime feedback ingestion and correlation."""

from __future__ import annotations

from typing import Dict, List

from .graph import SecurityGraph
from .models import RuntimeEventInput
from .utils import stable_id


class RuntimeEngine:
    def __init__(self, graph: SecurityGraph):
        self.graph = graph

    def ingest(self, item: RuntimeEventInput) -> dict:
        event_entity = self.graph.entity(
            "runtime_event",
            item.event_id,
            id=stable_id("runtime_event", item.event_id),
            source=item.source,
            event_type=item.event_type,
            service=item.service,
            severity=item.severity,
            signal=item.signal,
            code_path=item.code_path,
            repo=item.repo,
            attributes=item.attributes,
        )
        service_entity = self.graph.upsert_service(item.repo or "unknown", item.service)
        self.graph.link(event_entity.id, service_entity.id, "observed_in")
        self.graph.store.insert_runtime_event(event_entity.id, item.model_dump())
        return {"event": event_entity.model_dump(), "correlations": self.correlate(item.repo, item.service, item.code_path)}

    def correlate(self, repo: str | None, service: str, code_path: str | None = None) -> List[Dict[str, object]]:
        events = self.graph.store.list_runtime_events(repo=repo, service=service)
        findings = self.graph.store.list_findings(repo=repo) if repo else self.graph.store.list_findings()
        correlations: List[Dict[str, object]] = []
        for finding in findings:
            if finding.get("service") == service:
                correlations.append(
                    {
                        "type": "finding-service",
                        "finding_id": finding["id"],
                        "reason": "Finding affects the same service as runtime events.",
                    }
                )
            if code_path and finding.get("file") and code_path in finding["file"]:
                correlations.append(
                    {
                        "type": "finding-code-path",
                        "finding_id": finding["id"],
                        "reason": "Finding overlaps the runtime code path.",
                    }
                )
        for event in events[:5]:
            correlations.append(
                {
                    "type": "runtime-history",
                    "event_id": event["id"],
                    "severity": event["severity"],
                    "signal": event["signal"],
                }
            )
        return correlations
