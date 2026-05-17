"""Incident replay timeline."""

from __future__ import annotations

from typing import List

from .graph import SecurityGraph
from .models import ReplayEvent


class ReplayEngine:
    def __init__(self, graph: SecurityGraph):
        self.graph = graph

    def build(self, incident_id: str) -> List[ReplayEvent]:
        incident = self.graph.store.get_incident(incident_id)
        if not incident:
            return []
        report = incident["report"]
        events: List[ReplayEvent] = [
            ReplayEvent(
                timestamp=incident["created_at"],
                type="incident",
                title=incident["title"],
                entity_id=incident_id,
                details=report,
            )
        ]
        for runtime_id in report.get("runtime_event_ids", []):
            entity = self.graph.store.get_entity(runtime_id)
            if entity:
                events.append(
                    ReplayEvent(
                        timestamp=entity.attributes.get("created_at", incident["created_at"]),
                        type="runtime_event",
                        title=entity.name,
                        entity_id=entity.id,
                        details=entity.attributes,
                    )
                )
        for finding in report.get("hunt", {}).get("findings", []):
            events.append(
                ReplayEvent(
                    timestamp=incident["created_at"],
                    type="finding",
                    title=finding.get("title", "Related finding"),
                    entity_id=finding.get("id", "unknown"),
                    details=finding,
                )
            )
        return sorted(events, key=lambda event: event.timestamp)
