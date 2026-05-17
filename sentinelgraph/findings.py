"""Finding creation and normalization."""

from __future__ import annotations

from typing import Any, Dict

from .graph import SecurityGraph
from .models import FindingInput
from .utils import stable_id


class FindingEngine:
    def __init__(self, graph: SecurityGraph):
        self.graph = graph

    def create(self, item: FindingInput) -> Dict[str, Any]:
        finding_id = stable_id(
            "finding",
            item.repo,
            item.category,
            item.file or item.service or "",
            item.function or "",
            item.title,
        )
        payload = item.model_dump()
        payload["id"] = finding_id
        payload["status"] = payload.get("status", "open")
        self.graph.store.insert_finding(finding_id, payload)
        entity_payload = {key: value for key, value in payload.items() if key != "id"}
        finding_entity = self.graph.entity(
            "finding",
            item.title,
            id=finding_id,
            **entity_payload,
        )
        repo_entity = self.graph.upsert_repo(item.repo)
        self.graph.link(repo_entity.id, finding_entity.id, "has_finding")
        if item.service:
            service = self.graph.upsert_service(item.repo, item.service)
            self.graph.link(finding_entity.id, service.id, "affects")
        if item.mr_id:
            mr = self.graph.entity(
                "merge_request",
                item.mr_id,
                id=stable_id("merge_request", item.repo, item.mr_id),
                mr_id=item.mr_id,
            )
            self.graph.link(finding_entity.id, mr.id, "introduced_by")
        if item.cve:
            cve = self.graph.entity("cve", item.cve, id=stable_id("cve", item.cve), cve=item.cve)
            self.graph.link(finding_entity.id, cve.id, "maps_to")
        if item.ghsa:
            advisory = self.graph.entity("cve", item.ghsa, id=stable_id("advisory", item.ghsa), ghsa=item.ghsa)
            self.graph.link(finding_entity.id, advisory.id, "maps_to")
        return payload
