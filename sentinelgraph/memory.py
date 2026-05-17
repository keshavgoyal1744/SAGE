"""Organizational security memory checks."""

from __future__ import annotations

from typing import Dict, List

from .graph import SecurityGraph
from .models import DecisionInput, Entity, MergeRequestInput
from .utils import stable_id


SECURITY_KEYWORDS = {
    "auth": ["auth", "jwt", "token", "session", "permission", "role", "gateway"],
    "crypto": ["crypto", "hash", "bcrypt", "md5", "sha1", "certificate", "key"],
    "validation": ["validate", "validation", "sanitize", "schema", "bounds", "input"],
    "data": ["sql", "query", "orm", "database", "migration"],
    "runtime": ["kubernetes", "deployment", "ingress", "route", "waf"],
}


class MemoryEngine:
    def __init__(self, graph: SecurityGraph):
        self.graph = graph

    def add_decision(self, item: DecisionInput) -> Entity:
        repo_entity = self.graph.upsert_repo(item.repo)
        entity = self.graph.entity(
            "decision",
            item.title,
            id=stable_id("decision", item.repo, item.decision_id),
            decision_id=item.decision_id,
            text=item.text,
            governs=item.governs,
            security_relevant=item.security_relevant,
            status=item.status,
            tags=item.tags,
            evidence=item.evidence,
        )
        self.graph.link(repo_entity.id, entity.id, "records")
        for governed in item.governs:
            if "/" in governed:
                service = self.graph.service_from_file(item.repo, governed)
                self.graph.link(entity.id, service.id, "governs", path=governed)
        return entity

    def find_relevant_decisions(self, mr: MergeRequestInput) -> List[Entity]:
        decisions = self.graph.store.list_entities("decision")
        changed = " ".join(mr.files_changed).lower()
        text = f"{mr.title} {mr.description} {mr.diff_summary} {changed}".lower()
        result: List[Entity] = []
        for decision in decisions:
            attrs = decision.attributes
            if attrs.get("status") != "active":
                continue
            governs = " ".join(attrs.get("governs", [])).lower()
            tags = " ".join(attrs.get("tags", [])).lower()
            decision_text = f"{decision.name} {attrs.get('text', '')} {governs} {tags}".lower()
            if any(path.lower() in changed for path in attrs.get("governs", [])):
                result.append(decision)
                continue
            if any(word in text and word in decision_text for word in self._keywords(text)):
                result.append(decision)
        return result

    def detect_conflicts(self, mr: MergeRequestInput, decisions: List[Entity]) -> List[Dict[str, object]]:
        text = f"{mr.title} {mr.description} {mr.diff_summary}".lower()
        conflicts: List[Dict[str, object]] = []
        removal_words = ["remove", "removed", "skip", "bypass", "disable", "relax", "temporary"]
        for decision in decisions:
            decision_text = f"{decision.name} {decision.attributes.get('text', '')}".lower()
            tags = decision.attributes.get("tags", [])
            if any(word in text for word in removal_words) and any(tag in text or tag in decision_text for tag in tags):
                conflicts.append(
                    {
                        "decision_id": decision.id,
                        "title": decision.name,
                        "reason": "Change appears to weaken or bypass an active security decision.",
                    }
                )
            if "auth" in text and "validate" in decision_text and ("remove" in text or "simplif" in text):
                conflicts.append(
                    {
                        "decision_id": decision.id,
                        "title": decision.name,
                        "reason": "Authentication validation is being changed near a protected boundary.",
                    }
                )
        return conflicts

    def _keywords(self, text: str) -> List[str]:
        result: List[str] = []
        for words in SECURITY_KEYWORDS.values():
            result.extend(word for word in words if word in text)
        return result
