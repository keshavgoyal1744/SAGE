"""Supply-chain trust intelligence."""

from __future__ import annotations

from typing import Dict, List

from .graph import SecurityGraph
from .models import PackageInput
from .utils import clamp, stable_id


class SupplyChainEngine:
    def __init__(self, graph: SecurityGraph):
        self.graph = graph

    def analyze(self, item: PackageInput) -> Dict[str, object]:
        reasons: List[Dict[str, object]] = []
        score = 0.0
        if item.ownership_changed:
            score += 22
            reasons.append({"code": "ownership-change", "message": "Package ownership changed recently."})
        if item.new_maintainer:
            score += 14
            reasons.append({"code": "new-maintainer", "message": "Release includes a new maintainer."})
        if not item.signed:
            score += 10
            reasons.append({"code": "unsigned", "message": "Release is not signed."})
        if not item.provenance:
            score += 14
            reasons.append({"code": "missing-provenance", "message": "Build provenance is missing."})
        if item.typo_similarity_to:
            score += 28
            reasons.append({"code": "typo-similarity", "message": f"Name resembles {item.typo_similarity_to}."})
        if item.days_since_last_release is not None and item.days_since_last_release > 730:
            score += 12
            reasons.append({"code": "abandoned", "message": "Package appears inactive before this release."})
        if item.known_advisories:
            score += 12 + (len(item.known_advisories) * 4)
            reasons.append({"code": "known-advisory", "message": "Known advisories are attached."})
        score = clamp(score)
        level = "low"
        if score >= 75:
            level = "critical"
        elif score >= 50:
            level = "high"
        elif score >= 25:
            level = "medium"

        dep_entity = self.graph.entity(
            "dependency",
            f"{item.ecosystem}:{item.name}@{item.version}",
            id=stable_id("dependency", item.ecosystem, item.name, item.version),
            ecosystem=item.ecosystem,
            package=item.name,
            version=item.version,
            trust_score=round(score, 2),
            trust_level=level,
            reasons=reasons,
            metadata=item.metadata,
        )
        if item.repo:
            repo_entity = self.graph.upsert_repo(item.repo)
            self.graph.link(repo_entity.id, dep_entity.id, "depends_on")
        for advisory in item.known_advisories:
            cve = self.graph.entity("cve", advisory, id=stable_id("cve", advisory), advisory=advisory)
            self.graph.link(dep_entity.id, cve.id, "affected_by")
        return {
            "dependency": dep_entity.model_dump(),
            "risk_score": round(score, 2),
            "risk_level": level,
            "reasons": reasons,
        }
