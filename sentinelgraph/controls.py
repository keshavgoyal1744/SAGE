"""Control confidence scoring."""

from __future__ import annotations

from typing import Dict, List

from .graph import SecurityGraph
from .models import ControlRunInput, ControlScore
from .utils import clamp, stable_id


class ControlEngine:
    def __init__(self, graph: SecurityGraph):
        self.graph = graph

    def record_run(self, item: ControlRunInput) -> ControlScore:
        scanner_entity = self.graph.entity(
            "scanner",
            item.scanner,
            id=stable_id("scanner", item.repo, item.scanner),
            scanner=item.scanner,
        )
        control_entity = self.graph.entity(
            "control",
            item.control_id,
            id=stable_id("control", item.repo, item.control_id),
            control_type=item.control_type,
            scanner=item.scanner,
        )
        repo_entity = self.graph.upsert_repo(item.repo)
        self.graph.link(repo_entity.id, scanner_entity.id, "uses")
        self.graph.link(scanner_entity.id, control_entity.id, "implements")

        score = self.score(item)
        run_id = stable_id("control_run", item.repo, item.control_id, len(self.graph.store.latest_control_runs(item.repo)) + 1)
        payload = item.model_dump()
        payload["score"] = score.confidence_score
        payload["computed"] = score.model_dump()
        self.graph.store.insert_control_run(run_id, payload)
        self.graph.link(control_entity.id, scanner_entity.id, "validated_by", run_id=run_id, score=score.confidence_score)
        return score

    def score(self, item: ControlRunInput) -> ControlScore:
        applicable = [payload for payload in item.payloads if payload.expected]
        detected = sum(1 for payload in applicable if payload.detected)
        missed = max(len(applicable) - detected, 0)
        categories = sorted({payload.category for payload in applicable})
        missed_categories = sorted({payload.category for payload in applicable if not payload.detected})
        total = max(len(applicable), 1)
        detection_rate = detected / total
        policy_penalty = 0.0
        failed_policies = [name for name, ok in item.policy_checks.items() if not ok]
        if failed_policies:
            policy_penalty = min(30.0, len(failed_policies) * 8.0)
        blind_spot_score = clamp((len(missed_categories) / max(len(categories), 1)) * 100)
        exploit_coverage_score = clamp(detection_rate * 100 - policy_penalty)
        confidence = clamp((detection_rate * 75) + (exploit_coverage_score * 0.25) - policy_penalty)
        decay = clamp(100 - (missed * 7) - policy_penalty)
        recommendations = []
        for category in missed_categories:
            recommendations.append(f"Add or tune detection coverage for {category}.")
        for policy in failed_policies:
            recommendations.append(f"Fix failed control policy: {policy}.")
        if not recommendations:
            recommendations.append("Control is currently meeting expected payload coverage.")
        return ControlScore(
            control_id=item.control_id,
            confidence_score=round(confidence, 2),
            decay_score=round(decay, 2),
            blind_spot_score=round(blind_spot_score, 2),
            exploit_coverage_score=round(exploit_coverage_score, 2),
            detected=detected,
            missed=missed,
            blind_spots=missed_categories,
            recommendations=recommendations,
        )

    def latest_context(self, repo: str) -> Dict[str, object]:
        runs = self.graph.store.latest_control_runs(repo)
        if not runs:
            return {"average_confidence": None, "weak_controls": [], "blind_spots": []}
        weak: List[dict] = []
        blind_spots = set()
        scores = []
        for run in runs:
            payload = run["payload"]
            computed = payload.get("computed", {})
            score = computed.get("confidence_score", run.get("score", 0))
            scores.append(score)
            for blind in computed.get("blind_spots", []):
                blind_spots.add(blind)
            if score < 80:
                weak.append(
                    {
                        "control_id": payload.get("control_id"),
                        "score": score,
                        "blind_spots": computed.get("blind_spots", []),
                    }
                )
        average = sum(scores) / max(len(scores), 1)
        return {
            "average_confidence": round(average, 2),
            "weak_controls": weak,
            "blind_spots": sorted(blind_spots),
        }
