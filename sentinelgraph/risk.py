"""Merge request risk and causality passport engine."""

from __future__ import annotations

from datetime import datetime
from typing import Dict, List, Tuple

from .controls import ControlEngine
from .graph import SecurityGraph
from .memory import MemoryEngine
from .models import Entity, MergeRequestInput, RiskReason, RiskResult
from .runtime import RuntimeEngine
from .utils import clamp, stable_id


AUTH_TERMS = ["auth", "jwt", "token", "session", "permission", "role", "oauth", "gateway"]
VALIDATION_TERMS = ["validate", "validation", "sanitize", "schema", "bounds", "input"]
RISKY_DIFF_TERMS = ["remove", "removed", "disable", "bypass", "skip", "temporary", "todo"]
AI_RISK_TERMS = ["generated", "copilot", "cursor", "ai-assisted", "model", "prompt"]


class RiskEngine:
    def __init__(
        self,
        graph: SecurityGraph,
        memory: MemoryEngine,
        controls: ControlEngine,
        runtime: RuntimeEngine,
    ):
        self.graph = graph
        self.memory = memory
        self.controls = controls
        self.runtime = runtime

    def analyze_mr(self, item: MergeRequestInput) -> RiskResult:
        repo_entity = self.graph.upsert_repo(item.repo)
        developer = self.graph.entity(
            "developer",
            item.author,
            id=stable_id("developer", item.author),
            username=item.author,
            behavior=item.metadata.get("developer_behavior", {}),
        )
        mr_entity = self.graph.entity(
            "merge_request",
            item.mr_id,
            id=stable_id("merge_request", item.repo, item.mr_id),
            mr_id=item.mr_id,
            title=item.title,
            description=item.description,
            files_changed=item.files_changed,
            labels=item.labels,
            ai_assisted=item.ai_assisted,
            approvals=item.approvals,
            deployment_window=item.deployment_window,
            metadata=item.metadata,
        )
        self.graph.link(repo_entity.id, mr_entity.id, "has_change")
        self.graph.link(developer.id, mr_entity.id, "authored")

        services: List[Entity] = []
        for path in item.files_changed:
            service = self.graph.service_from_file(item.repo, path)
            services.append(service)
            self.graph.link(mr_entity.id, service.id, "touches", file=path)

        decisions = self.memory.find_relevant_decisions(item)
        conflicts = self.memory.detect_conflicts(item, decisions)
        for decision in decisions:
            self.graph.link(mr_entity.id, decision.id, "evaluated_against")
        for conflict in conflicts:
            self.graph.link(mr_entity.id, str(conflict["decision_id"]), "conflicts_with", reason=conflict["reason"])

        reasons: List[RiskReason] = []
        score = 10.0
        text = self._text(item)
        touched_auth = self._touches_terms(text, AUTH_TERMS)
        touched_validation = self._touches_terms(text, VALIDATION_TERMS)
        risky_diff = self._touches_terms(text, RISKY_DIFF_TERMS)

        if item.ai_assisted or self._touches_terms(text, AI_RISK_TERMS):
            score += 12
            reasons.append(
                RiskReason(
                    code="ai-code-governance",
                    message="Change carries AI-assisted coding risk signals.",
                    weight=12,
                    evidence={"ai_assisted": item.ai_assisted, "metadata": item.metadata.get("ai", {})},
                )
            )
            model_family = item.metadata.get("ai", {}).get("model_family")
            if model_family:
                model_entity = self.graph.entity(
                    "agent",
                    f"{model_family} coding assistant",
                    id=stable_id("agent", model_family),
                    model_family=model_family,
                    fingerprint=item.metadata.get("ai", {}),
                )
                self.graph.link(model_entity.id, mr_entity.id, "assisted")

        if touched_auth:
            score += 18
            reasons.append(
                RiskReason(
                    code="auth-boundary",
                    message="Change touches authentication, authorization, token, or gateway code.",
                    weight=18,
                    evidence={"files": item.files_changed},
                )
            )

        if touched_validation and risky_diff:
            score += 20
            reasons.append(
                RiskReason(
                    code="guard-weakening",
                    message="Diff appears to weaken validation, bounds checks, or security guards.",
                    weight=20,
                    evidence={"diff_summary": item.diff_summary},
                )
            )

        if conflicts:
            weight = min(25, 12 + len(conflicts) * 6)
            score += weight
            reasons.append(
                RiskReason(
                    code="memory-conflict",
                    message="Change conflicts with active security decisions.",
                    weight=weight,
                    evidence={"conflicts": conflicts},
                )
            )

        if self._is_risky_deployment_window(item):
            score += 8
            reasons.append(
                RiskReason(
                    code="rushed-deployment-window",
                    message="Change is associated with a risky deployment window.",
                    weight=8,
                    evidence={"created_at": item.created_at, "deployment_window": item.deployment_window},
                )
            )

        runtime_matches = []
        for service in services:
            runtime_matches.extend(self.runtime.correlate(item.repo, service.name))
        if runtime_matches:
            score += min(18, 8 + len(runtime_matches) * 2)
            reasons.append(
                RiskReason(
                    code="runtime-feedback",
                    message="Runtime telemetry has recent signals on the same service or path.",
                    weight=min(18, 8 + len(runtime_matches) * 2),
                    evidence={"correlations": runtime_matches[:6]},
                )
            )

        control_context = self.controls.latest_context(item.repo)
        weak_controls = control_context.get("weak_controls") or []
        blind_spots = control_context.get("blind_spots") or []
        if weak_controls:
            score += min(15, 6 + len(weak_controls) * 3)
            reasons.append(
                RiskReason(
                    code="control-confidence",
                    message="Recent control validation shows blind spots relevant to this change.",
                    weight=min(15, 6 + len(weak_controls) * 3),
                    evidence=control_context,
                )
            )
        if touched_auth and any("secret" in spot or "auth" in spot or "jwt" in spot for spot in blind_spots):
            score += 8
            reasons.append(
                RiskReason(
                    code="control-blind-spot-overlap",
                    message="Control blind spots overlap with authentication-sensitive code.",
                    weight=8,
                    evidence={"blind_spots": blind_spots},
                )
            )

        dep_risk = self._dependency_risk(item)
        if dep_risk:
            score += dep_risk[0]
            reasons.append(dep_risk[1])

        behavior = item.metadata.get("developer_behavior", {})
        behavior_weight = self._behavior_weight(behavior)
        if behavior_weight:
            score += behavior_weight
            reasons.append(
                RiskReason(
                    code="adaptive-review",
                    message="Developer workflow patterns require stronger review for this change.",
                    weight=behavior_weight,
                    evidence=behavior,
                )
            )

        score = round(clamp(score), 2)
        level = self._level(score)
        actions = self._recommended_actions(score, touched_auth, conflicts, weak_controls, item)
        linked_entities = decisions + services
        passport = {
            "summary": f"{item.repo} {item.mr_id} risk is {level} ({score}).",
            "touches_auth": touched_auth,
            "touches_validation": touched_validation,
            "memory_conflicts": conflicts,
            "control_context": control_context,
            "runtime_correlations": runtime_matches[:10],
            "services": [service.model_dump() for service in services],
            "recommended_actions": actions,
            "policy_context": {
                "risk_score": score,
                "approvals": item.approvals,
                "touches_auth": touched_auth,
                "unresolved_critical": 0,
            },
        }
        result = RiskResult(
            repo=item.repo,
            mr_id=item.mr_id,
            score=score,
            level=level,
            reasons=reasons,
            linked_entities=linked_entities,
            recommended_actions=actions,
            passport=passport,
        )
        self.graph.store.insert_analysis(
            stable_id("analysis", item.repo, item.mr_id),
            item.repo,
            mr_entity.id,
            "merge_request",
            score,
            level,
            result.model_dump(),
        )
        return result

    def _text(self, item: MergeRequestInput) -> str:
        return " ".join(
            [
                item.title,
                item.description,
                item.diff_summary,
                " ".join(item.files_changed),
                " ".join(item.labels),
                str(item.metadata),
            ]
        ).lower()

    def _touches_terms(self, text: str, terms: List[str]) -> bool:
        return any(term in text for term in terms)

    def _is_risky_deployment_window(self, item: MergeRequestInput) -> bool:
        window = (item.deployment_window or "").lower()
        if "friday" in window or "weekend" in window or "after-hours" in window:
            return True
        if not item.created_at:
            return False
        try:
            parsed = datetime.fromisoformat(item.created_at.replace("Z", "+00:00"))
        except ValueError:
            return False
        return parsed.weekday() == 4 or parsed.hour >= 18

    def _dependency_risk(self, item: MergeRequestInput) -> Tuple[float, RiskReason] | None:
        deps = item.metadata.get("dependencies", [])
        risky = [dep for dep in deps if dep.get("risk_level") in {"high", "critical"} or dep.get("new")]
        if not risky:
            return None
        weight = min(14, 6 + len(risky) * 4)
        return (
            weight,
            RiskReason(
                code="supply-chain-risk",
                message="Change introduces or updates dependencies with trust risk.",
                weight=weight,
                evidence={"dependencies": risky},
            ),
        )

    def _behavior_weight(self, behavior: Dict[str, object]) -> float:
        weight = 0.0
        if behavior.get("frequent_rollbacks"):
            weight += 4
        if behavior.get("review_bypass_attempts"):
            weight += 8
        if behavior.get("high_regression_rate"):
            weight += 6
        return min(weight, 12)

    def _level(self, score: float) -> str:
        if score >= 80:
            return "critical"
        if score >= 60:
            return "high"
        if score >= 35:
            return "medium"
        return "low"

    def _recommended_actions(
        self,
        score: float,
        touches_auth: bool,
        conflicts: List[Dict[str, object]],
        weak_controls: List[dict],
        item: MergeRequestInput,
    ) -> List[str]:
        actions = []
        if score >= 80:
            actions.append("Require security owner review before merge.")
        if touches_auth:
            actions.append("Add focused auth boundary tests and negative permission tests.")
        if conflicts:
            actions.append("Resolve or explicitly override conflicting security decisions with evidence.")
        if weak_controls:
            actions.append("Run targeted control validation for affected bug classes before merge.")
        if item.ai_assisted:
            actions.append("Review for hallucinated APIs, missing validation, unsafe crypto, and generated auth logic.")
        if not actions:
            actions.append("Proceed with normal review and keep generated evidence attached.")
        return actions
