"""Adaptive online MR reputation model."""

from __future__ import annotations

import math
from pathlib import Path
from typing import Dict, List

from .models import MergeRequestInput, ReputationFeedbackInput
from .storage import Store
from .utils import dumps, loads, stable_id, utcnow


FEATURES = [
    "touches_auth",
    "touches_validation",
    "ai_assisted",
    "dependency_change",
    "docs_only",
    "approval_count",
    "file_count",
    "risky_words",
]


class ReputationEngine:
    def __init__(self, store: Store):
        self.store = store
        self.model_path = Path(store.path).parent / "reputation_model.json"
        self.state = self._load()

    def score_mr(self, mr: MergeRequestInput) -> Dict[str, object]:
        features = extract_features(mr)
        probability = self._predict(features)
        level = "low"
        risk_score = round((1 - probability) * 100, 2)
        if risk_score >= 75:
            level = "critical"
        elif risk_score >= 55:
            level = "high"
        elif risk_score >= 30:
            level = "medium"
        result = {"merge_probability": round(probability, 4), "risk_score": risk_score, "level": level, "features": features}
        self.store.insert_analysis(
            stable_id("reputation", mr.repo, mr.mr_id),
            mr.repo,
            mr.mr_id,
            "reputation",
            risk_score,
            level,
            result,
        )
        return result

    def feedback(self, item: ReputationFeedbackInput) -> Dict[str, object]:
        features = item.features
        if features is None:
            analysis = next((a for a in self.store.list_analyses(item.repo) if a["subject_id"] == item.mr_id or a["payload"].get("mr_id") == item.mr_id), None)
            features = analysis["payload"].get("features", {}) if analysis else {}
        label = 1.0 if item.outcome == "merged" else 0.0
        pred = self._predict(features)
        err = label - pred
        lr = 0.08
        self.state["bias"] += lr * err
        for name in FEATURES:
            self.state["weights"][name] = self.state["weights"].get(name, 0.0) + lr * err * float(features.get(name, 0.0))
        self.state["samples"] += 1
        predicted_label = 1.0 if pred >= 0.5 else 0.0
        self.state["correct"] += int(predicted_label == label)
        self._save()
        return {
            "trained": True,
            "sample_count": self.state["samples"],
            "accuracy": round(self.state["correct"] / max(self.state["samples"], 1), 4),
            "previous_probability": round(pred, 4),
        }

    def user_reputation(self, repo: str | None = None) -> Dict[str, object]:
        users: Dict[str, Dict[str, float]] = {}
        for entity in self.store.list_entities("merge_request"):
            attrs = entity.attributes
            author = attrs.get("metadata", {}).get("author") or attrs.get("author") or "unknown"
            users.setdefault(author, {"changes": 0, "risk": 0.0})
            users[author]["changes"] += 1
        for analysis in self.store.list_analyses(repo):
            payload = analysis["payload"]
            author = payload.get("passport", {}).get("author") or "unknown"
            users.setdefault(author, {"changes": 0, "risk": 0.0})
            users[author]["risk"] += analysis["score"]
        return {"users": users, "model": {"samples": self.state["samples"], "accuracy": round(self.state["correct"] / max(self.state["samples"], 1), 4)}}

    def checkpoint(self) -> Dict[str, object]:
        self._save()
        return {"path": str(self.model_path), "state": self.state}

    def _predict(self, features: Dict[str, float]) -> float:
        z = self.state["bias"]
        for name, value in features.items():
            z += self.state["weights"].get(name, 0.0) * float(value)
        return 1 / (1 + math.exp(-max(-30, min(30, z))))

    def _load(self) -> Dict[str, object]:
        if self.model_path.exists():
            return loads(self.model_path.read_text(), {})
        return {"weights": {name: 0.0 for name in FEATURES}, "bias": 0.0, "samples": 0, "correct": 0}

    def _save(self) -> None:
        self.model_path.write_text(dumps(self.state))


def extract_features(mr: MergeRequestInput) -> Dict[str, float]:
    text = f"{mr.title} {mr.description} {mr.diff_summary} {' '.join(mr.files_changed)}".lower()
    docs_only = bool(mr.files_changed) and all(path.startswith("docs/") or path.endswith(".md") for path in mr.files_changed)
    return {
        "touches_auth": float(any(term in text for term in ["auth", "token", "jwt", "session", "permission", "gateway"])),
        "touches_validation": float(any(term in text for term in ["validation", "validate", "sanitize", "bounds"])),
        "ai_assisted": float(mr.ai_assisted),
        "dependency_change": float(any(path.rsplit("/", 1)[-1] in {"requirements.txt", "pyproject.toml", "package.json", "go.mod"} for path in mr.files_changed)),
        "docs_only": float(docs_only),
        "approval_count": float(min(mr.approvals, 5)) / 5.0,
        "file_count": float(min(len(mr.files_changed), 20)) / 20.0,
        "risky_words": float(sum(1 for term in ["remove", "bypass", "disable", "skip", "temporary"] if term in text)) / 5.0,
    }
