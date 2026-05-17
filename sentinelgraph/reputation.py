"""Adaptive online MR reputation model."""

from __future__ import annotations

import math
import os
from pathlib import Path
from typing import Dict, List

from .models import AgentExploreRequest, MergeRequestInput, ReputationFeedbackInput
from .provider_ops import ProviderOps
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
    "large_diff",
    "test_coverage_touch",
    "generated_code_signal",
    "weekend_or_after_hours",
    "author_change_count",
    "author_mean_risk",
    "security_file_touch",
    "migration_touch",
    "infra_touch",
]


class ReputationEngine:
    def __init__(self, store: Store):
        self.store = store
        self.model_path = Path(store.path).parent / "reputation_model.json"
        self.checkpointer = ModelCheckpointPersistence(self.model_path)
        self.state = self._load()

    def score_mr(self, mr: MergeRequestInput) -> Dict[str, object]:
        features = extract_features(mr)
        features.update(self._historical_features(mr))
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
        for author, data in users.items():
            data["mean_risk"] = round(data["risk"] / max(data["changes"], 1), 2)
            data["reputation_score"] = round(max(0.0, 100.0 - data["mean_risk"]), 2)
        return {"users": users, "model": {"samples": self.state["samples"], "accuracy": round(self.state["correct"] / max(self.state["samples"], 1), 4)}}

    def checkpoint(self) -> Dict[str, object]:
        status = self._save()
        return {"path": str(self.model_path), "state": self.state, "persistence": status}

    def ide_agent_context(self, mr: MergeRequestInput) -> Dict[str, object]:
        score = self.score_mr(mr)
        rules = []
        if score["features"].get("touches_auth"):
            rules.append("Open auth boundary tests and call graph before editing.")
        if score["features"].get("dependency_change"):
            rules.append("Inspect package release provenance and lockfile deltas.")
        if score["features"].get("ai_assisted") or score["features"].get("generated_code_signal"):
            rules.append("Check generated code for hallucinated APIs, missing validation, and unsafe crypto.")
        return {
            "repo": mr.repo,
            "mr_id": mr.mr_id,
            "risk": score,
            "ide_focus": rules or ["Review changed files against active security decisions."],
            "suggested_prompts": [
                "Trace user-controlled input through this change.",
                "List authorization checks removed or weakened by this diff.",
                "Generate negative tests for the highest-risk path.",
            ],
        }

    def agent_explore(self, request: AgentExploreRequest) -> Dict[str, object]:
        ops = ProviderOps(request)
        content = ops.get_file(request.file_path, request.default_branch) if request.file_path else None
        text = content or request.question
        findings = []
        for term, reason in [
            ("md5", "weak crypto"),
            ("pickle.loads", "unsafe deserialization"),
            ("jwt.decode", "token validation review"),
            ("subprocess", "command execution review"),
            ("requests.get", "SSRF review"),
            ("select", "query construction review"),
        ]:
            if term in text.lower():
                findings.append({"term": term, "reason": reason})
        return {
            "repo": request.repo,
            "mr_id": request.mr_id,
            "file_path": request.file_path,
            "question": request.question,
            "mode": "provider-file" if content else "heuristic",
            "findings": findings,
            "next_steps": [
                "Map each finding to reachable runtime routes.",
                "Create negative tests before applying automated patches.",
                "Feed confirmed misses back into control confidence scoring.",
            ],
        }

    def _predict(self, features: Dict[str, float]) -> float:
        z = self.state["bias"]
        for name, value in features.items():
            z += self.state["weights"].get(name, 0.0) * float(value)
        return 1 / (1 + math.exp(-max(-30, min(30, z))))

    def _load(self) -> Dict[str, object]:
        if self.model_path.exists():
            return loads(self.model_path.read_text(), {})
        return {"weights": {name: 0.0 for name in FEATURES}, "bias": 0.0, "samples": 0, "correct": 0}

    def _save(self) -> Dict[str, object]:
        self.model_path.write_text(dumps(self.state))
        return self.checkpointer.publish(self.state)

    def _historical_features(self, mr: MergeRequestInput) -> Dict[str, float]:
        author_analyses = []
        for analysis in self.store.list_analyses(mr.repo):
            payload = analysis["payload"]
            author = payload.get("passport", {}).get("author") or payload.get("author")
            if author == mr.author:
                author_analyses.append(analysis)
        mean_risk = sum(item["score"] for item in author_analyses) / max(len(author_analyses), 1)
        return {
            "author_change_count": float(min(len(author_analyses), 50)) / 50.0,
            "author_mean_risk": float(min(mean_risk, 100.0)) / 100.0,
        }


def extract_features(mr: MergeRequestInput) -> Dict[str, float]:
    text = f"{mr.title} {mr.description} {mr.diff_summary} {' '.join(mr.files_changed)}".lower()
    docs_only = bool(mr.files_changed) and all(path.startswith("docs/") or path.endswith(".md") for path in mr.files_changed)
    test_touch = any(path.startswith("tests/") or "/test" in path or path.endswith(("_test.py", ".spec.ts", ".test.ts")) for path in mr.files_changed)
    infra_touch = any(path.startswith((".github/", ".gitlab", "terraform/", "helm/", "k8s/")) or path.endswith((".tf", ".yaml", ".yml")) for path in mr.files_changed)
    migration_touch = any("migration" in path.lower() for path in mr.files_changed)
    security_file_touch = any(any(term in path.lower() for term in ["auth", "crypto", "token", "permission", "security"]) for path in mr.files_changed)
    return {
        "touches_auth": float(any(term in text for term in ["auth", "token", "jwt", "session", "permission", "gateway"])),
        "touches_validation": float(any(term in text for term in ["validation", "validate", "sanitize", "bounds"])),
        "ai_assisted": float(mr.ai_assisted),
        "dependency_change": float(any(path.rsplit("/", 1)[-1] in {"requirements.txt", "pyproject.toml", "package.json", "go.mod"} for path in mr.files_changed)),
        "docs_only": float(docs_only),
        "approval_count": float(min(mr.approvals, 5)) / 5.0,
        "file_count": float(min(len(mr.files_changed), 20)) / 20.0,
        "risky_words": float(sum(1 for term in ["remove", "bypass", "disable", "skip", "temporary"] if term in text)) / 5.0,
        "large_diff": float(min(len(mr.diff_summary), 4000)) / 4000.0,
        "test_coverage_touch": float(test_touch),
        "generated_code_signal": float(any(term in text for term in ["generated by", "copilot", "cursor", "llm", "ai-generated"])),
        "weekend_or_after_hours": float("friday" in (mr.deployment_window or "").lower() or "weekend" in (mr.deployment_window or "").lower()),
        "security_file_touch": float(security_file_touch),
        "migration_touch": float(migration_touch),
        "infra_touch": float(infra_touch),
    }


class ModelCheckpointPersistence:
    def __init__(self, model_path: Path):
        self.model_path = model_path

    def publish(self, state: Dict[str, object]) -> Dict[str, object]:
        status: Dict[str, object] = {"local": str(self.model_path)}
        checkpoint_dir = os.environ.get("SENTINELGRAPH_MODEL_CHECKPOINT_DIR")
        if checkpoint_dir:
            target = Path(checkpoint_dir)
            target.mkdir(parents=True, exist_ok=True)
            path = target / self.model_path.name
            path.write_text(dumps(state))
            status["filesystem_checkpoint"] = str(path)
        postgres_dsn = os.environ.get("SENTINELGRAPH_REPUTATION_POSTGRES_DSN")
        if postgres_dsn:
            status["postgres"] = self._publish_postgres(postgres_dsn, state)
        gcs_bucket = os.environ.get("SENTINELGRAPH_GCS_BUCKET")
        if gcs_bucket:
            status["gcs"] = self._publish_gcs(gcs_bucket, state)
        return status

    def _publish_postgres(self, dsn: str, state: Dict[str, object]) -> Dict[str, object]:
        try:
            import psycopg  # type: ignore
        except Exception as exc:  # pragma: no cover - optional dependency boundary
            return {"configured": True, "stored": False, "error": f"psycopg unavailable: {exc}"}
        try:  # pragma: no cover - requires external service
            with psycopg.connect(dsn) as conn:
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS sentinelgraph_model_checkpoints (
                      name TEXT PRIMARY KEY,
                      state JSONB NOT NULL,
                      updated_at TIMESTAMPTZ DEFAULT now()
                    )
                    """
                )
                conn.execute(
                    """
                    INSERT INTO sentinelgraph_model_checkpoints(name, state)
                    VALUES (%s, %s)
                    ON CONFLICT(name) DO UPDATE SET state=excluded.state, updated_at=now()
                    """,
                    ("reputation", dumps(state)),
                )
            return {"configured": True, "stored": True}
        except Exception as exc:
            return {"configured": True, "stored": False, "error": str(exc)}

    def _publish_gcs(self, bucket_name: str, state: Dict[str, object]) -> Dict[str, object]:
        try:
            from google.cloud import storage  # type: ignore
        except Exception as exc:  # pragma: no cover - optional dependency boundary
            return {"configured": True, "stored": False, "error": f"google-cloud-storage unavailable: {exc}"}
        try:  # pragma: no cover - requires external service
            client = storage.Client()
            bucket = client.bucket(bucket_name)
            blob = bucket.blob("sentinelgraph/reputation_model.json")
            blob.upload_from_string(dumps(state), content_type="application/json")
            return {"configured": True, "stored": True, "uri": f"gs://{bucket_name}/sentinelgraph/reputation_model.json"}
        except Exception as exc:
            return {"configured": True, "stored": False, "error": str(exc)}
