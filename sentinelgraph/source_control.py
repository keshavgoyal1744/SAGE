"""Source-control provider clients and history importer."""

from __future__ import annotations

import hmac
import os
from hashlib import sha256
from typing import Any, Dict, Iterable, List, Optional
from urllib.parse import quote

import httpx

from .factory import Engines
from .models import (
    DecisionInput,
    MergeRequestInput,
    SourceChangeRecord,
    SourceComment,
    SourceImportRequest,
    SourceImportResult,
)
from .utils import stable_id


DECISION_MARKERS = [
    "security decision:",
    "decision:",
    "we decided",
    "architecture decision:",
    "policy decision:",
]

AI_MARKERS = ["ai-assisted", "generated", "copilot", "cursor", "code assistant", "model-generated"]
AUTH_MARKERS = ["auth", "jwt", "token", "session", "permission", "role", "gateway", "oauth"]
VALIDATION_MARKERS = ["validation", "validate", "sanitize", "bounds", "schema"]
DEPENDENCY_FILES = {
    "requirements.txt",
    "pyproject.toml",
    "package.json",
    "package-lock.json",
    "pnpm-lock.yaml",
    "yarn.lock",
    "go.mod",
    "go.sum",
    "Cargo.toml",
    "Cargo.lock",
    "Gemfile",
    "Gemfile.lock",
    "pom.xml",
    "build.gradle",
}


class ProviderError(RuntimeError):
    pass


class GitLabClient:
    def __init__(self, token: Optional[str] = None, base_url: str = "https://gitlab.com"):
        self.token = token
        self.base_url = base_url.rstrip("/")

    def fetch_history(self, repo: str, limit: int = 100, include_closed: bool = True) -> List[SourceChangeRecord]:
        state = "all" if include_closed else "opened"
        project = quote(repo, safe="")
        records: List[SourceChangeRecord] = []
        page = 1
        headers = {"PRIVATE-TOKEN": self.token} if self.token else {}
        with httpx.Client(timeout=30.0, headers=headers) as client:
            while limit <= 0 or len(records) < limit:
                remaining = 100 if limit <= 0 else min(100, limit - len(records))
                response = client.get(
                    f"{self.base_url}/api/v4/projects/{project}/merge_requests",
                    params={"state": state, "per_page": remaining, "page": page},
                )
                response.raise_for_status()
                batch = response.json()
                if not batch:
                    break
                for mr in batch:
                    records.append(self._fetch_one(client, project, repo, mr))
                    if limit > 0 and len(records) >= limit:
                        break
                page += 1
        return records

    def fetch_one(self, repo: str, mr_id: str) -> SourceChangeRecord:
        project = quote(repo, safe="")
        headers = {"PRIVATE-TOKEN": self.token} if self.token else {}
        with httpx.Client(timeout=30.0, headers=headers) as client:
            response = client.get(f"{self.base_url}/api/v4/projects/{project}/merge_requests/{mr_id}")
            response.raise_for_status()
            return self._fetch_one(client, project, repo, response.json())

    def _fetch_one(self, client: httpx.Client, project: str, repo: str, mr: Dict[str, Any]) -> SourceChangeRecord:
        iid = str(mr.get("iid") or mr.get("id"))
        changes = self._json_or_empty(
            client.get(f"{self.base_url}/api/v4/projects/{project}/merge_requests/{iid}/changes")
        )
        notes = self._json_or_empty(
            client.get(f"{self.base_url}/api/v4/projects/{project}/merge_requests/{iid}/notes", params={"per_page": 100})
        )
        commits = self._json_or_empty(
            client.get(f"{self.base_url}/api/v4/projects/{project}/merge_requests/{iid}/commits", params={"per_page": 100})
        )
        approvals = self._json_or_empty(
            client.get(f"{self.base_url}/api/v4/projects/{project}/merge_requests/{iid}/approvals")
        )
        changed_files = [
            change.get("new_path") or change.get("old_path")
            for change in changes.get("changes", [])
            if change.get("new_path") or change.get("old_path")
        ]
        diff_summary = summarize_changes(changes.get("changes", []))
        labels = mr.get("labels") or []
        return SourceChangeRecord(
            provider="gitlab",
            repo=repo,
            mr_id=iid,
            title=mr.get("title") or "",
            description=mr.get("description") or "",
            author=(mr.get("author") or {}).get("username") or "",
            source_branch=mr.get("source_branch") or "",
            target_branch=mr.get("target_branch") or "main",
            state=mr.get("state") or "",
            created_at=mr.get("created_at"),
            merged_at=mr.get("merged_at"),
            files_changed=changed_files,
            diff_summary=diff_summary,
            commits=[commit.get("id") for commit in commits if commit.get("id")],
            labels=labels,
            approvals=int(approvals.get("approvals_left", 0) == 0 and len(approvals.get("approved_by", []))) if isinstance(approvals, dict) else 0,
            comments=[
                SourceComment(
                    id=str(note.get("id")),
                    author=(note.get("author") or {}).get("username") or "",
                    body=note.get("body") or "",
                    created_at=note.get("created_at"),
                )
                for note in notes
                if isinstance(note, dict) and not note.get("system")
            ],
            metadata={"source_url": mr.get("web_url"), "provider_state": mr.get("state")},
        )

    def _json_or_empty(self, response: httpx.Response) -> Any:
        if response.status_code >= 400:
            return {} if response.status_code in {401, 403, 404} else []
        data = response.json()
        return data if data is not None else {}


class GitHubClient:
    def __init__(self, token: Optional[str] = None, base_url: str = "https://api.github.com"):
        self.token = token
        self.base_url = base_url.rstrip("/")

    def fetch_history(self, repo: str, limit: int = 100, include_closed: bool = True) -> List[SourceChangeRecord]:
        state = "all" if include_closed else "open"
        records: List[SourceChangeRecord] = []
        page = 1
        headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        with httpx.Client(timeout=30.0, headers=headers) as client:
            while limit <= 0 or len(records) < limit:
                remaining = 100 if limit <= 0 else min(100, limit - len(records))
                response = client.get(
                    f"{self.base_url}/repos/{repo}/pulls",
                    params={
                        "state": state,
                        "per_page": remaining,
                        "page": page,
                        "sort": "updated",
                        "direction": "desc",
                    },
                )
                response.raise_for_status()
                batch = response.json()
                if not batch:
                    break
                for pr in batch:
                    records.append(self._fetch_one(client, repo, pr))
                    if limit > 0 and len(records) >= limit:
                        break
                page += 1
        return records

    def fetch_one(self, repo: str, pr_number: str) -> SourceChangeRecord:
        headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        with httpx.Client(timeout=30.0, headers=headers) as client:
            response = client.get(f"{self.base_url}/repos/{repo}/pulls/{pr_number}")
            response.raise_for_status()
            return self._fetch_one(client, repo, response.json())

    def _fetch_one(self, client: httpx.Client, repo: str, pr: Dict[str, Any]) -> SourceChangeRecord:
        number = str(pr.get("number"))
        files = self._json_or_empty(client.get(f"{self.base_url}/repos/{repo}/pulls/{number}/files", params={"per_page": 100}))
        issue_comments = self._json_or_empty(client.get(f"{self.base_url}/repos/{repo}/issues/{number}/comments", params={"per_page": 100}))
        review_comments = self._json_or_empty(client.get(f"{self.base_url}/repos/{repo}/pulls/{number}/comments", params={"per_page": 100}))
        commits = self._json_or_empty(client.get(f"{self.base_url}/repos/{repo}/pulls/{number}/commits", params={"per_page": 100}))
        reviews = self._json_or_empty(client.get(f"{self.base_url}/repos/{repo}/pulls/{number}/reviews", params={"per_page": 100}))
        changed_files = [item.get("filename") for item in files if item.get("filename")]
        diff_summary = summarize_changes(files)
        labels = [label.get("name") for label in pr.get("labels", []) if label.get("name")]
        approvals = len({review.get("user", {}).get("login") for review in reviews if review.get("state") == "APPROVED"})
        comments = []
        for comment in issue_comments + review_comments:
            comments.append(
                SourceComment(
                    id=str(comment.get("id")),
                    author=(comment.get("user") or {}).get("login") or "",
                    body=comment.get("body") or "",
                    created_at=comment.get("created_at"),
                )
            )
        return SourceChangeRecord(
            provider="github",
            repo=repo,
            mr_id=number,
            title=pr.get("title") or "",
            description=pr.get("body") or "",
            author=(pr.get("user") or {}).get("login") or "",
            source_branch=(pr.get("head") or {}).get("ref") or "",
            target_branch=(pr.get("base") or {}).get("ref") or "main",
            state=pr.get("state") or "",
            created_at=pr.get("created_at"),
            merged_at=pr.get("merged_at"),
            files_changed=changed_files,
            diff_summary=diff_summary,
            commits=[commit.get("sha") for commit in commits if commit.get("sha")],
            labels=labels,
            approvals=approvals,
            comments=comments,
            metadata={"source_url": pr.get("html_url"), "provider_state": pr.get("state")},
        )

    def _json_or_empty(self, response: httpx.Response) -> Any:
        if response.status_code >= 400:
            return []
        data = response.json()
        return data if data is not None else []


class HistoryImporter:
    def __init__(self, engines: Engines):
        self.engines = engines

    def import_from_request(self, request: SourceImportRequest) -> SourceImportResult:
        token = request.token or (os.environ.get(request.token_env) if request.token_env else None)
        if not token:
            default_env = "GITLAB_TOKEN" if request.provider == "gitlab" else "GITHUB_TOKEN"
            token = os.environ.get(default_env)
        if request.provider == "gitlab":
            client = GitLabClient(token=token, base_url=request.base_url or "https://gitlab.com")
        else:
            client = GitHubClient(token=token, base_url=request.base_url or "https://api.github.com")
        records = client.fetch_history(request.repo, limit=request.limit, include_closed=request.include_closed)
        return self.import_records(records, import_decisions=request.import_decisions, analyze=request.analyze)

    def import_records(
        self,
        records: Iterable[SourceChangeRecord],
        import_decisions: bool = True,
        analyze: bool = True,
    ) -> SourceImportResult:
        records = list(records)
        provider = records[0].provider if records else "fixture"
        repo = records[0].repo if records else ""
        imported = 0
        analyzed = 0
        decisions_imported = 0
        high_or_critical = 0
        errors: List[str] = []
        analyses: List[Dict[str, Any]] = []
        integration = self.engines.graph.entity(
            "integration",
            f"{provider}:{repo}",
            id=stable_id("integration", provider, repo),
            provider=provider,
            repo=repo,
        )
        repo_entity = self.engines.graph.upsert_repo(repo)
        self.engines.graph.link(repo_entity.id, integration.id, "imported_by")

        for record in records:
            try:
                imported += 1
                mr = normalize_record(record)
                mr_entity = self.engines.graph.entity(
                    "merge_request",
                    mr.mr_id,
                    id=stable_id("merge_request", mr.repo, mr.mr_id),
                    provider=record.provider,
                    state=record.state,
                    source_url=record.metadata.get("source_url"),
                    comments=[comment.model_dump() for comment in record.comments],
                )
                self.engines.graph.link(integration.id, mr_entity.id, "imported")
                if import_decisions:
                    for decision in extract_decisions(record):
                        self.engines.memory.add_decision(decision)
                        decisions_imported += 1
                if analyze:
                    result = self.engines.risk.analyze_mr(mr)
                    analyzed += 1
                    if result.level in {"high", "critical"}:
                        high_or_critical += 1
                    analyses.append(result.model_dump())
            except Exception as exc:  # pragma: no cover - defensive import boundary
                errors.append(f"{record.provider}:{record.repo}:{record.mr_id}: {exc}")
        return SourceImportResult(
            provider=provider,
            repo=repo,
            imported=imported,
            analyzed=analyzed,
            decisions_imported=decisions_imported,
            high_or_critical=high_or_critical,
            errors=errors,
            analyses=analyses,
        )

    def import_webhook(self, provider: str, payload: Dict[str, Any]) -> SourceImportResult:
        if provider == "gitlab":
            record = record_from_gitlab_webhook(payload)
        elif provider == "github":
            record = record_from_github_webhook(payload)
        else:
            raise ProviderError(f"Unsupported webhook provider: {provider}")
        event = self.engines.graph.entity(
            "webhook_event",
            f"{provider}:{record.repo}:{record.mr_id}",
            id=stable_id("webhook", provider, record.repo, record.mr_id, payload.get("action") or payload.get("object_kind")),
            provider=provider,
            action=payload.get("action") or payload.get("object_kind"),
        )
        repo = self.engines.graph.upsert_repo(record.repo)
        self.engines.graph.link(repo.id, event.id, "received")
        return self.import_records([record], import_decisions=True, analyze=True)


def normalize_record(record: SourceChangeRecord) -> MergeRequestInput:
    text = " ".join(
        [
            record.title,
            record.description,
            record.diff_summary,
            " ".join(record.labels),
            " ".join(comment.body for comment in record.comments),
        ]
    ).lower()
    ai_assisted = any(marker in text for marker in AI_MARKERS)
    deployment_window = "Friday after-hours" if record.created_at and "T2" in record.created_at else None
    metadata = dict(record.metadata)
    metadata.update(
        {
            "provider": record.provider,
            "state": record.state,
            "comments": [comment.model_dump() for comment in record.comments],
            "dependencies": dependency_hints(record.files_changed, record.diff_summary),
            "ai": {"model_family": "unknown", "source": "source-history"} if ai_assisted else {},
        }
    )
    return MergeRequestInput(
        repo=record.repo,
        mr_id=record.mr_id,
        title=record.title,
        description=record.description,
        author=record.author or "unknown",
        source_branch=record.source_branch,
        target_branch=record.target_branch,
        created_at=record.created_at,
        merged_at=record.merged_at,
        files_changed=record.files_changed,
        diff_summary=record.diff_summary,
        commits=record.commits,
        labels=record.labels,
        ai_assisted=ai_assisted,
        approvals=record.approvals,
        deployment_window=deployment_window,
        metadata=metadata,
    )


def extract_decisions(record: SourceChangeRecord) -> List[DecisionInput]:
    decisions: List[DecisionInput] = []
    for idx, comment in enumerate(record.comments, start=1):
        body = comment.body.strip()
        lower = body.lower()
        if not any(marker in lower for marker in DECISION_MARKERS):
            continue
        title = first_sentence(body)
        tags = []
        if any(marker in lower for marker in AUTH_MARKERS):
            tags.append("auth")
        if any(marker in lower for marker in VALIDATION_MARKERS):
            tags.append("validation")
        if "ai" in lower or "generated" in lower:
            tags.append("ai")
        decisions.append(
            DecisionInput(
                repo=record.repo,
                decision_id=f"{record.provider}-{record.mr_id}-{idx}",
                title=title[:140] or f"Imported security decision from change {record.mr_id}",
                text=body,
                governs=record.files_changed,
                security_relevant=bool(tags) or "security" in lower,
                tags=tags or ["imported"],
                evidence={
                    "provider": record.provider,
                    "mr_id": record.mr_id,
                    "comment_id": comment.id,
                    "author": comment.author,
                    "created_at": comment.created_at,
                },
            )
        )
    return decisions


def summarize_changes(changes: List[Dict[str, Any]]) -> str:
    summaries = []
    for change in changes[:25]:
        path = change.get("new_path") or change.get("filename") or change.get("old_path") or "unknown"
        additions = change.get("additions")
        deletions = change.get("deletions")
        patch = change.get("diff") or change.get("patch") or ""
        signals = []
        lower_patch = patch.lower()
        for marker in ["remove", "bypass", "disable", "token", "auth", "secret", "validation", "ssrf", "sql"]:
            if marker in lower_patch:
                signals.append(marker)
        if additions is not None or deletions is not None:
            summaries.append(f"{path} (+{additions or 0}/-{deletions or 0}) {' '.join(signals)}")
        else:
            summaries.append(f"{path} {' '.join(signals)}")
    return "; ".join(summaries)


def dependency_hints(files_changed: List[str], diff_summary: str) -> List[Dict[str, Any]]:
    hints = []
    for path in files_changed:
        name = path.rsplit("/", 1)[-1]
        if name in DEPENDENCY_FILES:
            hints.append({"name": name, "new": "add" in diff_summary.lower(), "risk_level": "medium"})
    return hints


def first_sentence(text: str) -> str:
    normalized = " ".join(text.split())
    for sep in [". ", "\n", "; "]:
        if sep in normalized:
            return normalized.split(sep, 1)[0]
    return normalized


def record_from_gitlab_webhook(payload: Dict[str, Any]) -> SourceChangeRecord:
    attrs = payload.get("object_attributes") or {}
    project = payload.get("project") or {}
    author = payload.get("user") or {}
    labels = [label.get("title") for label in attrs.get("labels", []) if label.get("title")]
    return SourceChangeRecord(
        provider="gitlab",
        repo=project.get("path_with_namespace") or attrs.get("target", {}).get("path_with_namespace") or "unknown",
        mr_id=str(attrs.get("iid") or attrs.get("id") or "unknown"),
        title=attrs.get("title") or "",
        description=attrs.get("description") or "",
        author=author.get("username") or attrs.get("author_id", "unknown"),
        source_branch=attrs.get("source_branch") or "",
        target_branch=attrs.get("target_branch") or "main",
        state=attrs.get("state") or attrs.get("action") or "",
        created_at=attrs.get("created_at"),
        merged_at=attrs.get("updated_at") if attrs.get("state") == "merged" else None,
        files_changed=[],
        diff_summary=attrs.get("description") or "",
        labels=labels,
        comments=[],
        metadata={"webhook": True, "action": attrs.get("action"), "source_url": attrs.get("url")},
    )


def record_from_github_webhook(payload: Dict[str, Any]) -> SourceChangeRecord:
    pr = payload.get("pull_request") or {}
    repo = payload.get("repository") or {}
    labels = [label.get("name") for label in pr.get("labels", []) if label.get("name")]
    return SourceChangeRecord(
        provider="github",
        repo=repo.get("full_name") or "unknown",
        mr_id=str(pr.get("number") or payload.get("number") or "unknown"),
        title=pr.get("title") or "",
        description=pr.get("body") or "",
        author=(pr.get("user") or {}).get("login") or "unknown",
        source_branch=(pr.get("head") or {}).get("ref") or "",
        target_branch=(pr.get("base") or {}).get("ref") or "main",
        state=pr.get("state") or payload.get("action") or "",
        created_at=pr.get("created_at"),
        merged_at=pr.get("merged_at"),
        files_changed=[],
        diff_summary=pr.get("body") or "",
        labels=labels,
        comments=[],
        metadata={"webhook": True, "action": payload.get("action"), "source_url": pr.get("html_url")},
    )


def verify_github_signature(body: bytes, signature: Optional[str], secret: Optional[str]) -> bool:
    if not secret:
        return True
    if not signature or not signature.startswith("sha256="):
        return False
    expected = "sha256=" + hmac.new(secret.encode("utf-8"), body, sha256).hexdigest()
    return hmac.compare_digest(expected, signature)


def verify_gitlab_token(header_token: Optional[str], secret: Optional[str]) -> bool:
    if not secret:
        return True
    if not header_token:
        return False
    return hmac.compare_digest(header_token, secret)
