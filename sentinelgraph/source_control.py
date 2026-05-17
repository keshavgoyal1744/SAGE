"""Source-control provider clients and history importer."""

from __future__ import annotations

import hmac
import os
import time
from base64 import b64decode, b64encode
from hashlib import sha256
from typing import TYPE_CHECKING, Any, Dict, Iterable, List, Optional
from urllib.parse import quote

import httpx

from .models import (
    DecisionInput,
    MergeRequestInput,
    SourceChangeRecord,
    SourceComment,
    SourceImportRequest,
    SourceImportResult,
)
from .utils import stable_id

if TYPE_CHECKING:
    from .factory import Engines


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


def request_with_retry(
    client: httpx.Client,
    method: str,
    url: str,
    *,
    retries: int = 3,
    backoff_seconds: float = 0.5,
    **kwargs,
) -> httpx.Response:
    """Retry provider calls on transient failures and common rate-limit responses."""
    last_response: httpx.Response | None = None
    for attempt in range(retries):
        response = client.request(method, url, **kwargs)
        last_response = response
        if response.status_code not in {429, 500, 502, 503, 504}:
            return response
        retry_after = response.headers.get("Retry-After")
        if retry_after:
            try:
                delay = min(30.0, float(retry_after))
            except ValueError:
                delay = backoff_seconds * (2 ** attempt)
        else:
            delay = backoff_seconds * (2 ** attempt)
        time.sleep(delay)
    return last_response


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
                response = request_with_retry(
                    client,
                    "GET",
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

    def comment_on_change(self, repo: str, mr_id: str, body: str) -> Dict[str, Any]:
        project = quote(repo, safe="")
        with httpx.Client(timeout=30.0, headers=self._headers()) as client:
            response = client.post(
                f"{self.base_url}/api/v4/projects/{project}/merge_requests/{mr_id}/notes",
                json={"body": body},
            )
            response.raise_for_status()
            return response.json()

    def create_issue(
        self,
        repo: str,
        title: str,
        body: str,
        labels: Optional[List[str]] = None,
        assignees: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        project = quote(repo, safe="")
        with httpx.Client(timeout=30.0, headers=self._headers()) as client:
            payload: Dict[str, Any] = {"title": title, "description": body, "labels": ",".join(labels or [])}
            assignee_ids = self._resolve_assignee_ids(client, assignees or [])
            if assignee_ids:
                payload["assignee_ids"] = assignee_ids
            response = client.post(
                f"{self.base_url}/api/v4/projects/{project}/issues",
                json=payload,
            )
            response.raise_for_status()
            return response.json()

    def list_issues(
        self,
        repo: str,
        labels: Optional[List[str]] = None,
        state: str = "opened",
        limit: int = 50,
    ) -> List[Dict[str, Any]]:
        project = quote(repo, safe="")
        params: Dict[str, Any] = {"state": state, "order_by": "updated_at", "sort": "desc"}
        if labels:
            params["labels"] = ",".join(labels)
        with httpx.Client(timeout=30.0, headers=self._headers()) as client:
            return self._list_pages(
                client,
                f"{self.base_url}/api/v4/projects/{project}/issues",
                params,
                max_pages=max(1, (limit + 99) // 100),
            )[:limit]

    def comment_on_issue(self, repo: str, issue_id: str, body: str) -> Dict[str, Any]:
        project = quote(repo, safe="")
        with httpx.Client(timeout=30.0, headers=self._headers()) as client:
            response = request_with_retry(
                client,
                "POST",
                f"{self.base_url}/api/v4/projects/{project}/issues/{issue_id}/notes",
                json={"body": body},
            )
            response.raise_for_status()
            return response.json()

    def close_issue(self, repo: str, issue_id: str) -> Dict[str, Any]:
        project = quote(repo, safe="")
        with httpx.Client(timeout=30.0, headers=self._headers()) as client:
            response = request_with_retry(
                client,
                "PUT",
                f"{self.base_url}/api/v4/projects/{project}/issues/{issue_id}",
                json={"state_event": "close"},
            )
            response.raise_for_status()
            return response.json()

    def issue_linked_changes(self, repo: str, issue_id: str) -> List[Dict[str, Any]]:
        project = quote(repo, safe="")
        with httpx.Client(timeout=30.0, headers=self._headers()) as client:
            data = self._json_or_empty(
                request_with_retry(
                    client,
                    "GET",
                    f"{self.base_url}/api/v4/projects/{project}/issues/{issue_id}/related_merge_requests",
                )
            )
        return data if isinstance(data, list) else []

    def create_branch(self, repo: str, branch: str, ref: str = "main") -> Dict[str, Any]:
        project = quote(repo, safe="")
        with httpx.Client(timeout=30.0, headers=self._headers()) as client:
            response = client.post(
                f"{self.base_url}/api/v4/projects/{project}/repository/branches",
                json={"branch": branch, "ref": ref},
            )
            if response.status_code == 400 and "already exists" in response.text.lower():
                return {"name": branch, "already_exists": True}
            response.raise_for_status()
            return response.json()

    def delete_branch(self, repo: str, branch: str) -> Dict[str, Any]:
        project = quote(repo, safe="")
        encoded_branch = quote(branch, safe="")
        with httpx.Client(timeout=30.0, headers=self._headers()) as client:
            response = request_with_retry(
                client,
                "DELETE",
                f"{self.base_url}/api/v4/projects/{project}/repository/branches/{encoded_branch}",
            )
            if response.status_code == 404:
                return {"branch": branch, "already_absent": True}
            response.raise_for_status()
            return {"branch": branch, "deleted": True}

    def commit_files(
        self,
        repo: str,
        branch: str,
        message: str,
        files: Dict[str, str],
    ) -> Dict[str, Any]:
        project = quote(repo, safe="")
        with httpx.Client(timeout=30.0, headers=self._headers()) as client:
            actions = []
            for path, content in files.items():
                file_path = quote(path, safe="")
                existing = client.get(
                    f"{self.base_url}/api/v4/projects/{project}/repository/files/{file_path}",
                    params={"ref": branch},
                )
                actions.append(
                    {
                        "action": "update" if existing.status_code == 200 else "create",
                        "file_path": path,
                        "content": content,
                    }
                )
            response = client.post(
                f"{self.base_url}/api/v4/projects/{project}/repository/commits",
                json={"branch": branch, "commit_message": message, "actions": actions},
            )
            response.raise_for_status()
            return response.json()

    def create_merge_request(self, repo: str, source_branch: str, target_branch: str, title: str, body: str) -> Dict[str, Any]:
        project = quote(repo, safe="")
        with httpx.Client(timeout=30.0, headers=self._headers()) as client:
            response = client.post(
                f"{self.base_url}/api/v4/projects/{project}/merge_requests",
                json={
                    "source_branch": source_branch,
                    "target_branch": target_branch,
                    "title": title,
                    "description": body,
                },
            )
            response.raise_for_status()
            return response.json()

    def sync_wiki_pages(self, repo: str, pages: Dict[str, str]) -> Dict[str, Any]:
        project = quote(repo, safe="")
        synced = []
        with httpx.Client(timeout=30.0, headers=self._headers()) as client:
            for filename, content in pages.items():
                title = filename.rsplit(".", 1)[0]
                slug = quote(title, safe="")
                existing = client.get(f"{self.base_url}/api/v4/projects/{project}/wikis/{slug}")
                payload = {"title": title, "content": content, "format": "markdown"}
                if existing.status_code == 200:
                    response = request_with_retry(
                        client,
                        "PUT",
                        f"{self.base_url}/api/v4/projects/{project}/wikis/{slug}",
                        json=payload,
                    )
                else:
                    response = request_with_retry(
                        client,
                        "POST",
                        f"{self.base_url}/api/v4/projects/{project}/wikis",
                        json=payload,
                    )
                response.raise_for_status()
                synced.append(response.json())
        return {"pages": len(synced), "target": "gitlab-wiki", "items": synced}

    def get_policy_status(self, repo: str, default_branch: str = "main") -> Dict[str, Any]:
        project = quote(repo, safe="")
        with httpx.Client(timeout=30.0, headers=self._headers()) as client:
            protected = self._list_pages(client, f"{self.base_url}/api/v4/projects/{project}/protected_branches")
            approvals = self._json_or_empty(client.get(f"{self.base_url}/api/v4/projects/{project}/approvals"))
            approval_rules = self._list_pages(client, f"{self.base_url}/api/v4/projects/{project}/approval_rules")
            project_data = self._json_or_empty(client.get(f"{self.base_url}/api/v4/projects/{project}"))
            environments = self._list_pages(client, f"{self.base_url}/api/v4/projects/{project}/protected_environments")
        protected_names = [item.get("name") for item in protected if isinstance(item, dict)]
        approvals_before_merge = approvals.get("approvals_before_merge", 0) if isinstance(approvals, dict) else 0
        return {
            "protected_branches": default_branch in protected_names or bool(protected),
            "approval_rules": bool(approval_rules) or approvals_before_merge > 0,
            "only_allow_merge_if_pipeline_succeeds": bool(project_data.get("only_allow_merge_if_pipeline_succeeds")),
            "protected_environments": bool(environments),
            "protected_environment_count": len(environments),
            "protected_branch_count": len(protected),
            "protected_branch_names": protected_names,
        }

    def get_security_findings(self, repo: str) -> List[Dict[str, Any]]:
        project = quote(repo, safe="")
        with httpx.Client(timeout=30.0, headers=self._headers()) as client:
            findings = self._list_pages(
                client,
                f"{self.base_url}/api/v4/projects/{project}/vulnerability_findings",
                {"scope": "all"},
            )
            vulnerabilities = self._list_pages(
                client,
                f"{self.base_url}/api/v4/projects/{project}/vulnerabilities",
                {"scope": "all"},
            )
            dependencies = self._list_pages(client, f"{self.base_url}/api/v4/projects/{project}/dependencies")
        result = []
        if isinstance(findings, list):
            result.extend({"source": "gitlab-vulnerability-finding", **item} for item in findings)
        if isinstance(vulnerabilities, list):
            result.extend({"source": "gitlab-vulnerability", **item} for item in vulnerabilities)
        if isinstance(dependencies, list):
            result.extend({"source": "gitlab-dependency", **item} for item in dependencies)
        return result

    def get_file(self, repo: str, path: str, ref: str = "main") -> Optional[str]:
        project = quote(repo, safe="")
        file_path = quote(path, safe="")
        with httpx.Client(timeout=30.0, headers=self._headers()) as client:
            response = client.get(
                f"{self.base_url}/api/v4/projects/{project}/repository/files/{file_path}/raw",
                params={"ref": ref},
            )
            if response.status_code == 404:
                return None
            response.raise_for_status()
            return response.text

    def list_ci_runs(self, repo: str, ref: str = "main") -> List[Dict[str, Any]]:
        project = quote(repo, safe="")
        with httpx.Client(timeout=30.0, headers=self._headers()) as client:
            data = self._json_or_empty(
                client.get(f"{self.base_url}/api/v4/projects/{project}/pipelines", params={"ref": ref, "per_page": 20})
            )
        return data if isinstance(data, list) else []

    def list_ci_jobs(self, repo: str, run_id: str) -> List[Dict[str, Any]]:
        project = quote(repo, safe="")
        with httpx.Client(timeout=30.0, headers=self._headers()) as client:
            data = self._json_or_empty(
                client.get(f"{self.base_url}/api/v4/projects/{project}/pipelines/{run_id}/jobs", params={"per_page": 100})
            )
        return data if isinstance(data, list) else []

    def wait_for_ci(self, repo: str, ref: str = "main", timeout_seconds: int = 900, poll_seconds: int = 15) -> Dict[str, Any]:
        deadline = time.monotonic() + timeout_seconds
        last_run: Dict[str, Any] = {}
        while time.monotonic() <= deadline:
            runs = self.list_ci_runs(repo, ref)
            if runs:
                last_run = runs[0]
                if last_run.get("status") in {"success", "failed", "canceled", "skipped", "manual"}:
                    return {"completed": True, "run": last_run, "jobs": self.list_ci_jobs(repo, str(last_run.get("id")))}
            time.sleep(max(1, poll_seconds))
        return {"completed": False, "run": last_run, "jobs": []}

    def download_ci_artifacts(self, repo: str, jobs: List[Dict[str, Any]]) -> Dict[str, bytes]:
        project = quote(repo, safe="")
        artifacts: Dict[str, bytes] = {}
        with httpx.Client(timeout=60.0, headers=self._headers()) as client:
            for job in jobs:
                if not job.get("artifacts_file") and not job.get("artifacts"):
                    continue
                job_id = job.get("id")
                response = client.get(f"{self.base_url}/api/v4/projects/{project}/jobs/{job_id}/artifacts")
                if response.status_code == 200:
                    artifacts[f"gitlab-job-{job_id}-artifacts.zip"] = response.content
        return artifacts

    def file_history(self, repo: str, path: str, ref: str = "main", limit: int = 20) -> List[Dict[str, Any]]:
        project = quote(repo, safe="")
        with httpx.Client(timeout=30.0, headers=self._headers()) as client:
            data = self._json_or_empty(
                request_with_retry(
                    client,
                    "GET",
                    f"{self.base_url}/api/v4/projects/{project}/repository/commits",
                    params={"ref_name": ref, "path": path, "per_page": min(limit, 100)},
                )
            )
        return data if isinstance(data, list) else []

    def file_blame(
        self,
        repo: str,
        path: str,
        ref: str = "main",
        start_line: Optional[int] = None,
        end_line: Optional[int] = None,
    ) -> List[Dict[str, Any]]:
        project = quote(repo, safe="")
        file_path = quote(path, safe="")
        params: Dict[str, Any] = {"ref": ref}
        if start_line:
            params["range[start]"] = start_line
        if end_line:
            params["range[end]"] = end_line
        with httpx.Client(timeout=30.0, headers=self._headers()) as client:
            data = self._json_or_empty(
                request_with_retry(
                    client,
                    "GET",
                    f"{self.base_url}/api/v4/projects/{project}/repository/files/{file_path}/blame",
                    params=params,
                )
            )
        return data if isinstance(data, list) else []

    def commit_diff(self, repo: str, commit_sha: str) -> List[Dict[str, Any]]:
        project = quote(repo, safe="")
        with httpx.Client(timeout=30.0, headers=self._headers()) as client:
            data = self._json_or_empty(
                request_with_retry(client, "GET", f"{self.base_url}/api/v4/projects/{project}/repository/commits/{commit_sha}/diff")
            )
        return data if isinstance(data, list) else []

    def merge_requests_for_commit(self, repo: str, commit_sha: str) -> List[Dict[str, Any]]:
        project = quote(repo, safe="")
        with httpx.Client(timeout=30.0, headers=self._headers()) as client:
            data = self._json_or_empty(
                request_with_retry(
                    client,
                    "GET",
                    f"{self.base_url}/api/v4/projects/{project}/repository/commits/{commit_sha}/merge_requests",
                )
            )
        return data if isinstance(data, list) else []

    def _headers(self) -> Dict[str, str]:
        return {"PRIVATE-TOKEN": self.token} if self.token else {}

    def _resolve_assignee_ids(self, client: httpx.Client, assignees: List[str]) -> List[int]:
        ids: List[int] = []
        for assignee in assignees:
            value = str(assignee or "").strip().lstrip("@")
            if not value or value == "unassigned":
                continue
            if value.isdigit():
                ids.append(int(value))
                continue
            users = self._json_or_empty(
                request_with_retry(client, "GET", f"{self.base_url}/api/v4/users", params={"username": value})
            )
            if not users:
                users = self._json_or_empty(
                    request_with_retry(client, "GET", f"{self.base_url}/api/v4/users", params={"search": value})
                )
            fallback_id: int | None = None
            for user in users if isinstance(users, list) else []:
                username = str(user.get("username") or "")
                name = str(user.get("name") or "")
                user_id = user.get("id")
                if isinstance(user_id, int) and fallback_id is None:
                    fallback_id = user_id
                if isinstance(user_id, int) and (username == value or name == value):
                    ids.append(user_id)
                    break
            else:
                if fallback_id is not None:
                    ids.append(fallback_id)
        return ids

    def _list_pages(
        self,
        client: httpx.Client,
        url: str,
        params: Optional[Dict[str, Any]] = None,
        max_pages: int = 5,
    ) -> List[Dict[str, Any]]:
        items: List[Dict[str, Any]] = []
        base_params = dict(params or {})
        for page in range(1, max_pages + 1):
            response = request_with_retry(client, "GET", url, params={**base_params, "per_page": 100, "page": page})
            data = self._json_or_empty(response)
            if not isinstance(data, list):
                break
            items.extend(item for item in data if isinstance(item, dict))
            if len(data) < 100:
                break
        return items

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
            metadata={
                "source_url": mr.get("web_url"),
                "provider_state": mr.get("state"),
                "author": (mr.get("author") or {}).get("username") or "",
                "changes": [
                    {
                        "path": change.get("new_path") or change.get("old_path"),
                        "old_path": change.get("old_path"),
                        "new_path": change.get("new_path"),
                        "diff": change.get("diff", "")[:20000],
                    }
                    for change in changes.get("changes", [])
                    if isinstance(change, dict)
                ],
            },
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
                response = request_with_retry(
                    client,
                    "GET",
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

    def comment_on_change(self, repo: str, mr_id: str, body: str) -> Dict[str, Any]:
        with httpx.Client(timeout=30.0, headers=self._headers()) as client:
            response = client.post(
                f"{self.base_url}/repos/{repo}/issues/{mr_id}/comments",
                json={"body": body},
            )
            response.raise_for_status()
            return response.json()

    def create_issue(
        self,
        repo: str,
        title: str,
        body: str,
        labels: Optional[List[str]] = None,
        assignees: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        with httpx.Client(timeout=30.0, headers=self._headers()) as client:
            payload: Dict[str, Any] = {"title": title, "body": body, "labels": labels or []}
            if assignees:
                payload["assignees"] = [name.lstrip("@") for name in assignees if name and name != "unassigned"]
            response = client.post(
                f"{self.base_url}/repos/{repo}/issues",
                json=payload,
            )
            response.raise_for_status()
            return response.json()

    def list_issues(
        self,
        repo: str,
        labels: Optional[List[str]] = None,
        state: str = "open",
        limit: int = 50,
    ) -> List[Dict[str, Any]]:
        params: Dict[str, Any] = {"state": state, "sort": "updated", "direction": "desc"}
        if labels:
            params["labels"] = ",".join(labels)
        with httpx.Client(timeout=30.0, headers=self._headers()) as client:
            return self._list_pages(
                client,
                f"{self.base_url}/repos/{repo}/issues",
                params,
                max_pages=max(1, (limit + 99) // 100),
            )[:limit]

    def comment_on_issue(self, repo: str, issue_id: str, body: str) -> Dict[str, Any]:
        with httpx.Client(timeout=30.0, headers=self._headers()) as client:
            response = request_with_retry(
                client,
                "POST",
                f"{self.base_url}/repos/{repo}/issues/{issue_id}/comments",
                json={"body": body},
            )
            response.raise_for_status()
            return response.json()

    def close_issue(self, repo: str, issue_id: str) -> Dict[str, Any]:
        with httpx.Client(timeout=30.0, headers=self._headers()) as client:
            response = request_with_retry(
                client,
                "PATCH",
                f"{self.base_url}/repos/{repo}/issues/{issue_id}",
                json={"state": "closed"},
            )
            response.raise_for_status()
            return response.json()

    def issue_linked_changes(self, repo: str, issue_id: str) -> List[Dict[str, Any]]:
        headers = self._headers() | {"Accept": "application/vnd.github+json"}
        linked = []
        with httpx.Client(timeout=30.0, headers=headers) as client:
            timeline = self._json_or_empty(
                request_with_retry(
                    client,
                    "GET",
                    f"{self.base_url}/repos/{repo}/issues/{issue_id}/timeline",
                    params={"per_page": 100},
                )
            )
        for event in timeline if isinstance(timeline, list) else []:
            source = event.get("source", {}) if isinstance(event, dict) else {}
            issue = source.get("issue", {}) if isinstance(source, dict) else {}
            if issue.get("pull_request"):
                linked.append(issue)
        return linked

    def create_branch(self, repo: str, branch: str, ref: str = "main") -> Dict[str, Any]:
        with httpx.Client(timeout=30.0, headers=self._headers()) as client:
            ref_response = client.get(f"{self.base_url}/repos/{repo}/git/ref/heads/{ref}")
            ref_response.raise_for_status()
            sha = ref_response.json()["object"]["sha"]
            response = client.post(
                f"{self.base_url}/repos/{repo}/git/refs",
                json={"ref": f"refs/heads/{branch}", "sha": sha},
            )
            if response.status_code == 422 and "already_exists" in response.text.lower():
                return {"ref": f"refs/heads/{branch}", "already_exists": True}
            response.raise_for_status()
            return response.json()

    def delete_branch(self, repo: str, branch: str) -> Dict[str, Any]:
        with httpx.Client(timeout=30.0, headers=self._headers()) as client:
            response = request_with_retry(
                client,
                "DELETE",
                f"{self.base_url}/repos/{repo}/git/refs/heads/{quote(branch, safe='/')}",
            )
            if response.status_code == 404:
                return {"branch": branch, "already_absent": True}
            response.raise_for_status()
            return {"branch": branch, "deleted": True}

    def commit_files(self, repo: str, branch: str, message: str, files: Dict[str, str]) -> Dict[str, Any]:
        with httpx.Client(timeout=30.0, headers=self._headers()) as client:
            results = {}
            for path, content in files.items():
                existing = client.get(f"{self.base_url}/repos/{repo}/contents/{path}", params={"ref": branch})
                payload = {"message": message, "content": _b64(content), "branch": branch}
                if existing.status_code == 200:
                    payload["sha"] = existing.json().get("sha")
                response = client.put(f"{self.base_url}/repos/{repo}/contents/{path}", json=payload)
                response.raise_for_status()
                results[path] = response.json()
        return {"files": results}

    def create_merge_request(self, repo: str, source_branch: str, target_branch: str, title: str, body: str) -> Dict[str, Any]:
        with httpx.Client(timeout=30.0, headers=self._headers()) as client:
            response = client.post(
                f"{self.base_url}/repos/{repo}/pulls",
                json={"head": source_branch, "base": target_branch, "title": title, "body": body},
            )
            response.raise_for_status()
            return response.json()

    def sync_wiki_pages(self, repo: str, pages: Dict[str, str]) -> Dict[str, Any]:
        files = {f"docs/sentinelgraph-memory/{path}": content for path, content in pages.items()}
        result = self.commit_files(repo, "main", "docs: sync SentinelGraph security memory pages", files)
        return {
            "pages": len(files),
            "target": "github-repo-docs",
            "note": "GitHub wiki is a separate git repository; pages were synced to repo docs for API-only operation.",
            "result": result,
        }

    def get_policy_status(self, repo: str, default_branch: str = "main") -> Dict[str, Any]:
        with httpx.Client(timeout=30.0, headers=self._headers()) as client:
            branch = self._json_or_empty(client.get(f"{self.base_url}/repos/{repo}/branches/{quote(default_branch, safe='')}/protection"))
            repo_data = self._json_or_empty(client.get(f"{self.base_url}/repos/{repo}"))
            environments = self._json_or_empty(client.get(f"{self.base_url}/repos/{repo}/environments"))
            environment_details = []
            for environment in (environments or {}).get("environments", []) if isinstance(environments, dict) else []:
                name = environment.get("name")
                if not name:
                    continue
                detail = self._json_or_empty(
                    client.get(f"{self.base_url}/repos/{repo}/environments/{quote(name, safe='')}")
                )
                if isinstance(detail, dict):
                    environment_details.append(detail)
                else:
                    environment_details.append(environment)
        protected_environments = [
            item
            for item in environment_details
            if item.get("protection_rules") or item.get("deployment_branch_policy")
        ]
        return {
            "protected_branches": bool(branch),
            "approval_rules": bool(branch.get("required_pull_request_reviews")) if isinstance(branch, dict) else False,
            "only_allow_merge_if_pipeline_succeeds": bool(branch.get("required_status_checks")) if isinstance(branch, dict) else False,
            "protected_environments": bool(protected_environments),
            "protected_environment_count": len(protected_environments),
            "environment_count": len(environment_details),
            "private": bool(repo_data.get("private")) if isinstance(repo_data, dict) else False,
        }

    def get_security_findings(self, repo: str) -> List[Dict[str, Any]]:
        with httpx.Client(timeout=30.0, headers=self._headers()) as client:
            code_scanning = self._list_pages(
                client,
                f"{self.base_url}/repos/{repo}/code-scanning/alerts",
                {"state": "open"},
            )
            dependabot = self._list_pages(
                client,
                f"{self.base_url}/repos/{repo}/dependabot/alerts",
                {"state": "open"},
            )
            secrets = self._list_pages(
                client,
                f"{self.base_url}/repos/{repo}/secret-scanning/alerts",
                {"state": "open"},
            )
        result = []
        if isinstance(code_scanning, list):
            result.extend({"source": "github-code-scanning", **item} for item in code_scanning)
        if isinstance(dependabot, list):
            result.extend({"source": "github-dependabot", **item} for item in dependabot)
        if isinstance(secrets, list):
            result.extend({"source": "github-secret-scanning", **item} for item in secrets)
        return result

    def get_file(self, repo: str, path: str, ref: str = "main") -> Optional[str]:
        with httpx.Client(timeout=30.0, headers=self._headers()) as client:
            response = client.get(f"{self.base_url}/repos/{repo}/contents/{path}", params={"ref": ref})
            if response.status_code == 404:
                return None
            response.raise_for_status()
            data = response.json()
            content = data.get("content")
            if content:
                return b64decode(content).decode("utf-8", errors="replace")
            return None

    def list_ci_runs(self, repo: str, ref: str = "main") -> List[Dict[str, Any]]:
        with httpx.Client(timeout=30.0, headers=self._headers()) as client:
            data = self._json_or_empty(
                client.get(f"{self.base_url}/repos/{repo}/actions/runs", params={"branch": ref, "per_page": 20})
            )
        if isinstance(data, dict):
            return data.get("workflow_runs", [])
        return []

    def list_ci_jobs(self, repo: str, run_id: str) -> List[Dict[str, Any]]:
        with httpx.Client(timeout=30.0, headers=self._headers()) as client:
            data = self._json_or_empty(client.get(f"{self.base_url}/repos/{repo}/actions/runs/{run_id}/jobs", params={"per_page": 100}))
        if isinstance(data, dict):
            return data.get("jobs", [])
        return []

    def wait_for_ci(self, repo: str, ref: str = "main", timeout_seconds: int = 900, poll_seconds: int = 15) -> Dict[str, Any]:
        deadline = time.monotonic() + timeout_seconds
        last_run: Dict[str, Any] = {}
        while time.monotonic() <= deadline:
            runs = self.list_ci_runs(repo, ref)
            if runs:
                last_run = runs[0]
                if last_run.get("status") == "completed":
                    return {"completed": True, "run": last_run, "jobs": self.list_ci_jobs(repo, str(last_run.get("id")))}
            time.sleep(max(1, poll_seconds))
        return {"completed": False, "run": last_run, "jobs": []}

    def download_ci_artifacts(self, repo: str, run_id: str) -> Dict[str, bytes]:
        artifacts: Dict[str, bytes] = {}
        with httpx.Client(timeout=60.0, headers=self._headers(), follow_redirects=True) as client:
            listing = self._json_or_empty(client.get(f"{self.base_url}/repos/{repo}/actions/runs/{run_id}/artifacts"))
            for artifact in (listing or {}).get("artifacts", []) if isinstance(listing, dict) else []:
                archive_url = artifact.get("archive_download_url")
                if not archive_url:
                    continue
                response = client.get(archive_url)
                if response.status_code == 200:
                    artifacts[f"github-artifact-{artifact.get('id')}.zip"] = response.content
        return artifacts

    def file_history(self, repo: str, path: str, ref: str = "main", limit: int = 20) -> List[Dict[str, Any]]:
        with httpx.Client(timeout=30.0, headers=self._headers()) as client:
            data = self._json_or_empty(
                request_with_retry(
                    client,
                    "GET",
                    f"{self.base_url}/repos/{repo}/commits",
                    params={"sha": ref, "path": path, "per_page": min(limit, 100)},
                )
            )
        return data if isinstance(data, list) else []

    def file_blame(
        self,
        repo: str,
        path: str,
        ref: str = "main",
        start_line: Optional[int] = None,
        end_line: Optional[int] = None,
    ) -> List[Dict[str, Any]]:
        commits = self.file_history(repo, path, ref, limit=1)
        if not commits:
            return []
        return [{"commit": commits[0], "lines": [{"line_number": start_line, "content": ""}], "source": "github-history-fallback"}]

    def commit_diff(self, repo: str, commit_sha: str) -> List[Dict[str, Any]]:
        headers = self._headers() | {"Accept": "application/vnd.github+json"}
        with httpx.Client(timeout=30.0, headers=headers) as client:
            data = self._json_or_empty(
                request_with_retry(client, "GET", f"{self.base_url}/repos/{repo}/commits/{commit_sha}")
            )
        files = data.get("files") if isinstance(data, dict) else []
        return files if isinstance(files, list) else []

    def merge_requests_for_commit(self, repo: str, commit_sha: str) -> List[Dict[str, Any]]:
        headers = self._headers() | {"Accept": "application/vnd.github.groot-preview+json"}
        with httpx.Client(timeout=30.0, headers=headers) as client:
            data = self._json_or_empty(
                request_with_retry(client, "GET", f"{self.base_url}/repos/{repo}/commits/{commit_sha}/pulls")
            )
        return data if isinstance(data, list) else []

    def _headers(self) -> Dict[str, str]:
        headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        return headers

    def _list_pages(
        self,
        client: httpx.Client,
        url: str,
        params: Optional[Dict[str, Any]] = None,
        max_pages: int = 5,
    ) -> List[Dict[str, Any]]:
        items: List[Dict[str, Any]] = []
        base_params = dict(params or {})
        for page in range(1, max_pages + 1):
            data = self._json_or_empty(request_with_retry(client, "GET", url, params={**base_params, "per_page": 100, "page": page}))
            if not isinstance(data, list):
                break
            items.extend(item for item in data if isinstance(item, dict))
            if len(data) < 100:
                break
        return items

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
            metadata={
                "source_url": pr.get("html_url"),
                "provider_state": pr.get("state"),
                "author": (pr.get("user") or {}).get("login") or "",
                "changes": [
                    {
                        "path": item.get("filename"),
                        "old_path": item.get("previous_filename"),
                        "new_path": item.get("filename"),
                        "patch": item.get("patch", "")[:20000],
                        "additions": item.get("additions"),
                        "deletions": item.get("deletions"),
                    }
                    for item in files
                    if isinstance(item, dict)
                ],
            },
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
                    author=record.author,
                    title=record.title,
                    files_changed=record.files_changed,
                    commits=record.commits,
                    merged_at=record.merged_at,
                    diff_summary=record.diff_summary,
                    labels=record.labels,
                    source_url=record.metadata.get("source_url"),
                    comments=[comment.model_dump() for comment in record.comments],
                    metadata=record.metadata,
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
    sources = [
        ("description", "description", record.description),
        ("title", "title", record.title),
    ] + [(comment.id, comment.author, comment.body) for comment in record.comments]
    for idx, (source_id, author, raw_body) in enumerate(sources, start=1):
        body = str(raw_body or "").strip()
        lower = body.lower()
        if not any(marker in lower for marker in DECISION_MARKERS) and not semantic_decision_signal(lower):
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
                    "source_id": source_id,
                    "author": author,
                },
            )
        )
    return decisions


def semantic_decision_signal(text: str) -> bool:
    return any(
        phrase in text
        for phrase in [
            "must require",
            "must not",
            "never allow",
            "deny by default",
            "security owner",
            "encryption at rest",
            "parameterized queries",
            "negative tests",
        ]
    )


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


def _b64(content: str) -> str:
    return b64encode(content.encode("utf-8")).decode("ascii")
