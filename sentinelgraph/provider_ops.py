"""Provider writeback helper."""

from __future__ import annotations

import os
from typing import Dict, List, Optional

from .models import ProviderTarget, WritebackAction
from .source_control import GitHubClient, GitLabClient
from .utils import stable_id


class ProviderOps:
    def __init__(self, target: ProviderTarget):
        self.target = target
        token = target.token or (os.environ.get(target.token_env) if target.token_env else None)
        if not token:
            token = os.environ.get("GITLAB_TOKEN" if target.provider == "gitlab" else "GITHUB_TOKEN")
        self.token = token
        if target.provider == "gitlab":
            self.client = GitLabClient(token=token, base_url=target.base_url or "https://gitlab.com")
        elif target.provider == "github":
            self.client = GitHubClient(token=token, base_url=target.base_url or "https://api.github.com")
        else:
            self.client = None

    def plan_or_call(self, action: str, payload: Dict[str, object], fn=None) -> WritebackAction:
        if self.target.dry_run or self.client is None or fn is None:
            return WritebackAction(
                action=action,
                provider=self.target.provider,
                repo=self.target.repo,
                status="planned",
                payload=payload,
            )
        try:
            result = fn()
            return WritebackAction(
                action=action,
                provider=self.target.provider,
                repo=self.target.repo,
                status="created",
                url=result.get("web_url") or result.get("html_url") or result.get("url"),
                payload=result,
            )
        except Exception as exc:
            return WritebackAction(
                action=action,
                provider=self.target.provider,
                repo=self.target.repo,
                status="failed",
                payload=payload,
                error=str(exc),
            )

    def create_branch(self, branch: str, ref: str = "main") -> WritebackAction:
        return self.plan_or_call(
            "create_branch",
            {"branch": branch, "ref": ref},
            lambda: self.client.create_branch(self.target.repo, branch, ref),
        )

    def delete_branch(self, branch: str) -> WritebackAction:
        return self.plan_or_call(
            "delete_branch",
            {"branch": branch},
            lambda: self.client.delete_branch(self.target.repo, branch),
        )

    def commit_files(self, branch: str, message: str, files: Dict[str, str]) -> WritebackAction:
        return self.plan_or_call(
            "commit_files",
            {"branch": branch, "message": message, "files": sorted(files)},
            lambda: self.client.commit_files(self.target.repo, branch, message, files),
        )

    def create_change_request(self, source_branch: str, target_branch: str, title: str, body: str) -> WritebackAction:
        return self.plan_or_call(
            "create_change_request",
            {"source_branch": source_branch, "target_branch": target_branch, "title": title, "body": body},
            lambda: self.client.create_merge_request(self.target.repo, source_branch, target_branch, title, body),
        )

    def create_issue(
        self,
        title: str,
        body: str,
        labels: Optional[List[str]] = None,
        assignees: Optional[List[str]] = None,
    ) -> WritebackAction:
        return self.plan_or_call(
            "create_issue",
            {"title": title, "body": body, "labels": labels or [], "assignees": assignees or []},
            lambda: self.client.create_issue(self.target.repo, title, body, labels, assignees),
        )

    def create_issue_once(
        self,
        title: str,
        body: str,
        labels: Optional[List[str]] = None,
        assignees: Optional[List[str]] = None,
        fingerprint_parts: Optional[List[object]] = None,
    ) -> WritebackAction:
        fingerprint = stable_id("issue", self.target.repo, *(fingerprint_parts or [title]))
        marker = f"SentinelGraph-Fingerprint: {fingerprint}"
        marked_body = body if marker in body else f"{body.rstrip()}\n\n<!-- {marker} -->\n"
        if not self.target.dry_run and self.client is not None:
            try:
                for issue in self.list_issues(labels, state="opened", limit=100):
                    issue_text = f"{issue.get('title')} {issue.get('description') or issue.get('body')}"
                    if marker in issue_text or issue.get("title") == title:
                        return WritebackAction(
                            action="create_issue",
                            provider=self.target.provider,
                            repo=self.target.repo,
                            status="skipped",
                            url=issue.get("web_url") or issue.get("html_url") or issue.get("url"),
                            payload={"reason": "existing_issue", "fingerprint": fingerprint, "issue": issue},
                        )
            except Exception:
                pass
        action = self.create_issue(title, marked_body, labels, assignees)
        action.payload.setdefault("fingerprint", fingerprint)
        return action

    def sync_wiki_pages(self, pages: Dict[str, str]) -> WritebackAction:
        return self.plan_or_call(
            "sync_wiki_pages",
            {"pages": sorted(pages)},
            lambda: self.client.sync_wiki_pages(self.target.repo, pages),
        )

    def list_issues(self, labels: Optional[List[str]] = None, state: str = "opened", limit: int = 50) -> List[Dict[str, object]]:
        if self.target.dry_run or self.client is None:
            return []
        provider_state = "open" if self.target.provider == "github" and state == "opened" else state
        return self.client.list_issues(self.target.repo, labels, provider_state, limit)

    def comment_on_issue(self, issue_id: str, body: str) -> WritebackAction:
        return self.plan_or_call(
            "comment_on_issue",
            {"issue_id": issue_id, "body": body},
            lambda: self.client.comment_on_issue(self.target.repo, issue_id, body),
        )

    def close_issue(self, issue_id: str) -> WritebackAction:
        return self.plan_or_call(
            "close_issue",
            {"issue_id": issue_id},
            lambda: self.client.close_issue(self.target.repo, issue_id),
        )

    def issue_linked_changes(self, issue_id: str) -> List[Dict[str, object]]:
        if self.target.dry_run or self.client is None:
            return []
        return self.client.issue_linked_changes(self.target.repo, issue_id)

    def comment_on_change(self, change_id: str, body: str) -> WritebackAction:
        return self.plan_or_call(
            "comment_on_change",
            {"change_id": change_id, "body": body},
            lambda: self.client.comment_on_change(self.target.repo, change_id, body),
        )

    def policy_status(self, default_branch: str = "main") -> Dict[str, object]:
        if self.target.dry_run or self.client is None:
            return {
                "protected_branches": False,
                "approval_rules": False,
                "only_allow_merge_if_pipeline_succeeds": False,
                "protected_environments": False,
                "source": "dry-run",
            }
        return self.client.get_policy_status(self.target.repo, default_branch)

    def security_findings(self) -> List[Dict[str, object]]:
        if self.target.dry_run or self.client is None:
            return []
        return self.client.get_security_findings(self.target.repo)

    def get_file(self, path: str, ref: str = "main") -> Optional[str]:
        if self.target.dry_run or self.client is None:
            return None
        return self.client.get_file(self.target.repo, path, ref)

    def file_history(self, path: str, ref: str = "main", limit: int = 20) -> List[Dict[str, object]]:
        if self.target.dry_run or self.client is None:
            return []
        return self.client.file_history(self.target.repo, path, ref, limit)

    def file_blame(
        self,
        path: str,
        ref: str = "main",
        start_line: Optional[int] = None,
        end_line: Optional[int] = None,
    ) -> List[Dict[str, object]]:
        if self.target.dry_run or self.client is None:
            return []
        return self.client.file_blame(self.target.repo, path, ref, start_line, end_line)

    def commit_diff(self, commit_sha: str) -> List[Dict[str, object]]:
        if self.target.dry_run or self.client is None:
            return []
        return self.client.commit_diff(self.target.repo, commit_sha)

    def merge_requests_for_commit(self, commit_sha: str) -> List[Dict[str, object]]:
        if self.target.dry_run or self.client is None:
            return []
        return self.client.merge_requests_for_commit(self.target.repo, commit_sha)

    def wait_for_ci(self, ref: str = "main", timeout_seconds: int = 900, poll_seconds: int = 15) -> Dict[str, object]:
        if self.target.dry_run or self.client is None:
            return {
                "completed": True,
                "run": {"id": "dry-run", "status": "simulated", "conclusion": "success", "ref": ref},
                "jobs": [
                    {"id": "dry-sast", "name": "sast", "status": "success"},
                    {"id": "dry-secret", "name": "secret-detection", "status": "success"},
                ],
                "source": "dry-run",
            }
        return self.client.wait_for_ci(self.target.repo, ref, timeout_seconds, poll_seconds)

    def download_ci_artifacts(self, ci_result: Dict[str, object]) -> Dict[str, bytes]:
        if self.target.dry_run or self.client is None:
            return {}
        if self.target.provider == "gitlab":
            return self.client.download_ci_artifacts(self.target.repo, ci_result.get("jobs", []))
        run = ci_result.get("run", {})
        run_id = str(run.get("id") or "")
        if not run_id:
            return {}
        return self.client.download_ci_artifacts(self.target.repo, run_id)
