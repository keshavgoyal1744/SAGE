"""Provider writeback helper."""

from __future__ import annotations

import os
from typing import Dict, List, Optional

from .models import ProviderTarget, WritebackAction
from .source_control import GitHubClient, GitLabClient


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

    def create_issue(self, title: str, body: str, labels: Optional[List[str]] = None) -> WritebackAction:
        return self.plan_or_call(
            "create_issue",
            {"title": title, "body": body, "labels": labels or []},
            lambda: self.client.create_issue(self.target.repo, title, body, labels),
        )

    def comment_on_change(self, change_id: str, body: str) -> WritebackAction:
        return self.plan_or_call(
            "comment_on_change",
            {"change_id": change_id, "body": body},
            lambda: self.client.comment_on_change(self.target.repo, change_id, body),
        )

    def policy_status(self) -> Dict[str, object]:
        if self.target.dry_run or self.client is None:
            return {
                "protected_branches": False,
                "approval_rules": False,
                "only_allow_merge_if_pipeline_succeeds": False,
                "protected_environments": False,
                "source": "dry-run",
            }
        return self.client.get_policy_status(self.target.repo)

    def security_findings(self) -> List[Dict[str, object]]:
        if self.target.dry_run or self.client is None:
            return []
        return self.client.get_security_findings(self.target.repo)
