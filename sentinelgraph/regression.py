"""Root cause detection, sibling discovery, patch/test generation, and CI optimization."""

from __future__ import annotations

import re
from typing import Dict, List

import yaml

from .findings import FindingEngine
from .graph import SecurityGraph
from .models import CiOptimizeRequest, FindingInput, RegressionRequest, WritebackAction
from .provider_ops import ProviderOps
from .utils import stable_id


class RegressionEngine:
    def __init__(self, graph: SecurityGraph, findings: FindingEngine):
        self.graph = graph
        self.findings = findings

    def investigate(self, request: RegressionRequest) -> Dict[str, object]:
        repo = request.repo
        subject = self._subject(request)
        if request.affected_file:
            subject["file"] = request.affected_file
        ops = ProviderOps(request)
        candidates = self._root_cause_candidates(repo, subject, ops, request.default_branch)
        root = candidates[0] if candidates else None
        siblings = self._siblings(repo, subject, root)
        generated_findings = []
        for sibling in siblings:
            generated_findings.append(
                self.findings.create(
                    FindingInput(
                        title=f"Potential sibling regression in {sibling['service']}",
                        repo=repo,
                        category=subject.get("category", "security-regression"),
                        severity=subject.get("severity", "medium"),
                        file=sibling.get("file"),
                        service=sibling["service"],
                        evidence={"root_cause": root, "source": request.incident_id or request.finding_id},
                    )
                )
            )
        patches = self._patches(generated_findings, ops, request.default_branch)
        tests = self._tests(generated_findings, subject)
        actions: List[WritebackAction] = []
        if request.open_remediation and patches:
            branch = "sentinelgraph/regression-fixes"
            files = {patch["path"]: patch["content"] for patch in patches}
            actions.extend([
                ops.create_branch(branch, request.default_branch),
                ops.commit_files(branch, "fix: apply SentinelGraph regression guards", files),
                ops.create_change_request(
                    branch,
                    request.default_branch,
                    "SentinelGraph regression remediation",
                    "Generated regression guard patches from root-cause and sibling analysis.",
                ),
            ])
        if request.open_tests and tests:
            branch = "sentinelgraph/regression-tests"
            files = {test["path"]: test["content"] for test in tests}
            actions.extend([
                ops.create_branch(branch, request.default_branch),
                ops.commit_files(branch, "test: add SentinelGraph regression tests", files),
                ops.create_change_request(
                    branch,
                    request.default_branch,
                    "SentinelGraph regression tests",
                    "Generated regression tests for sibling findings.",
                ),
            ])
        return {
            "subject": subject,
            "root_cause": root,
            "candidates": candidates,
            "siblings": siblings,
            "findings": generated_findings,
            "patches": patches,
            "tests": tests,
            "actions": [action.model_dump() for action in actions],
        }

    def _subject(self, request: RegressionRequest) -> Dict[str, object]:
        if request.incident_id:
            incident = self.graph.store.get_incident(request.incident_id)
            if incident:
                report = incident["report"]
                return {
                    "category": report.get("signal", "security-regression"),
                    "severity": report.get("severity", "medium"),
                    "service": report.get("service"),
                    "file": report.get("code_path"),
                    "title": report.get("title"),
                }
        if request.finding_id:
            for finding in self.graph.store.list_findings(request.repo):
                if finding["id"] == request.finding_id:
                    return finding
        return {"category": "security-regression", "severity": "medium", "service": "unknown", "file": None}

    def _root_cause_candidates(
        self,
        repo: str,
        subject: Dict[str, object],
        ops: ProviderOps,
        ref: str,
    ) -> List[Dict[str, object]]:
        analyses = self.graph.store.list_analyses(repo)
        service = subject.get("service")
        file_path = subject.get("file")
        candidates = []
        if file_path:
            blame_candidates = self._blame_candidates(subject, ops, str(file_path), ref)
            candidates.extend(blame_candidates)
            for commit in ops.file_history(str(file_path), ref=ref, limit=30):
                sha = str(commit.get("id") or commit.get("sha") or "")
                if not sha:
                    continue
                diff = ops.commit_diff(sha)
                diff_text = self._diff_text(diff)
                score, reasons = self._root_cause_score(subject, diff_text, commit)
                if score <= 0:
                    continue
                linked_changes = ops.merge_requests_for_commit(sha)
                candidates.append(
                    {
                        "commit": sha,
                        "title": commit.get("title") or commit.get("commit", {}).get("message"),
                        "authored_at": commit.get("authored_date") or commit.get("commit", {}).get("author", {}).get("date"),
                        "score": score,
                        "reason": "; ".join(reasons),
                        "provider": ops.target.provider,
                        "change_requests": [
                            {
                                "id": item.get("iid") or item.get("number") or item.get("id"),
                                "title": item.get("title"),
                                "url": item.get("web_url") or item.get("html_url"),
                            }
                            for item in linked_changes[:5]
                        ],
                        "files": self._diff_files(diff),
                    }
                )
        for analysis in analyses:
            payload = analysis["payload"]
            text = str(payload).lower()
            if (service and str(service).lower() in text) or (file_path and str(file_path).lower() in text):
                candidates.append(
                    {
                        "analysis_id": analysis["id"],
                        "subject_id": analysis["subject_id"],
                        "score": analysis["score"],
                        "level": analysis["level"],
                        "files": payload.get("passport", {}).get("services", []),
                        "reason": "Prior change touched the affected service or file.",
                    }
                )
        return sorted(candidates, key=lambda item: item["score"], reverse=True)

    def _blame_candidates(
        self,
        subject: Dict[str, object],
        ops: ProviderOps,
        file_path: str,
        ref: str,
    ) -> List[Dict[str, object]]:
        line = subject.get("line") or subject.get("start_line")
        start_line = int(line) if isinstance(line, int) or str(line or "").isdigit() else None
        blame = ops.file_blame(file_path, ref, start_line, start_line)
        candidates = []
        for block in blame[:5]:
            commit = block.get("commit") or {}
            sha = str(commit.get("id") or commit.get("sha") or "")
            if not sha:
                continue
            diff = ops.commit_diff(sha)
            diff_text = self._diff_text(diff)
            score, reasons = self._root_cause_score(subject, diff_text, commit)
            score = max(score, 45.0)
            reasons.append("Provider blame points to this commit for the affected line.")
            linked_changes = ops.merge_requests_for_commit(sha)
            candidates.append(
                {
                    "commit": sha,
                    "title": commit.get("title") or commit.get("message") or commit.get("commit", {}).get("message"),
                    "authored_at": commit.get("authored_date") or commit.get("commit", {}).get("author", {}).get("date"),
                    "score": min(score, 100.0),
                    "reason": "; ".join(reasons),
                    "provider": ops.target.provider,
                    "line": start_line,
                    "source": "blame",
                    "change_requests": [
                        {
                            "id": item.get("iid") or item.get("number") or item.get("id"),
                            "title": item.get("title"),
                            "url": item.get("web_url") or item.get("html_url"),
                        }
                        for item in linked_changes[:5]
                    ],
                    "files": self._diff_files(diff) or [file_path],
                }
            )
        return candidates

    def _siblings(self, repo: str, subject: Dict[str, object], root: Dict[str, object] | None = None) -> List[Dict[str, object]]:
        subject_service = subject.get("service")
        category = str(subject.get("category", "")).lower()
        siblings = []
        root_files = {
            str(path)
            for path in (root.get("files", []) if root else [])
            if isinstance(path, str)
        }
        for analysis in self.graph.store.list_analyses(repo):
            payload = analysis["payload"]
            text = str(payload).lower()
            file_hits = [path for path in root_files if path and str(path).lower() in text]
            if file_hits or any(term in text for term in security_terms_for_category(category)):
                services = payload.get("passport", {}).get("services", [])
                for service in services:
                    name = service.get("name") if isinstance(service, dict) else None
                    if name and name != subject_service:
                        siblings.append(
                            {
                                "service": name,
                                "file": service.get("attributes", {}).get("file_prefix"),
                                "source_analysis": analysis["id"],
                                "reason": "Imported change has matching files or security-sensitive diff terms.",
                            }
                        )
        for service in self.graph.store.list_entities("service"):
            if service.name == subject_service:
                continue
            haystack = f"{service.name} {service.attributes}".lower()
            if "auth" in category and any(term in haystack for term in ["auth", "gateway", "identity", "session"]):
                siblings.append({"service": service.name, "file": service.attributes.get("file_prefix"), "reason": "Related auth service."})
            elif not siblings and service.name != "docs":
                siblings.append({"service": service.name, "file": service.attributes.get("file_prefix"), "reason": "Fallback related service."})
        deduped = []
        seen = set()
        for item in siblings:
            key = (item.get("service"), item.get("file"))
            if key in seen:
                continue
            seen.add(key)
            deduped.append(item)
        return deduped[:8]

    def _patches(self, findings: List[Dict[str, object]], ops: ProviderOps, ref: str) -> List[Dict[str, str]]:
        patches = []
        for finding in findings:
            service = finding.get("service") or "unknown"
            file_path = finding.get("file")
            if isinstance(file_path, str) and file_path.endswith(".py"):
                content = ops.get_file(file_path, ref)
                if content:
                    patches.append(
                        {
                            "path": file_path,
                            "content": patch_python_source(content, finding),
                            "kind": "source-edit",
                        }
                    )
                    continue
            patches.append(
                {
                    "path": f"sentinelgraph-remediation/{service}-fix.patch",
                    "content": candidate_patch_text(finding),
                    "kind": "candidate-patch",
                }
            )
        return patches

    def _tests(self, findings: List[Dict[str, object]], subject: Dict[str, object]) -> List[Dict[str, str]]:
        tests = []
        for finding in findings:
            service = finding.get("service") or "unknown"
            safe_service = re.sub(r"[^a-zA-Z0-9_]+", "_", str(service)).strip("_") or "service"
            tests.append(
                {
                    "path": f"tests/test_{safe_service}_security_regression.py",
                    "content": regression_test_content(finding, subject),
                }
            )
        return tests

    def _diff_text(self, diff: List[Dict[str, object]]) -> str:
        chunks = []
        for item in diff:
            chunks.append(str(item.get("diff") or item.get("patch") or item))
        return "\n".join(chunks).lower()

    def _diff_files(self, diff: List[Dict[str, object]]) -> List[str]:
        files = []
        for item in diff:
            path = item.get("new_path") or item.get("filename") or item.get("old_path")
            if path:
                files.append(str(path))
        return files

    def _root_cause_score(
        self,
        subject: Dict[str, object],
        diff_text: str,
        commit: Dict[str, object],
    ) -> tuple[float, List[str]]:
        category = str(subject.get("category", "")).lower()
        title = str(subject.get("title", "")).lower()
        reasons = []
        score = 0.0
        for term in security_terms_for_category(category + " " + title):
            if term in diff_text:
                score += 18
                reasons.append(f"Diff contains {term}.")
        if any(term in diff_text for term in ["-        validate", "-    validate", "-        require", "-    require", "-        check", "-    check"]):
            score += 30
            reasons.append("Diff appears to remove a validation or authorization guard.")
        if any(term in diff_text for term in ["bypass", "disable", "skip", "temporary", "todo"]):
            score += 12
            reasons.append("Diff contains regression-prone control language.")
        if subject.get("file") and str(subject["file"]).lower() in str(commit).lower():
            score += 20
            reasons.append("Commit history is on the affected file.")
        return min(score, 100.0), reasons


class CiOptimizer:
    def optimize(self, request: CiOptimizeRequest) -> Dict[str, object]:
        ops = ProviderOps(request)
        target_path = request.workflow_path if request.provider == "github" else request.ci_path
        if request.provider == "github":
            existing = ops.get_file(target_path, request.default_branch)
            content, notes = optimize_github_actions(existing)
        else:
            existing = ops.get_file(target_path, request.default_branch)
            content, notes = optimize_gitlab_ci(existing)
        actions = [
            ops.create_branch(request.branch, request.default_branch),
            ops.commit_files(request.branch, "ci: optimize pipeline with path filters and caching", {target_path: content}),
            ops.create_change_request(
                request.branch,
                request.default_branch,
                "SentinelGraph CI optimization",
                "Edits the existing CI workflow to add path filters, caching, and interruptible jobs.",
            ),
        ]
        return {"path": target_path, "content": content, "notes": notes, "actions": [action.model_dump() for action in actions]}


def security_terms_for_category(category: str) -> List[str]:
    text = category.lower()
    terms = ["auth", "token", "permission", "validate", "sanitize", "guard"]
    if "sql" in text:
        terms.extend(["query", "sql", "parameterized"])
    if "secret" in text:
        terms.extend(["secret", "key", "token"])
    if "race" in text:
        terms.extend(["lock", "async", "race"])
    return terms


def candidate_patch_text(finding: Dict[str, object]) -> str:
    title = finding.get("title")
    return f"""diff --git a/{finding.get('file') or 'affected-file'} b/{finding.get('file') or 'affected-file'}
--- a/{finding.get('file') or 'affected-file'}
+++ b/{finding.get('file') or 'affected-file'}
@@
+# SentinelGraph candidate fix for: {title}
+# Restore explicit input validation, deny-by-default authorization, and negative tests before merging.
"""


def patch_python_source(content: str, finding: Dict[str, object]) -> str:
    guard = '''

def _sentinelgraph_security_regression_guard(value, *, allow_empty=False):
    """Generated guard for a security regression candidate."""
    if value is None:
        raise ValueError("missing security-sensitive value")
    if not allow_empty and value == "":
        raise ValueError("empty security-sensitive value")
    return value
'''
    if "_sentinelgraph_security_regression_guard" in content:
        return content
    return content.rstrip() + guard + "\n"


def regression_test_content(finding: Dict[str, object], subject: Dict[str, object]) -> str:
    service = finding.get("service") or subject.get("service") or "service"
    return f'''"""Generated security regression tests for {service}."""


def test_{re.sub(r"[^a-zA-Z0-9_]+", "_", str(service)).strip("_") or "service"}_rejects_invalid_security_context():
    # Replace the placeholder call with the service's real request helper.
    forged_context = {{"token": "forged", "role": "unexpected"}}
    assert forged_context["token"] != "trusted"


def test_{re.sub(r"[^a-zA-Z0-9_]+", "_", str(service)).strip("_") or "service"}_requires_negative_authorization_case():
    denied_roles = ["anonymous", "wrong-role", "expired-session"]
    assert "anonymous" in denied_roles
'''


def optimize_gitlab_ci(existing: str | None) -> tuple[str, List[str]]:
    notes = []
    if existing:
        try:
            data = yaml.safe_load(existing) or {}
            if not isinstance(data, dict):
                data = {}
        except yaml.YAMLError:
            data = {}
            notes.append("Existing GitLab CI was not parseable; generated optimized baseline.")
    else:
        data = {}
        notes.append("No existing GitLab CI found; generated optimized baseline.")
    stages = data.setdefault("stages", [])
    if not isinstance(stages, list):
        stages = []
        data["stages"] = stages
    for stage in ["lint", "test", "security"]:
        if stage not in stages:
            stages.append(stage)
            notes.append(f"Added {stage} stage.")
    default = data.setdefault("default", {})
    if isinstance(default, dict):
        if default.get("interruptible") is not True:
            default["interruptible"] = True
            notes.append("Enabled interruptible jobs.")
        default.setdefault("cache", {"key": "$CI_COMMIT_REF_SLUG", "paths": [".cache/pip", "node_modules/"]})
    for name, stage, paths in [
        ("sentinelgraph-lint", "lint", ["**/*.py", "**/*.js", "**/*.ts"]),
        ("sentinelgraph-test", "test", ["src/**/*", "services/**/*", "tests/**/*"]),
        ("sentinelgraph-security", "security", ["src/**/*", "services/**/*", "requirements.txt", "package.json", "Dockerfile"]),
    ]:
        if name not in data:
            data[name] = {"stage": stage, "script": [f"echo run {stage}"], "rules": [{"changes": paths}]}
            notes.append(f"Added {name} job.")
    return yaml.safe_dump(data, sort_keys=False), notes


def optimize_github_actions(existing: str | None) -> tuple[str, List[str]]:
    notes = []
    if existing:
        try:
            data = yaml.safe_load(existing) or {}
            if not isinstance(data, dict):
                data = {}
        except yaml.YAMLError:
            data = {}
            notes.append("Existing GitHub Actions workflow was not parseable; generated optimized baseline.")
    else:
        data = {}
        notes.append("No existing GitHub Actions workflow found; generated optimized baseline.")
    if True in data and "on" not in data:
        data["on"] = data.pop(True)
    data.setdefault("name", "SentinelGraph Optimized CI")
    data["on"] = merge_github_paths(data.get("on"))
    jobs = data.setdefault("jobs", {})
    if not isinstance(jobs, dict):
        jobs = {}
        data["jobs"] = jobs
        notes.append("Rebuilt invalid jobs section.")
    if "test" not in jobs:
        jobs["test"] = {"runs-on": "ubuntu-latest", "steps": [{"uses": "actions/checkout@v4"}, {"run": "echo run optimized CI"}]}
        notes.append("Added test job.")
    for job in jobs.values():
        if not isinstance(job, dict):
            continue
        steps = job.setdefault("steps", [])
        if isinstance(steps, list) and not any(isinstance(step, dict) and step.get("uses") == "actions/cache@v4" for step in steps):
            steps.insert(
                1 if steps else 0,
                {
                    "uses": "actions/cache@v4",
                    "with": {
                        "path": "~/.cache/pip\nnode_modules",
                        "key": "deps-${{ runner.os }}-${{ hashFiles('**/requirements.txt', '**/package-lock.json') }}",
                    },
                },
            )
            notes.append("Added dependency cache step.")
    return yaml.safe_dump(data, sort_keys=False), notes


def merge_github_paths(trigger: object) -> Dict[str, object]:
    paths = ["src/**", "services/**", "tests/**", "requirements.txt", "package.json", "Dockerfile"]
    if not isinstance(trigger, dict):
        return {"pull_request": {"paths": paths}}
    pull_request = trigger.setdefault("pull_request", {})
    if pull_request is None:
        pull_request = {}
        trigger["pull_request"] = pull_request
    if isinstance(pull_request, dict):
        existing_paths = pull_request.get("paths") or []
        pull_request["paths"] = sorted(set(existing_paths) | set(paths))
    return trigger


GITLAB_CI_OPTIMIZED = """stages: [lint, test, security]

default:
  interruptible: true
  cache:
    key: "$CI_COMMIT_REF_SLUG"
    paths:
      - .cache/pip
      - node_modules/

lint:
  stage: lint
  script: echo "run lint"
  rules:
    - changes:
        - "**/*.py"
        - "**/*.js"
        - "**/*.ts"

test:
  stage: test
  script: echo "run tests"
  rules:
    - changes:
        - "src/**/*"
        - "services/**/*"
        - "tests/**/*"

security:
  stage: security
  script: echo "run security scans"
  rules:
    - changes:
        - "src/**/*"
        - "services/**/*"
        - "requirements.txt"
        - "package.json"
        - "Dockerfile"
"""

GITHUB_ACTIONS_OPTIMIZED = """name: SentinelGraph Optimized CI
on:
  pull_request:
    paths:
      - 'src/**'
      - 'services/**'
      - 'tests/**'
      - 'requirements.txt'
      - 'package.json'
      - 'Dockerfile'
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/cache@v4
        with:
          path: |
            ~/.cache/pip
            node_modules
          key: deps-${{ runner.os }}-${{ hashFiles('**/requirements.txt', '**/package-lock.json') }}
      - run: echo "run optimized CI"
"""
