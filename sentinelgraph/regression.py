"""Root cause detection, sibling discovery, patch/test generation, and CI optimization."""

from __future__ import annotations

from typing import Dict, List

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
        candidates = self._root_cause_candidates(repo, subject)
        root = candidates[0] if candidates else None
        siblings = self._siblings(repo, subject)
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
        patches = self._patches(generated_findings)
        tests = self._tests(generated_findings)
        actions: List[WritebackAction] = []
        ops = ProviderOps(request)
        if request.open_remediation and patches:
            branch = "sentinelgraph/regression-fixes"
            files = {patch["path"]: patch["content"] for patch in patches}
            actions.extend([
                ops.create_branch(branch),
                ops.commit_files(branch, "fix: apply SentinelGraph regression guards", files),
                ops.create_change_request(branch, "main", "SentinelGraph regression remediation", "Generated regression guard patches."),
            ])
        if request.open_tests and tests:
            branch = "sentinelgraph/regression-tests"
            files = {test["path"]: test["content"] for test in tests}
            actions.extend([
                ops.create_branch(branch),
                ops.commit_files(branch, "test: add SentinelGraph regression tests", files),
                ops.create_change_request(branch, "main", "SentinelGraph regression tests", "Generated regression tests for sibling findings."),
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

    def _root_cause_candidates(self, repo: str, subject: Dict[str, object]) -> List[Dict[str, object]]:
        analyses = self.graph.store.list_analyses(repo)
        service = subject.get("service")
        file_path = subject.get("file")
        candidates = []
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
                        "reason": "Prior change touched the affected service or file.",
                    }
                )
        return sorted(candidates, key=lambda item: item["score"], reverse=True)

    def _siblings(self, repo: str, subject: Dict[str, object]) -> List[Dict[str, object]]:
        subject_service = subject.get("service")
        category = str(subject.get("category", "")).lower()
        siblings = []
        for service in self.graph.store.list_entities("service"):
            if service.name == subject_service:
                continue
            haystack = f"{service.name} {service.attributes}".lower()
            if "auth" in category and any(term in haystack for term in ["auth", "gateway", "identity", "session"]):
                siblings.append({"service": service.name, "file": service.attributes.get("file_prefix")})
            elif not siblings and service.name != "docs":
                siblings.append({"service": service.name, "file": service.attributes.get("file_prefix")})
        return siblings[:5]

    def _patches(self, findings: List[Dict[str, object]]) -> List[Dict[str, str]]:
        patches = []
        for finding in findings:
            service = finding.get("service") or "unknown"
            patches.append(
                {
                    "path": f"sentinelgraph-remediation/{service}-fix.md",
                    "content": f"# Regression Fix Pattern\n\nFinding: {finding.get('title')}\n\nRestore validation, add explicit deny-by-default behavior, and require security owner review.\n",
                }
            )
        return patches

    def _tests(self, findings: List[Dict[str, object]]) -> List[Dict[str, str]]:
        tests = []
        for finding in findings:
            service = finding.get("service") or "unknown"
            tests.append(
                {
                    "path": f"sentinelgraph-tests/test_{service}_regression.md",
                    "content": f"# Regression Test\n\nFinding: {finding.get('title')}\n\nAssert forged, missing, expired, malformed, and wrong-role requests are rejected.\n",
                }
            )
        return tests


class CiOptimizer:
    def optimize(self, request: CiOptimizeRequest) -> Dict[str, object]:
        ops = ProviderOps(request)
        target_path = request.workflow_path if request.provider == "github" else request.ci_path
        if request.provider == "github":
            content = GITHUB_ACTIONS_OPTIMIZED
        else:
            content = GITLAB_CI_OPTIMIZED
        actions = [
            ops.create_branch(request.branch),
            ops.commit_files(request.branch, "ci: optimize pipeline with path filters and caching", {target_path: content}),
            ops.create_change_request(request.branch, "main", "SentinelGraph CI optimization", "Adds path-based filters, caching, and interruptible jobs."),
        ]
        return {"path": target_path, "content": content, "actions": [action.model_dump() for action in actions]}


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
