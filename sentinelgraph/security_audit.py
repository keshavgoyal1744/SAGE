"""Security policy audit and scanner chaos workflows."""

from __future__ import annotations

from typing import Dict, List, Tuple

import yaml

from .controls import ControlEngine
from .models import (
    ControlPayloadResult,
    ControlRunInput,
    PolicyAuditRequest,
    ScannerChaosRequest,
    WritebackAction,
)
from .provider_ops import ProviderOps
from .scan_reports import parse_security_artifacts


PAYLOADS = {
    "sql-injection": ("scannervalidation/sast/sql_injection.py", "query = 'SELECT * FROM users WHERE id=' + user_id\n"),
    "xss": ("scannervalidation/sast/xss.py", "return f'<h1>{request.args.get(\"name\")}</h1>'\n"),
    "command-injection": ("scannervalidation/sast/command_injection.py", "os.system('ping ' + hostname)\n"),
    "weak-crypto": ("scannervalidation/sast/weak_crypto.py", "hashlib.md5(password.encode()).hexdigest()\n"),
    "path-traversal": ("scannervalidation/sast/path_traversal.py", "open(user_filename).read()\n"),
    "ssrf": ("scannervalidation/sast/ssrf.py", "requests.get(user_url).text\n"),
    "insecure-deserialization": ("scannervalidation/sast/insecure_deserialization.py", "pickle.loads(session_data)\n"),
    "open-redirect": ("scannervalidation/sast/open_redirect.py", "return redirect(request.args.get('url'))\n"),
    "hardcoded-secret": ("scannervalidation/secrets/hardcoded_secret.py", "API_TOKEN = 'sg_test_1234567890abcdef'\n"),
    "private-key": ("scannervalidation/secrets/private_key.py", "PRIVATE_KEY='-----BEGIN RSA PRIVATE KEY-----FAKE-----END RSA PRIVATE KEY-----'\n"),
}


class ScannerChaosEngine:
    def __init__(self, controls: ControlEngine):
        self.controls = controls

    def run(self, request: ScannerChaosRequest) -> Dict[str, object]:
        selected = request.payload_categories or list(PAYLOADS)
        files = {
            path: f'"""SentinelGraph scanner validation payload: {category}"""\n{content}'
            for category, (path, content) in PAYLOADS.items()
            if category in selected
        }
        ops = ProviderOps(request)
        actions: List[WritebackAction] = [
            ops.create_branch(request.branch),
            ops.commit_files(request.branch, "test: add scanner validation payloads", files),
        ]
        if request.open_merge_request:
            actions.append(
                ops.create_change_request(
                    request.branch,
                    "main",
                    "SentinelGraph scanner validation payloads",
                    "Adds synthetic payloads to validate security control coverage. Review only; do not merge into production branches.",
                )
            )
        ci_result = None
        artifact_findings = []
        if request.wait_for_ci:
            ci_result = ops.wait_for_ci(request.branch, request.timeout_seconds, request.poll_seconds)
            artifact_findings = parse_security_artifacts(ops.download_ci_artifacts(ci_result))
        detected_categories = detected_payload_categories(artifact_findings)
        payload_results = [
            ControlPayloadResult(
                payload_id=category,
                category=category,
                detected=(category in detected_categories) if request.wait_for_ci else not request.dry_run,
                severity="critical" if category in {"ssrf", "hardcoded-secret", "private-key"} else "high",
                evidence={"file": path, "mode": "dry-run" if request.dry_run else "provider", "ci_waited": request.wait_for_ci},
            )
            for category, (path, _) in PAYLOADS.items()
            if category in selected
        ]
        score = self.controls.record_run(
            ControlRunInput(
                control_id="scanner-chaos",
                control_type="scanner-validation",
                repo=request.repo,
                scanner=f"{request.provider}-security-controls",
                payloads=payload_results,
                metadata={"branch": request.branch, "actions": [action.model_dump() for action in actions]},
            )
        )
        return {
            "score": score.model_dump(),
            "actions": [action.model_dump() for action in actions],
            "files": sorted(files),
            "ci": ci_result,
            "artifact_findings": artifact_findings,
        }


class SecurityPolicyAuditor:
    def audit(self, request: PolicyAuditRequest) -> Dict[str, object]:
        ops = ProviderOps(request)
        status = ops.policy_status(request.default_branch)
        checks = {
            "protected_branches": bool(status.get("protected_branches")),
            "approval_rules": bool(status.get("approval_rules")),
            "pipelines_required": bool(status.get("only_allow_merge_if_pipeline_succeeds")),
            "protected_environments": bool(status.get("protected_environments")),
        }
        findings = ops.security_findings()
        ci_path, current_ci = read_existing_ci(ops, request)
        remediation = remediate_ci_config(current_ci, request.provider)
        score = round((sum(1 for ok in checks.values() if ok) / max(len(checks), 1)) * 100, 2)
        recommendations = [name for name, ok in checks.items() if not ok]
        actions = []
        if recommendations and request.open_remediation:
            body = "Missing controls:\n" + "\n".join(f"- {name}" for name in recommendations)
            actions.append(ops.create_issue("SentinelGraph security policy remediation", body, ["security", "policy"]))
        if request.remediate_ci and remediation["changed"]:
            branch = "sentinelgraph/security-policy-remediation"
            actions.extend(
                [
                    ops.create_branch(branch, request.default_branch),
                    ops.commit_files(branch, "ci: add security controls and policy gates", {ci_path: remediation["content"]}),
                    ops.create_change_request(
                        branch,
                        request.default_branch,
                        "SentinelGraph security policy CI remediation",
                        "Adds missing security scanners, path filters, caching, and policy gates.",
                    ),
                ]
            )
        return {
            "repo": request.repo,
            "score": score,
            "checks": checks,
            "policy_status": status,
            "security_findings_seen": len(findings),
            "security_findings": findings[:50],
            "recommendations": recommendations,
            "ci_remediation": remediation,
            "actions": [action.model_dump() for action in actions],
        }


def detected_payload_categories(findings: List[Dict[str, object]]) -> set[str]:
    detected = set()
    text = " ".join(str(finding).lower() for finding in findings)
    for category in PAYLOADS:
        words = category.replace("-", " ").split()
        if category in text or all(word in text for word in words):
            detected.add(category)
    if "secret" in text:
        detected.add("hardcoded-secret")
    if "private key" in text or "rsa private" in text:
        detected.add("private-key")
    return detected


def read_existing_ci(ops: ProviderOps, request: PolicyAuditRequest) -> Tuple[str, str | None]:
    candidates = [".gitlab-ci.yml"] if request.provider == "gitlab" else [".github/workflows/ci.yml", ".github/workflows/security.yml"]
    if request.provider == "fixture":
        candidates = [".gitlab-ci.yml"]
    for path in candidates:
        content = ops.get_file(path, request.default_branch)
        if content:
            return path, content
    return candidates[0], None


def remediate_ci_config(existing: str | None, provider: str) -> Dict[str, object]:
    if provider == "github":
        return remediate_github_actions(existing)
    return remediate_gitlab_ci(existing)


def remediate_gitlab_ci(existing: str | None) -> Dict[str, object]:
    data = {}
    if existing:
        try:
            parsed = yaml.safe_load(existing) or {}
            if isinstance(parsed, dict):
                data = parsed
        except yaml.YAMLError:
            return {"changed": True, "content": gitlab_ci_baseline(), "notes": ["Existing YAML could not be parsed; generated safe baseline."]}
    notes = []
    stages = data.get("stages") or []
    if not isinstance(stages, list):
        stages = []
    for stage in ["test", "security"]:
        if stage not in stages:
            stages.append(stage)
            notes.append(f"Added {stage} stage.")
    data["stages"] = stages
    default = data.setdefault("default", {})
    if isinstance(default, dict):
        if default.get("interruptible") is not True:
            default["interruptible"] = True
            notes.append("Added interruptible default.")
        default.setdefault("cache", {"key": "$CI_COMMIT_REF_SLUG", "paths": [".cache/pip", "node_modules/"]})
    include = data.setdefault("include", [])
    if isinstance(include, dict):
        include = [include]
    if isinstance(include, list):
        templates = {
            "Jobs/SAST.gitlab-ci.yml",
            "Jobs/Secret-Detection.gitlab-ci.yml",
            "Jobs/Dependency-Scanning.gitlab-ci.yml",
            "Jobs/Container-Scanning.gitlab-ci.yml",
        }
        existing_templates = {
            item.get("template") for item in include if isinstance(item, dict) and item.get("template")
        }
        for template in sorted(templates - existing_templates):
            include.append({"template": template})
            notes.append(f"Added {template}.")
        data["include"] = include
    data.setdefault(
        "sentinelgraph-security-policy",
        {
            "stage": "security",
            "script": ["echo SentinelGraph security policy gate"],
            "rules": [{"changes": ["src/**/*", "services/**/*", "requirements.txt", "package.json", "Dockerfile"]}],
            "allow_failure": False,
        },
    )
    content = yaml.safe_dump(data, sort_keys=False)
    return {"changed": bool(notes) or existing is None, "content": content, "notes": notes}


def remediate_github_actions(existing: str | None) -> Dict[str, object]:
    data = {}
    notes = []
    if existing:
        try:
            parsed = yaml.safe_load(existing) or {}
            if isinstance(parsed, dict):
                data = parsed
        except yaml.YAMLError:
            data = {}
            notes.append("Existing workflow could not be parsed; generated safe baseline.")
    if True in data and "on" not in data:
        data["on"] = data.pop(True)
        notes.append("Normalized GitHub Actions trigger key.")
    elif True in data:
        data.pop(True)
    data.setdefault("name", "SentinelGraph Security")
    data.setdefault("on", {"pull_request": {"paths": ["src/**", "services/**", "requirements.txt", "package.json", "Dockerfile"]}})
    jobs = data.setdefault("jobs", {})
    if not isinstance(jobs, dict):
        jobs = {}
        data["jobs"] = jobs
        notes.append("Rebuilt invalid jobs section.")
    if "security" not in jobs:
        jobs["security"] = {
            "runs-on": "ubuntu-latest",
            "permissions": {"security-events": "write", "contents": "read", "actions": "read"},
            "steps": [
                {"uses": "actions/checkout@v4"},
                {"name": "Dependency review", "uses": "actions/dependency-review-action@v4"},
                {"name": "SentinelGraph policy gate", "run": "echo SentinelGraph security policy gate"},
            ],
        }
        notes.append("Added security job.")
    content = yaml.safe_dump(data, sort_keys=False)
    return {"changed": bool(notes) or existing is None, "content": content, "notes": notes}


def gitlab_ci_baseline() -> str:
    return yaml.safe_dump(
        {
            "stages": ["test", "security"],
            "include": [
                {"template": "Jobs/SAST.gitlab-ci.yml"},
                {"template": "Jobs/Secret-Detection.gitlab-ci.yml"},
                {"template": "Jobs/Dependency-Scanning.gitlab-ci.yml"},
                {"template": "Jobs/Container-Scanning.gitlab-ci.yml"},
            ],
            "default": {"interruptible": True, "cache": {"key": "$CI_COMMIT_REF_SLUG", "paths": [".cache/pip", "node_modules/"]}},
            "sentinelgraph-security-policy": {
                "stage": "security",
                "script": ["echo SentinelGraph security policy gate"],
                "rules": [{"changes": ["src/**/*", "services/**/*", "requirements.txt", "package.json", "Dockerfile"]}],
            },
        },
        sort_keys=False,
    )
