"""Security policy audit and scanner chaos workflows."""

from __future__ import annotations

from typing import Dict, List

from .controls import ControlEngine
from .models import (
    ControlPayloadResult,
    ControlRunInput,
    PolicyAuditRequest,
    ScannerChaosRequest,
    WritebackAction,
)
from .provider_ops import ProviderOps


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
        payload_results = [
            ControlPayloadResult(
                payload_id=category,
                category=category,
                detected=not request.dry_run,
                severity="critical" if category in {"ssrf", "hardcoded-secret", "private-key"} else "high",
                evidence={"file": path, "mode": "dry-run" if request.dry_run else "provider"},
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
        return {"score": score.model_dump(), "actions": [action.model_dump() for action in actions], "files": sorted(files)}


class SecurityPolicyAuditor:
    def audit(self, request: PolicyAuditRequest) -> Dict[str, object]:
        ops = ProviderOps(request)
        status = ops.policy_status()
        checks = {
            "protected_branches": bool(status.get("protected_branches")),
            "approval_rules": bool(status.get("approval_rules")),
            "pipelines_required": bool(status.get("only_allow_merge_if_pipeline_succeeds")),
            "protected_environments": bool(status.get("protected_environments")),
        }
        findings = ops.security_findings()
        score = round((sum(1 for ok in checks.values() if ok) / max(len(checks), 1)) * 100, 2)
        recommendations = [name for name, ok in checks.items() if not ok]
        actions = []
        if recommendations and request.open_remediation:
            body = "Missing controls:\n" + "\n".join(f"- {name}" for name in recommendations)
            actions.append(ops.create_issue("SentinelGraph security policy remediation", body, ["security", "policy"]))
        return {
            "repo": request.repo,
            "score": score,
            "checks": checks,
            "security_findings_seen": len(findings),
            "recommendations": recommendations,
            "actions": [action.model_dump() for action in actions],
        }
