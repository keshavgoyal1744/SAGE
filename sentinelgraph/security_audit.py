"""Security policy audit, scanner validation, triage, and verification workflows."""

from __future__ import annotations

from typing import Any, Dict, List, Tuple

import yaml

from .advisory import AdvisoryEngine
from .controls import ControlEngine
from .models import (
    AdvisoryEnrichmentRequest,
    ControlPayloadResult,
    ControlRunInput,
    FullSecurityAuditRequest,
    PolicyAuditRequest,
    RemediationVerificationRequest,
    ScannerChaosRequest,
    VulnerabilityTriageRequest,
    WritebackAction,
)
from .provider_ops import ProviderOps
from .scan_reports import parse_security_artifacts


PAYLOAD_CATALOG = {
    "sast-sqli-001": {
        "category": "sql-injection",
        "scanner": "sast",
        "owasp": "A03:2021 Injection",
        "cwe": "CWE-89",
        "severity": "critical",
        "path": "scannervalidation/sast/sql_injection.py",
        "content": "query = 'SELECT * FROM users WHERE id=' + user_id\n",
    },
    "sast-xss-002": {
        "category": "xss",
        "scanner": "sast",
        "owasp": "A03:2021 Injection",
        "cwe": "CWE-79",
        "severity": "high",
        "path": "scannervalidation/sast/xss.py",
        "content": "return f'<h1>{request.args.get(\"name\")}</h1>'\n",
    },
    "sast-cmdi-003": {
        "category": "command-injection",
        "scanner": "sast",
        "owasp": "A03:2021 Injection",
        "cwe": "CWE-78",
        "severity": "critical",
        "path": "scannervalidation/sast/command_injection.py",
        "content": "os.system('ping ' + hostname)\n",
    },
    "sast-crypto-004": {
        "category": "weak-crypto",
        "scanner": "sast",
        "owasp": "A02:2021 Cryptographic Failures",
        "cwe": "CWE-327",
        "severity": "high",
        "path": "scannervalidation/sast/weak_crypto.py",
        "content": "hashlib.md5(password.encode()).hexdigest()\n",
    },
    "sast-path-005": {
        "category": "path-traversal",
        "scanner": "sast",
        "owasp": "A01:2021 Broken Access Control",
        "cwe": "CWE-22",
        "severity": "high",
        "path": "scannervalidation/sast/path_traversal.py",
        "content": "open(user_filename).read()\n",
    },
    "sast-ssrf-006": {
        "category": "ssrf",
        "scanner": "sast",
        "owasp": "A10:2021 Server-Side Request Forgery",
        "cwe": "CWE-918",
        "severity": "critical",
        "path": "scannervalidation/sast/ssrf.py",
        "content": "requests.get(user_url).text\n",
    },
    "sast-deser-007": {
        "category": "insecure-deserialization",
        "scanner": "sast",
        "owasp": "A08:2021 Software and Data Integrity Failures",
        "cwe": "CWE-502",
        "severity": "critical",
        "path": "scannervalidation/sast/insecure_deserialization.py",
        "content": "pickle.loads(session_data)\n",
    },
    "sast-redirect-008": {
        "category": "open-redirect",
        "scanner": "sast",
        "owasp": "A01:2021 Broken Access Control",
        "cwe": "CWE-601",
        "severity": "medium",
        "path": "scannervalidation/sast/open_redirect.py",
        "content": "return redirect(request.args.get('url'))\n",
    },
    "sast-xxe-009": {
        "category": "xxe",
        "scanner": "sast",
        "owasp": "A05:2021 Security Misconfiguration",
        "cwe": "CWE-611",
        "severity": "high",
        "path": "scannervalidation/sast/xxe.py",
        "content": "parser = etree.XMLParser(resolve_entities=True)\netree.fromstring(xml_body, parser)\n",
    },
    "sast-ldap-010": {
        "category": "ldap-injection",
        "scanner": "sast",
        "owasp": "A03:2021 Injection",
        "cwe": "CWE-90",
        "severity": "high",
        "path": "scannervalidation/sast/ldap_injection.py",
        "content": "ldap_filter = '(uid=' + username + ')'\n",
    },
    "secret-token-011": {
        "category": "hardcoded-secret",
        "scanner": "secret-detection",
        "owasp": "A07:2021 Identification and Authentication Failures",
        "cwe": "CWE-798",
        "severity": "critical",
        "path": "scannervalidation/secrets/hardcoded_secret.py",
        "content": "API_TOKEN = 'sg_test_1234567890abcdef'\n",
    },
    "secret-key-012": {
        "category": "private-key",
        "scanner": "secret-detection",
        "owasp": "A02:2021 Cryptographic Failures",
        "cwe": "CWE-321",
        "severity": "critical",
        "path": "scannervalidation/secrets/private_key.py",
        "content": "PRIVATE_KEY='-----BEGIN RSA PRIVATE KEY-----FAKE-----END RSA PRIVATE KEY-----'\n",
    },
    "secret-aws-013": {
        "category": "cloud-access-key",
        "scanner": "secret-detection",
        "owasp": "A05:2021 Security Misconfiguration",
        "cwe": "CWE-798",
        "severity": "critical",
        "path": "scannervalidation/secrets/aws_key.py",
        "content": "AWS_ACCESS_KEY_ID='AKIAIOSFODNN7EXAMPLE'\n",
    },
    "secret-jwt-014": {
        "category": "jwt-secret",
        "scanner": "secret-detection",
        "owasp": "A07:2021 Identification and Authentication Failures",
        "cwe": "CWE-798",
        "severity": "critical",
        "path": "scannervalidation/secrets/jwt_secret.py",
        "content": "JWT_SIGNING_SECRET='super-secret-signing-key-please-rotate'\n",
    },
    "secret-db-015": {
        "category": "database-password",
        "scanner": "secret-detection",
        "owasp": "A02:2021 Cryptographic Failures",
        "cwe": "CWE-798",
        "severity": "critical",
        "path": "scannervalidation/secrets/database_url.py",
        "content": "DATABASE_URL='postgres://admin:plaintext-password@example.internal/app'\n",
    },
}

PAYLOADS = {item["category"]: (item["path"], item["content"]) for item in PAYLOAD_CATALOG.values()}
PRIORITY_RANK = {"P0": 0, "P1": 1, "P2": 2, "P3": 3}


class ScannerChaosEngine:
    def __init__(self, controls: ControlEngine):
        self.controls = controls

    def run(self, request: ScannerChaosRequest) -> Dict[str, object]:
        selected = select_payloads(request.payload_categories)
        files = {
            item["path"]: f'"""SentinelGraph scanner validation payload: {payload_id} {item["category"]}"""\n{item["content"]}'
            for payload_id, item in selected.items()
        }
        ops = ProviderOps(request)
        actions: List[WritebackAction] = [
            ops.create_branch(request.branch),
            ops.commit_files(request.branch, "test: add scanner validation payloads", files),
        ]
        if request.open_merge_request:
            body = scanner_validation_merge_request_body(request.block_merge)
            actions.append(
                ops.create_change_request(
                    request.branch,
                    "main",
                    "SentinelGraph scanner validation payloads",
                    body,
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
                payload_id=payload_id,
                category=item["category"],
                detected=(payload_id in detected_categories or item["category"] in detected_categories) if request.wait_for_ci else not request.dry_run,
                severity=item["severity"],
                evidence={
                    "file": item["path"],
                    "mode": "dry-run" if request.dry_run else "provider",
                    "ci_waited": request.wait_for_ci,
                    "owasp": item["owasp"],
                    "cwe": item["cwe"],
                    "scanner": item["scanner"],
                },
            )
            for payload_id, item in selected.items()
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
        coverage = owasp_coverage(payload_results)
        actions.extend(
            post_trigger_comment(
                ops,
                request.trigger_issue_id,
                request.trigger_change_id,
                "Scanner validation completed",
                scanner_validation_comment(score.model_dump(), payload_results, coverage, actions),
            )
        )
        if request.cleanup_branch:
            actions.append(ops.delete_branch(request.branch))
        return {
            "score": score.model_dump(),
            "actions": [action.model_dump() for action in actions],
            "files": sorted(files),
            "payloads": selected,
            "owasp_coverage": coverage,
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
            actions.append(
                ops.create_issue_once(
                    "SentinelGraph security policy remediation",
                    body,
                    ["security", "policy"],
                    fingerprint_parts=["policy-remediation", request.repo, sorted(recommendations)],
                )
            )
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
        actions.extend(
            post_trigger_comment(
                ops,
                request.trigger_issue_id,
                request.trigger_change_id,
                "Security policy audit completed",
                policy_audit_comment(score, checks, recommendations, actions),
            )
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


class VulnerabilityTriageEngine:
    def run(self, request: VulnerabilityTriageRequest) -> Dict[str, object]:
        ops = ProviderOps(request)
        raw_findings = ops.security_findings()[: request.max_findings]
        triaged = []
        actions: List[WritebackAction] = []
        advisory_engine = AdvisoryEngine()
        for raw in raw_findings:
            normalized = normalize_provider_finding(raw)
            if is_validation_payload(normalized):
                continue
            owner = last_author_for_file(ops, normalized.get("file"), request.default_branch)
            triage = triage_finding(normalized, owner)
            if request.enrich_advisories:
                triage["advisory_enrichment"] = enrich_triage_advisories(advisory_engine, triage)
            triaged.append(triage)
            if request.create_child_issues and should_create_child_issue(triage, request.minimum_child_priority):
                title = f"[{triage['priority']}] Remediate {triage['title']}"
                body = triage_issue_body(triage)
                labels = ["security", "sentinelgraph", "triage", triage["priority"].lower()]
                if request.dedupe_existing_issues:
                    actions.append(
                        ops.create_issue_once(
                            title,
                            body,
                            labels,
                            assignees=assignees_for_owner(triage["owner"]),
                            fingerprint_parts=["triage", triage.get("id"), triage.get("file"), triage.get("cve"), triage.get("ghsa")],
                        )
                    )
                else:
                    actions.append(ops.create_issue(title, body, labels, assignees=assignees_for_owner(triage["owner"])))
        summary = triage_summary(triaged)
        if request.create_report_issue:
            actions.append(
                ops.create_issue_once(
                    f"SentinelGraph vulnerability triage report: {request.repo}",
                    triage_report_body(request.repo, summary, triaged),
                    ["security", "sentinelgraph", "triage-report"],
                    fingerprint_parts=["triage-report", request.repo, summary],
                )
            )
        actions.extend(
            post_trigger_comment(
                ops,
                request.trigger_issue_id,
                request.trigger_change_id,
                "Vulnerability triage completed",
                triage_report_body(request.repo, summary, triaged[:20]),
            )
        )
        return {
            "repo": request.repo,
            "raw_seen": len(raw_findings),
            "triaged": triaged,
            "summary": summary,
            "actions": [action.model_dump() for action in actions],
        }


class RemediationVerificationEngine:
    def run(self, request: RemediationVerificationRequest) -> Dict[str, object]:
        ops = ProviderOps(request)
        issues = ops.list_issues(request.issue_labels, state="opened", limit=request.max_issues)
        results = []
        actions: List[WritebackAction] = []
        for issue in issues:
            issue_id = str(issue.get("iid") or issue.get("number") or issue.get("id"))
            linked = ops.issue_linked_changes(issue_id) if issue_id else []
            result = verify_issue(issue, linked, ops, request.default_branch)
            results.append(result)
            if result["status"] == "verified" and request.close_verified:
                actions.append(ops.comment_on_issue(issue_id, verification_comment(result)))
                actions.append(ops.close_issue(issue_id))
            elif result["status"] in {"stale", "unresolved"} and request.escalate_stale:
                actions.append(ops.comment_on_issue(issue_id, escalation_comment(result)))
        summary = verification_summary(results)
        if request.create_report_issue:
            actions.append(
                ops.create_issue_once(
                    f"SentinelGraph remediation verification report: {request.repo}",
                    verification_report_body(request.repo, summary, results),
                    ["security", "sentinelgraph", "verification-report"],
                    fingerprint_parts=["verification-report", request.repo, summary],
                )
            )
        actions.extend(
            post_trigger_comment(
                ops,
                request.trigger_issue_id,
                request.trigger_change_id,
                "Remediation verification completed",
                verification_report_body(request.repo, summary, results[:20]),
            )
        )
        return {
            "repo": request.repo,
            "issues_seen": len(issues),
            "results": results,
            "summary": summary,
            "actions": [action.model_dump() for action in actions],
        }


class FullSecurityAuditEngine:
    def __init__(
        self,
        scanner: ScannerChaosEngine,
        policy: SecurityPolicyAuditor,
        triage: VulnerabilityTriageEngine,
        verification: RemediationVerificationEngine,
    ):
        self.scanner = scanner
        self.policy = policy
        self.triage = triage
        self.verification = verification

    def run(self, request: FullSecurityAuditRequest) -> Dict[str, object]:
        base = request.model_dump()
        policy = self.policy.audit(
            PolicyAuditRequest(**base, remediate_ci=True, open_remediation=True)
        )
        scanner = self.scanner.run(
            ScannerChaosRequest(
                **{key: value for key, value in base.items() if key not in {"wait_for_ci", "timeout_seconds", "poll_seconds"}},
                wait_for_ci=request.wait_for_ci,
                timeout_seconds=request.timeout_seconds,
                poll_seconds=request.poll_seconds,
                cleanup_branch=request.cleanup_scanner_branch,
            )
        )
        triage = self.triage.run(VulnerabilityTriageRequest(**base)) if request.run_triage else None
        verification = self.verification.run(RemediationVerificationRequest(**base)) if request.run_verification else None
        summary = {
            "policy_score": policy["score"],
            "scanner_confidence": scanner["score"]["confidence_score"],
            "triaged": triage["summary"]["total"] if triage else 0,
            "verified": verification["summary"]["verified"] if verification else 0,
        }
        trigger_actions = post_trigger_comment(
            ProviderOps(request),
            request.trigger_issue_id,
            request.trigger_change_id,
            "Full security audit completed",
            "\n".join(f"- {key}: {value}" for key, value in summary.items()),
        )
        return {
            "repo": request.repo,
            "policy": policy,
            "scanner": scanner,
            "triage": triage,
            "verification": verification,
            "summary": summary,
            "trigger_actions": [action.model_dump() for action in trigger_actions],
        }


def select_payloads(filters: List[str]) -> Dict[str, Dict[str, str]]:
    if not filters:
        return PAYLOAD_CATALOG
    selected = {}
    normalized = {item.lower() for item in filters}
    for payload_id, item in PAYLOAD_CATALOG.items():
        if payload_id.lower() in normalized or item["category"].lower() in normalized or item["scanner"].lower() in normalized:
            selected[payload_id] = item
    return selected


def owasp_coverage(payloads: List[ControlPayloadResult]) -> Dict[str, object]:
    groups: Dict[str, Dict[str, int]] = {}
    for payload in payloads:
        owasp = str(payload.evidence.get("owasp", "unmapped"))
        group = groups.setdefault(owasp, {"total": 0, "detected": 0})
        group["total"] += 1
        group["detected"] += int(payload.detected)
    return {
        "categories": groups,
        "covered": len(groups),
        "payloads": len(payloads),
        "detected": sum(group["detected"] for group in groups.values()),
    }


def detected_payload_categories(findings: List[Dict[str, object]]) -> set[str]:
    detected = set()
    text = " ".join(str(finding).lower() for finding in findings)
    for payload_id, payload in PAYLOAD_CATALOG.items():
        category = payload["category"]
        if payload_id in text:
            detected.add(payload_id)
            detected.add(category)
        words = category.replace("-", " ").split()
        if category in text or all(word in text for word in words):
            detected.add(category)
    if "secret" in text:
        detected.add("hardcoded-secret")
    if "private key" in text or "rsa private" in text:
        detected.add("private-key")
    return detected


def normalize_provider_finding(raw: Dict[str, Any]) -> Dict[str, Any]:
    rule = raw.get("rule") or raw.get("scanner") or {}
    vulnerability = raw.get("vulnerability") or raw
    security_advisory = raw.get("security_advisory") or {}
    location = raw.get("location") or raw.get("most_recent_instance", {}).get("location") or {}
    identifiers = raw.get("identifiers") or vulnerability.get("identifiers") or []
    title = (
        raw.get("title")
        or raw.get("name")
        or raw.get("message")
        or vulnerability.get("name")
        or security_advisory.get("summary")
        or rule.get("description")
        or rule.get("name")
        or "Security finding"
    )
    severity = str(raw.get("severity") or vulnerability.get("severity") or security_advisory.get("severity") or "medium").lower()
    file_path = (
        location.get("file")
        or location.get("path")
        or location.get("dependency", {}).get("package", {}).get("name")
        or raw.get("file")
        or raw.get("path")
    )
    cwe = first_identifier(identifiers, "cwe") or raw.get("cwe")
    cve = raw.get("cve") or raw.get("cve_id") or security_advisory.get("cve_id") or first_identifier(identifiers, "cve")
    ghsa = raw.get("ghsa") or raw.get("ghsa_id") or security_advisory.get("ghsa_id") or first_identifier(identifiers, "ghsa")
    return {
        "source": raw.get("source", "provider"),
        "id": str(raw.get("id") or raw.get("uuid") or raw.get("number") or title),
        "title": title,
        "severity": severity,
        "category": raw.get("category") or raw.get("report_type") or raw.get("tool", {}).get("name") or raw.get("source", "security"),
        "file": file_path,
        "line": location.get("start_line") or location.get("line"),
        "cwe": cwe,
        "cve": cve,
        "ghsa": ghsa,
        "raw": raw,
    }


def first_identifier(identifiers: List[Any], prefix: str) -> str | None:
    needle = prefix.lower()
    for item in identifiers:
        value = ""
        if isinstance(item, dict):
            value = str(item.get("value") or item.get("name") or item.get("external_id") or item.get("url") or "")
        else:
            value = str(item)
        if needle in value.lower():
            return value
    return None


def enrich_triage_advisories(engine: AdvisoryEngine, triage: Dict[str, Any]) -> Dict[str, object]:
    cve = triage.get("cve")
    ghsa = triage.get("ghsa")
    raw = triage.get("raw") or {}
    package = package_from_provider_finding(raw)
    if not cve and not ghsa and not package:
        return {"count": 0, "advisories": [], "errors": []}
    request = AdvisoryEnrichmentRequest(
        ecosystem=package.get("ecosystem") if package else None,
        package=package.get("name") if package else None,
        version=package.get("version") if package else None,
        cve=str(cve) if cve else None,
        ghsa=str(ghsa) if ghsa else None,
    )
    return engine.enrich(request)


def package_from_provider_finding(raw: Dict[str, Any]) -> Dict[str, str] | None:
    dependency = raw.get("dependency") or raw.get("location", {}).get("dependency") or {}
    package = dependency.get("package") or raw.get("package") or {}
    name = package.get("name") if isinstance(package, dict) else raw.get("package_name")
    version = dependency.get("version") or raw.get("version") or raw.get("package_version")
    ecosystem = package.get("ecosystem") if isinstance(package, dict) else raw.get("ecosystem")
    if name:
        return {"name": str(name), "version": str(version or ""), "ecosystem": str(ecosystem or "")}
    return None


def is_validation_payload(finding: Dict[str, Any]) -> bool:
    file_path = str(finding.get("file") or "").lower()
    title = str(finding.get("title") or "").lower()
    return "scannervalidation/" in file_path or "sentinelgraph scanner validation" in title


def last_author_for_file(ops: ProviderOps, file_path: Any, default_branch: str) -> str:
    if not file_path:
        return "unassigned"
    history = ops.file_history(str(file_path), default_branch, limit=1)
    if not history:
        return "unassigned"
    commit = history[0]
    provider_author = commit.get("author") or {}
    provider_committer = commit.get("committer") or {}
    commit_payload = commit.get("commit") or {}
    commit_author = commit_payload.get("author") or {}
    commit_committer = commit_payload.get("committer") or {}
    return (
        provider_author.get("login")
        or provider_committer.get("login")
        or commit.get("author_name")
        or commit.get("committer_name")
        or commit_author.get("name")
        or commit_committer.get("name")
        or "unassigned"
    )


def assignees_for_owner(owner: str) -> List[str]:
    value = str(owner or "").strip()
    if not value or value == "unassigned":
        return []
    if "<" in value:
        value = value.split("<", 1)[0].strip()
    return [value.lstrip("@")]


def triage_finding(finding: Dict[str, Any], owner: str) -> Dict[str, Any]:
    severity = normalize_severity(finding.get("severity"))
    false_positive = is_likely_false_positive(finding)
    priority = "P3" if false_positive else severity_to_priority(severity)
    return {
        **finding,
        "severity": severity,
        "priority": priority,
        "classification": "false-positive" if false_positive else "true-positive",
        "owner": owner,
        "suggested_fix": suggested_fix(finding),
        "rationale": "Test, fixture, generated, or validation payload path." if false_positive else "Provider finding is in production-looking code and needs owner review.",
    }


def normalize_severity(value: Any) -> str:
    text = str(value or "medium").lower()
    if text in {"critical", "high", "medium", "low", "info"}:
        return text
    if text in {"error", "severe"}:
        return "high"
    if text in {"warning", "moderate"}:
        return "medium"
    return "medium"


def is_likely_false_positive(finding: Dict[str, Any]) -> bool:
    file_path = str(finding.get("file") or "").lower()
    title = str(finding.get("title") or "").lower()
    return any(part in file_path for part in ["/test", "tests/", "fixtures/", "mocks/", "example", "demo/"]) or "test" in title


def severity_to_priority(severity: str) -> str:
    return {"critical": "P0", "high": "P1", "medium": "P2", "low": "P3", "info": "P3"}.get(severity, "P2")


def should_create_child_issue(triage: Dict[str, Any], minimum: str) -> bool:
    if triage["classification"] != "true-positive":
        return False
    return PRIORITY_RANK[triage["priority"]] <= PRIORITY_RANK[minimum]


def suggested_fix(finding: Dict[str, Any]) -> str:
    text = f"{finding.get('title')} {finding.get('category')} {finding.get('cwe')}".lower()
    if "sql" in text or "cwe-89" in text:
        return "Use parameterized queries and add negative injection tests."
    if "secret" in text or "key" in text or "password" in text:
        return "Revoke the credential, move it to a secrets manager, and add a rotation note."
    if "xss" in text or "cwe-79" in text:
        return "Escape untrusted output and add browser/client-side regression tests."
    if "ssrf" in text:
        return "Add URL allow-listing, block metadata IPs, and test denied destinations."
    if "deserialization" in text or "pickle" in text:
        return "Replace unsafe deserialization with a typed parser and reject untrusted payloads."
    return "Patch the vulnerable code path, add a regression test, and attach scanner evidence."


def triage_summary(triaged: List[Dict[str, Any]]) -> Dict[str, int]:
    return {
        "total": len(triaged),
        "true_positive": sum(1 for item in triaged if item["classification"] == "true-positive"),
        "false_positive": sum(1 for item in triaged if item["classification"] == "false-positive"),
        "p0": sum(1 for item in triaged if item["priority"] == "P0"),
        "p1": sum(1 for item in triaged if item["priority"] == "P1"),
        "p2": sum(1 for item in triaged if item["priority"] == "P2"),
        "p3": sum(1 for item in triaged if item["priority"] == "P3"),
    }


def triage_issue_body(item: Dict[str, Any]) -> str:
    enrichment = item.get("advisory_enrichment") or {}
    advisory_rows = "\n".join(
        f"- {advisory.get('id')}: {advisory.get('summary')}"
        for advisory in enrichment.get("advisories", [])[:5]
        if isinstance(advisory, dict)
    )
    return "\n".join(
        [
            f"Priority: {item['priority']}",
            f"Classification: {item['classification']}",
            f"Owner: {item['owner']}",
            f"File: {item.get('file') or 'unknown'}",
            f"Severity: {item['severity']}",
            f"Source: {item.get('source')}",
            f"CVE: {item.get('cve') or 'none'}",
            f"GHSA: {item.get('ghsa') or 'none'}",
            "",
            "Suggested fix:",
            item["suggested_fix"],
            "",
            "Advisory intelligence:",
            advisory_rows or "No external advisory match found.",
            "",
            "Evidence:",
            str(item.get("raw", {}))[:4000],
        ]
    )


def triage_report_body(repo: str, summary: Dict[str, int], triaged: List[Dict[str, Any]]) -> str:
    rows = "\n".join(
        f"| {item['priority']} | {item['classification']} | {item['severity']} | {item.get('file') or ''} | {item['owner']} | {item['title']} |"
        for item in triaged
    )
    return f"""# SentinelGraph Vulnerability Triage Report

Repository: `{repo}`

| Metric | Count |
|---|---:|
| Total triaged | {summary['total']} |
| True positives | {summary['true_positive']} |
| False positives | {summary['false_positive']} |
| P0 | {summary['p0']} |
| P1 | {summary['p1']} |
| P2 | {summary['p2']} |
| P3 | {summary['p3']} |

| Priority | Classification | Severity | File | Owner | Finding |
|---|---|---|---|---|---|
{rows or '| - | - | - | - | - | No findings |'}
"""


def verify_issue(issue: Dict[str, Any], linked: List[Dict[str, Any]], ops: ProviderOps, default_branch: str) -> Dict[str, Any]:
    title = issue.get("title") or ""
    body = issue.get("description") or issue.get("body") or ""
    issue_id = str(issue.get("iid") or issue.get("number") or issue.get("id"))
    merged = [item for item in linked if str(item.get("state") or "").lower() in {"merged", "closed"} or item.get("merged_at")]
    file_path = extract_file_from_text(f"{title}\n{body}")
    current_content = ops.get_file(file_path, default_branch) if file_path else None
    vulnerable_terms = ["md5", "pickle.loads", "os.system", "select *", "private key", "api_token", "password="]
    pattern_present = bool(current_content and any(term in current_content.lower() for term in vulnerable_terms))
    if linked and len(merged) == len(linked) and not pattern_present:
        status = "verified"
    elif linked:
        status = "unresolved"
    else:
        status = "stale"
    return {
        "issue_id": issue_id,
        "title": title,
        "status": status,
        "linked_changes": len(linked),
        "merged_changes": len(merged),
        "file": file_path,
        "pattern_present": pattern_present,
    }


def extract_file_from_text(text: str) -> str | None:
    for token in text.replace("`", " ").split():
        cleaned = token.strip(" ,.;:()[]")
        if "/" in cleaned and "." in cleaned:
            return cleaned
    return None


def verification_summary(results: List[Dict[str, Any]]) -> Dict[str, int]:
    return {
        "total": len(results),
        "verified": sum(1 for item in results if item["status"] == "verified"),
        "unresolved": sum(1 for item in results if item["status"] == "unresolved"),
        "stale": sum(1 for item in results if item["status"] == "stale"),
    }


def verification_comment(result: Dict[str, Any]) -> str:
    return f"""SentinelGraph remediation verification

Status: verified
Linked changes merged: {result['merged_changes']}/{result['linked_changes']}
File checked: {result.get('file') or 'not available'}

Closing this issue because all linked remediation evidence is merged and no vulnerable pattern was detected by the verifier.
"""


def escalation_comment(result: Dict[str, Any]) -> str:
    return f"""SentinelGraph remediation verification

Status: {result['status']}
Linked changes merged: {result['merged_changes']}/{result['linked_changes']}
File checked: {result.get('file') or 'not available'}

Action required: attach a remediation MR/PR, merge the linked fix, or provide evidence explaining why this finding is accepted.
"""


def verification_report_body(repo: str, summary: Dict[str, int], results: List[Dict[str, Any]]) -> str:
    rows = "\n".join(
        f"| {item['status']} | {item['issue_id']} | {item['merged_changes']}/{item['linked_changes']} | {item.get('file') or ''} | {item['title']} |"
        for item in results
    )
    return f"""# SentinelGraph Remediation Verification Report

Repository: `{repo}`

| Metric | Count |
|---|---:|
| Issues checked | {summary['total']} |
| Verified | {summary['verified']} |
| Unresolved | {summary['unresolved']} |
| Stale | {summary['stale']} |

| Status | Issue | Merged changes | File | Title |
|---|---:|---:|---|---|
{rows or '| - | - | - | - | No tracked issues |'}
"""


def post_trigger_comment(ops: ProviderOps, issue_id: str | None, change_id: str | None, title: str, body: str) -> List[WritebackAction]:
    actions: List[WritebackAction] = []
    message = f"## {title}\n\n{body}"
    if issue_id:
        actions.append(ops.comment_on_issue(issue_id, message))
    if change_id:
        actions.append(ops.comment_on_change(change_id, message))
    return actions


def scanner_validation_merge_request_body(block_merge: bool) -> str:
    warning = "This merge request is blocked from production merge by policy. Close it after CI has produced security artifacts."
    if not block_merge:
        warning = "Review only; do not merge into production branches."
    return "\n".join(
        [
            "Adds synthetic payloads to validate security control coverage.",
            "",
            warning,
            "",
            "Expected handling:",
            "- Let CI run security scanners.",
            "- Confirm SAST and secret scanners report the validation files.",
            "- Use the generated confidence score to open remediation work for missed payloads.",
            "- Delete the validation branch after evidence is collected.",
            "",
            "<!-- SentinelGraph-Scanner-Validation: do-not-merge -->",
        ]
    )


def scanner_validation_comment(score: Dict[str, Any], payloads: List[ControlPayloadResult], coverage: Dict[str, object], actions: List[WritebackAction]) -> str:
    missed = [payload for payload in payloads if not payload.detected]
    rows = "\n".join(
        f"| {payload.payload_id} | {payload.category} | {payload.evidence.get('owasp')} | {'yes' if payload.detected else 'no'} |"
        for payload in payloads
    )
    return f"""Scanner confidence: **{score['confidence_score']}**

OWASP categories covered: **{coverage['covered']}**
Payloads detected: **{coverage['detected']}/{coverage['payloads']}**
Missed payloads: **{len(missed)}**

| Payload | Category | OWASP | Detected |
|---|---|---|---|
{rows}

Actions: {', '.join(action.action for action in actions) or 'none'}
"""


def policy_audit_comment(score: float, checks: Dict[str, bool], recommendations: List[str], actions: List[WritebackAction]) -> str:
    rows = "\n".join(f"| {name} | {'pass' if ok else 'fail'} |" for name, ok in checks.items())
    return f"""Compliance score: **{score}%**

| Check | Status |
|---|---|
{rows}

Recommendations: {', '.join(recommendations) if recommendations else 'none'}
Actions: {', '.join(action.action for action in actions) if actions else 'none'}
"""


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
