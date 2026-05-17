"""End-to-end demo scenario."""

from __future__ import annotations

from .factory import Engines
from .models import (
    ControlPayloadResult,
    ControlRunInput,
    DecisionInput,
    FindingInput,
    IncidentInput,
    MergeRequestInput,
    PackageInput,
    PolicyEvaluationInput,
    RuntimeEventInput,
)


def load_demo(engines: Engines) -> dict:
    engines.store.reset()
    repo = "payments-platform"

    engines.memory.add_decision(
        DecisionInput(
            repo=repo,
            decision_id="SEC-001",
            title="Gateway tokens require issuer, audience, expiry, and role validation",
            text="Every gateway-facing service must validate token issuer, audience, expiration, and role before forwarding requests.",
            governs=["services/gateway/auth_middleware.py", "services/identity/session.py"],
            tags=["auth", "jwt", "gateway", "validation"],
            evidence={"source": "architecture-review"},
        )
    )
    engines.memory.add_decision(
        DecisionInput(
            repo=repo,
            decision_id="SEC-002",
            title="Generated authentication logic requires negative tests",
            text="AI-assisted changes to authentication and authorization logic must include forged-token and missing-claim tests.",
            governs=["services/gateway", "services/identity"],
            tags=["auth", "ai", "test"],
            evidence={"source": "security-standard"},
        )
    )

    control = engines.controls.record_run(
        ControlRunInput(
            control_id="pre-merge-security-suite",
            control_type="scanner-validation",
            repo=repo,
            scanner="default-security-controls",
            payloads=[
                ControlPayloadResult(payload_id="sqli-001", category="sql-injection", detected=True, severity="high"),
                ControlPayloadResult(payload_id="xss-001", category="xss", detected=True, severity="medium"),
                ControlPayloadResult(payload_id="cmd-001", category="command-injection", detected=True, severity="critical"),
                ControlPayloadResult(payload_id="crypto-001", category="weak-crypto", detected=True, severity="high"),
                ControlPayloadResult(payload_id="path-001", category="path-traversal", detected=True, severity="high"),
                ControlPayloadResult(payload_id="ssrf-001", category="ssrf", detected=False, severity="critical"),
                ControlPayloadResult(payload_id="secret-jwt-001", category="jwt-secret", detected=False, severity="critical"),
                ControlPayloadResult(payload_id="dep-vendored-001", category="vendored-dependency", detected=False, severity="high"),
            ],
            policy_checks={"protected_branches": True, "approval_policy": True, "squash_merge_policy": False},
        )
    )

    package = engines.supply_chain.analyze(
        PackageInput(
            ecosystem="pypi",
            name="jwt-lite",
            version="2.4.0",
            repo=repo,
            maintainer_count=1,
            new_maintainer=True,
            ownership_changed=True,
            signed=False,
            provenance=False,
            typo_similarity_to="pyjwt",
            known_advisories=["GHSA-demo-token-bypass"],
        )
    )

    runtime = engines.runtime.ingest(
        RuntimeEventInput(
            event_id="rt-2026-05-15-001",
            source="siem",
            event_type="auth_anomaly",
            service="gateway",
            severity="high",
            signal="auth anomaly spike: forged sessions accepted at gateway",
            code_path="services/gateway/auth_middleware.py",
            repo=repo,
            attributes={"requests": 1840, "window": "15m", "attack_path": "/api/session/refresh"},
        )
    )

    mr = MergeRequestInput(
        repo=repo,
        mr_id="128",
        title="Simplify gateway session refresh",
        description="AI-assisted refactor of token parsing and gateway session refresh.",
        author="alex",
        created_at="2026-05-15T20:12:00+00:00",
        files_changed=[
            "services/gateway/auth_middleware.py",
            "services/identity/session.py",
            "services/webhook/fetcher.py",
        ],
        diff_summary="Removed duplicate issuer validation and relaxed audience checks while adding jwt-lite.",
        labels=["security-sensitive", "fast-track"],
        ai_assisted=True,
        approvals=1,
        deployment_window="Friday after-hours",
        metadata={
            "ai": {"model_family": "general-code-model", "risk_fingerprint": ["auth-logic", "missing-validation"]},
            "dependencies": [{"name": "jwt-lite", "risk_level": "critical", "new": True}],
            "developer_behavior": {"frequent_rollbacks": True, "high_regression_rate": True},
        },
    )
    risk = engines.risk.analyze_mr(mr)

    finding = engines.findings.create(
        FindingInput(
            title="Gateway session refresh can accept forged sessions",
            repo=repo,
            category="auth-bypass",
            severity="critical",
            file="services/gateway/auth_middleware.py",
            function="refresh_session",
            cwe="CWE-287",
            ghsa="GHSA-demo-token-bypass",
            service="gateway",
            mr_id="128",
            evidence={"line": 42, "reason": "Audience and issuer checks were relaxed."},
        )
    )
    evidence = engines.compliance.evidence_for_finding(finding)

    incident = engines.incidents.create_incident(
        IncidentInput(
            incident_id="inc-2026-05-16-auth",
            title="Forged session tokens accepted by gateway",
            severity="critical",
            repo=repo,
            service="gateway",
            signal="auth bypass from forged sessions",
            code_path="services/gateway/auth_middleware.py",
            customer_impact="Unauthorized access attempts reached tenant data boundary.",
            runtime_event_ids=[runtime["event"]["id"]],
        )
    )

    policy = engines.policy.evaluate(
        PolicyEvaluationInput(
            repo=repo,
            subject_id="128",
            subject_type="merge_request",
            context={**risk.passport["policy_context"], "unresolved_critical": 1},
        )
    )

    return {
        "repo": repo,
        "control_score": control.model_dump(),
        "package_risk": package,
        "runtime": runtime,
        "risk": risk.model_dump(),
        "finding": finding,
        "compliance_evidence": evidence,
        "incident": incident,
        "policy": [p.model_dump() for p in policy],
        "counts": engines.store.counts(),
    }
