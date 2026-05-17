"""Policy-as-code evaluation."""

from __future__ import annotations

from typing import Dict, List

from .controls import ControlEngine
from .graph import SecurityGraph
from .models import PolicyEvaluationInput, PolicyResult


class PolicyEngine:
    def __init__(self, graph: SecurityGraph, controls: ControlEngine):
        self.graph = graph
        self.controls = controls

    def evaluate(self, item: PolicyEvaluationInput) -> List[PolicyResult]:
        context = item.context
        results: List[PolicyResult] = []
        risk_score = float(context.get("risk_score", 0))
        approvals = int(context.get("approvals", 0))
        touches_auth = bool(context.get("touches_auth", False))
        unresolved_critical = int(context.get("unresolved_critical", 0))
        scanner_context = self.controls.latest_context(item.repo)
        average_confidence = scanner_context.get("average_confidence")

        if touches_auth and approvals < 2:
            results.append(
                PolicyResult(
                    policy_id="auth-change-two-approvals",
                    title="Authentication changes require two approvals",
                    status="fail",
                    severity="high",
                    message="Authentication-sensitive changes need at least two approvals.",
                    evidence={"approvals": approvals},
                )
            )
        else:
            results.append(
                PolicyResult(
                    policy_id="auth-change-two-approvals",
                    title="Authentication changes require two approvals",
                    status="pass",
                    severity="high",
                    message="Approval requirement is satisfied.",
                    evidence={"approvals": approvals},
                )
            )

        if risk_score >= 80:
            results.append(
                PolicyResult(
                    policy_id="critical-risk-manual-review",
                    title="Critical risk requires manual security review",
                    status="fail",
                    severity="critical",
                    message="Risk score is critical and cannot be auto-approved.",
                    evidence={"risk_score": risk_score},
                )
            )
        elif risk_score >= 60:
            results.append(
                PolicyResult(
                    policy_id="critical-risk-manual-review",
                    title="Critical risk requires manual security review",
                    status="warn",
                    severity="high",
                    message="Risk score is high; require focused review.",
                    evidence={"risk_score": risk_score},
                )
            )

        if unresolved_critical > 0:
            results.append(
                PolicyResult(
                    policy_id="block-critical-findings",
                    title="Block unresolved critical findings",
                    status="fail",
                    severity="critical",
                    message="Critical findings remain unresolved.",
                    evidence={"unresolved_critical": unresolved_critical},
                )
            )
        else:
            results.append(
                PolicyResult(
                    policy_id="block-critical-findings",
                    title="Block unresolved critical findings",
                    status="pass",
                    severity="critical",
                    message="No unresolved critical findings were supplied.",
                    evidence={"unresolved_critical": unresolved_critical},
                )
            )

        if average_confidence is not None and float(average_confidence) < 75:
            results.append(
                PolicyResult(
                    policy_id="control-confidence-floor",
                    title="Security controls must maintain confidence floor",
                    status="warn",
                    severity="medium",
                    message="One or more controls have weak recent validation coverage.",
                    evidence=scanner_context,
                )
            )

        return results

    def rego_template(self) -> str:
        return """
package sentinelgraph.policy

deny[msg] {
  input.touches_auth
  input.approvals < 2
  msg := "authentication-sensitive changes require at least two approvals"
}

deny[msg] {
  input.risk_score >= 80
  msg := "critical risk score requires manual security review"
}

warn[msg] {
  input.control_confidence < 75
  msg := "recent control validation confidence is below threshold"
}
""".strip()
