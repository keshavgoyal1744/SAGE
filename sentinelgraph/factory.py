"""Engine factory."""

from __future__ import annotations

from .advisory import AdvisoryEngine
from .compliance import ComplianceEngine
from .controls import ControlEngine
from .exploitability import ExploitabilityEngine
from .findings import FindingEngine
from .graph import SecurityGraph
from .governance import AICodeGovernanceEngine, SecurityDebateEngine
from .incident import IncidentEngine
from .memory import MemoryEngine
from .memory_suite import MemorySuite
from .policy import PolicyEngine
from .regression import CiOptimizer, RegressionEngine
from .reputation import ReputationEngine
from .replay import ReplayEngine
from .risk import RiskEngine
from .runtime import RuntimeEngine
from .security_audit import FullSecurityAuditEngine, RemediationVerificationEngine, ScannerChaosEngine, SecurityPolicyAuditor, VulnerabilityTriageEngine
from .storage import Store
from .supply_chain import SupplyChainEngine


class Engines:
    def __init__(self, store: Store):
        self.store = store
        self.graph = SecurityGraph(store)
        self.memory = MemoryEngine(self.graph)
        self.memory_suite = MemorySuite(self.graph)
        self.advisory = AdvisoryEngine()
        self.controls = ControlEngine(self.graph)
        self.runtime = RuntimeEngine(self.graph)
        self.findings = FindingEngine(self.graph)
        self.compliance = ComplianceEngine(self.graph)
        self.supply_chain = SupplyChainEngine(self.graph)
        self.exploitability = ExploitabilityEngine(self.graph)
        self.ai_governance = AICodeGovernanceEngine(self.graph)
        self.security_debate = SecurityDebateEngine(self.graph)
        self.risk = RiskEngine(self.graph, self.memory, self.controls, self.runtime)
        self.policy = PolicyEngine(self.graph, self.controls)
        self.incidents = IncidentEngine(self.graph, self.controls, self.findings, self.compliance)
        self.replay = ReplayEngine(self.graph)
        self.scanner_chaos = ScannerChaosEngine(self.controls)
        self.policy_audit = SecurityPolicyAuditor()
        self.vulnerability_triage = VulnerabilityTriageEngine()
        self.remediation_verification = RemediationVerificationEngine()
        self.full_security_audit = FullSecurityAuditEngine(
            self.scanner_chaos,
            self.policy_audit,
            self.vulnerability_triage,
            self.remediation_verification,
        )
        self.regression = RegressionEngine(self.graph, self.findings)
        self.ci_optimizer = CiOptimizer()
        self.reputation = ReputationEngine(store)


def build_engines(store: Store | None = None) -> Engines:
    return Engines(store or Store())
