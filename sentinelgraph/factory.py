"""Engine factory."""

from __future__ import annotations

from .compliance import ComplianceEngine
from .controls import ControlEngine
from .findings import FindingEngine
from .graph import SecurityGraph
from .incident import IncidentEngine
from .memory import MemoryEngine
from .policy import PolicyEngine
from .replay import ReplayEngine
from .risk import RiskEngine
from .runtime import RuntimeEngine
from .storage import Store
from .supply_chain import SupplyChainEngine


class Engines:
    def __init__(self, store: Store):
        self.store = store
        self.graph = SecurityGraph(store)
        self.memory = MemoryEngine(self.graph)
        self.controls = ControlEngine(self.graph)
        self.runtime = RuntimeEngine(self.graph)
        self.findings = FindingEngine(self.graph)
        self.compliance = ComplianceEngine(self.graph)
        self.supply_chain = SupplyChainEngine(self.graph)
        self.risk = RiskEngine(self.graph, self.memory, self.controls, self.runtime)
        self.policy = PolicyEngine(self.graph, self.controls)
        self.incidents = IncidentEngine(self.graph, self.controls, self.findings, self.compliance)
        self.replay = ReplayEngine(self.graph)


def build_engines(store: Store | None = None) -> Engines:
    return Engines(store or Store())
