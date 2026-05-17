"""API and service models."""

from __future__ import annotations

from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, Field


EntityType = Literal[
    "repo",
    "service",
    "merge_request",
    "developer",
    "scanner",
    "control",
    "finding",
    "cve",
    "dependency",
    "incident",
    "decision",
    "deployment",
    "runtime_event",
    "customer_impact",
    "test",
    "fix_pattern",
    "agent",
    "cloud_resource",
    "policy",
    "compliance_evidence",
    "integration",
    "webhook_event",
]


class Entity(BaseModel):
    id: str
    type: EntityType
    name: str
    attributes: Dict[str, Any] = Field(default_factory=dict)


class Edge(BaseModel):
    id: Optional[int] = None
    source: str
    target: str
    relation: str
    attributes: Dict[str, Any] = Field(default_factory=dict)


class DecisionInput(BaseModel):
    repo: str
    decision_id: str
    title: str
    text: str
    governs: List[str] = Field(default_factory=list)
    security_relevant: bool = True
    status: str = "active"
    tags: List[str] = Field(default_factory=list)
    evidence: Dict[str, Any] = Field(default_factory=dict)


class MergeRequestInput(BaseModel):
    repo: str
    mr_id: str
    title: str
    description: str = ""
    author: str
    source_branch: str = ""
    target_branch: str = "main"
    created_at: Optional[str] = None
    merged_at: Optional[str] = None
    files_changed: List[str] = Field(default_factory=list)
    diff_summary: str = ""
    commits: List[str] = Field(default_factory=list)
    labels: List[str] = Field(default_factory=list)
    ai_assisted: bool = False
    approvals: int = 0
    deployment_window: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)


class SourceComment(BaseModel):
    id: str
    author: str = ""
    body: str = ""
    created_at: Optional[str] = None


class SourceChangeRecord(BaseModel):
    provider: Literal["gitlab", "github", "fixture"]
    repo: str
    mr_id: str
    title: str
    description: str = ""
    author: str = ""
    source_branch: str = ""
    target_branch: str = "main"
    state: str = ""
    created_at: Optional[str] = None
    merged_at: Optional[str] = None
    files_changed: List[str] = Field(default_factory=list)
    diff_summary: str = ""
    commits: List[str] = Field(default_factory=list)
    labels: List[str] = Field(default_factory=list)
    approvals: int = 0
    comments: List[SourceComment] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)


class SourceImportRequest(BaseModel):
    provider: Literal["gitlab", "github"]
    repo: str
    token: Optional[str] = None
    token_env: Optional[str] = None
    base_url: Optional[str] = None
    limit: int = 100
    include_closed: bool = True
    import_decisions: bool = True
    analyze: bool = True


class FixtureImportRequest(BaseModel):
    records: List[SourceChangeRecord]
    import_decisions: bool = True
    analyze: bool = True


class SourceImportResult(BaseModel):
    provider: str
    repo: str
    imported: int
    analyzed: int
    decisions_imported: int
    high_or_critical: int
    errors: List[str] = Field(default_factory=list)
    analyses: List[Dict[str, Any]] = Field(default_factory=list)


class RuntimeEventInput(BaseModel):
    event_id: str
    source: str
    event_type: str
    service: str
    severity: str = "medium"
    signal: str
    code_path: Optional[str] = None
    repo: Optional[str] = None
    attributes: Dict[str, Any] = Field(default_factory=dict)


class ControlPayloadResult(BaseModel):
    payload_id: str
    category: str
    expected: bool = True
    detected: bool = False
    severity: str = "medium"
    evidence: Dict[str, Any] = Field(default_factory=dict)


class ControlRunInput(BaseModel):
    control_id: str
    control_type: str
    repo: str
    scanner: str
    payloads: List[ControlPayloadResult]
    policy_checks: Dict[str, bool] = Field(default_factory=dict)
    metadata: Dict[str, Any] = Field(default_factory=dict)


class PackageInput(BaseModel):
    ecosystem: str
    name: str
    version: str
    repo: Optional[str] = None
    maintainer_count: int = 1
    new_maintainer: bool = False
    ownership_changed: bool = False
    signed: bool = False
    provenance: bool = False
    days_since_last_release: Optional[int] = None
    typo_similarity_to: Optional[str] = None
    known_advisories: List[str] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)


class IncidentInput(BaseModel):
    incident_id: str
    title: str
    severity: str
    repo: str
    service: str
    signal: str
    code_path: Optional[str] = None
    customer_impact: Optional[str] = None
    runtime_event_ids: List[str] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)


class PolicyEvaluationInput(BaseModel):
    repo: str
    subject_id: str
    subject_type: str = "merge_request"
    context: Dict[str, Any] = Field(default_factory=dict)


class RiskReason(BaseModel):
    code: str
    message: str
    weight: float
    evidence: Dict[str, Any] = Field(default_factory=dict)


class RiskResult(BaseModel):
    repo: str
    mr_id: str
    score: float
    level: Literal["low", "medium", "high", "critical"]
    reasons: List[RiskReason]
    linked_entities: List[Entity] = Field(default_factory=list)
    recommended_actions: List[str] = Field(default_factory=list)
    passport: Dict[str, Any] = Field(default_factory=dict)


class ControlScore(BaseModel):
    control_id: str
    confidence_score: float
    decay_score: float
    blind_spot_score: float
    exploit_coverage_score: float
    detected: int
    missed: int
    blind_spots: List[str]
    recommendations: List[str]


class FindingInput(BaseModel):
    title: str
    repo: str
    category: str
    severity: str
    file: Optional[str] = None
    function: Optional[str] = None
    cwe: Optional[str] = None
    cve: Optional[str] = None
    ghsa: Optional[str] = None
    service: Optional[str] = None
    mr_id: Optional[str] = None
    evidence: Dict[str, Any] = Field(default_factory=dict)


class HuntResult(BaseModel):
    incident_id: str
    siblings_found: int
    findings: List[Dict[str, Any]]
    patches: List[Dict[str, Any]]
    tests: List[Dict[str, Any]]
    scanner_gaps: List[Dict[str, Any]]


class PolicyResult(BaseModel):
    policy_id: str
    title: str
    status: Literal["pass", "fail", "warn"]
    severity: str
    message: str
    evidence: Dict[str, Any] = Field(default_factory=dict)


class ReplayEvent(BaseModel):
    timestamp: str
    type: str
    title: str
    entity_id: str
    details: Dict[str, Any] = Field(default_factory=dict)
