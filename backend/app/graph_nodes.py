from hashlib import sha256
from typing import Any, Literal, TypeAlias

from pydantic import BaseModel, Field, field_validator


GraphNodeType: TypeAlias = Literal[
    "source_repo",
    "artifact",
    "evidence_span",
    "tool",
    "parameter",
    "capability",
    "env_var",
    "external_domain",
    "dependency",
    "maintainer",
    "finding",
    "policy_rule",
    "scan_run",
    "sandbox_task",
    "unsafe_action",
]

GRAPH_NODE_TYPES: tuple[str, ...] = (
    "source_repo",
    "artifact",
    "evidence_span",
    "tool",
    "parameter",
    "capability",
    "env_var",
    "external_domain",
    "dependency",
    "maintainer",
    "finding",
    "policy_rule",
    "scan_run",
    "sandbox_task",
    "unsafe_action",
)


class GraphNode(BaseModel):
    node_id: str
    node_type: GraphNodeType
    label: str
    source_id: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("node_id", "label")
    @classmethod
    def _must_not_be_blank(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("graph node identifiers and labels must not be blank.")
        return value


class SourceRepoNode(GraphNode):
    node_type: Literal["source_repo"] = "source_repo"
    source_id: str
    source_url: str
    canonical_url: str | None = None
    owner: str | None = None
    repo_name: str | None = None
    trust_tier: str = "unknown"


class ArtifactNode(GraphNode):
    node_type: Literal["artifact"] = "artifact"
    artifact_id: str
    source_id: str
    path: str
    artifact_type: str
    content_hash: str


class EvidenceSpanNode(GraphNode):
    node_type: Literal["evidence_span"] = "evidence_span"
    span_id: str
    artifact_id: str
    start_line: int = Field(ge=1)
    end_line: int = Field(ge=1)
    span_type: str
    content_hash: str


class ToolNode(GraphNode):
    node_type: Literal["tool"] = "tool"
    tool_id: str
    source_id: str
    name: str
    description: str | None = None


class ParameterNode(GraphNode):
    node_type: Literal["parameter"] = "parameter"
    tool_id: str
    name: str
    required: bool = False
    description: str | None = None


class CapabilityNode(GraphNode):
    node_type: Literal["capability"] = "capability"
    capability_id: str
    name: str
    risk_weight: int = Field(default=0, ge=0)
    description: str | None = None


class EnvVarNode(GraphNode):
    node_type: Literal["env_var"] = "env_var"
    name: str
    sensitive: bool = False


class ExternalDomainNode(GraphNode):
    node_type: Literal["external_domain"] = "external_domain"
    domain: str


class DependencyNode(GraphNode):
    node_type: Literal["dependency"] = "dependency"
    name: str
    version: str | None = None
    ecosystem: str | None = None


class MaintainerNode(GraphNode):
    node_type: Literal["maintainer"] = "maintainer"
    handle: str
    platform: str | None = None


class FindingNode(GraphNode):
    node_type: Literal["finding"] = "finding"
    finding_id: str
    source_id: str
    finding_type: str
    severity: str
    confidence: float = Field(ge=0.0, le=1.0)


class PolicyRuleNode(GraphNode):
    node_type: Literal["policy_rule"] = "policy_rule"
    policy_rule_id: str
    action: str
    description: str | None = None


class ScanRunNode(GraphNode):
    node_type: Literal["scan_run"] = "scan_run"
    run_id: str
    source_id: str
    status: str
    risk_score: int | None = Field(default=None, ge=0, le=100)


class SandboxTaskNode(GraphNode):
    node_type: Literal["sandbox_task"] = "sandbox_task"
    sandbox_task_id: str
    name: str
    task_type: str


class UnsafeActionNode(GraphNode):
    node_type: Literal["unsafe_action"] = "unsafe_action"
    unsafe_action_id: str
    action_type: str
    severity: str


GraphNodeModel: TypeAlias = (
    SourceRepoNode
    | ArtifactNode
    | EvidenceSpanNode
    | ToolNode
    | ParameterNode
    | CapabilityNode
    | EnvVarNode
    | ExternalDomainNode
    | DependencyNode
    | MaintainerNode
    | FindingNode
    | PolicyRuleNode
    | ScanRunNode
    | SandboxTaskNode
    | UnsafeActionNode
)


def make_graph_node_id(node_type: GraphNodeType, raw_id: str) -> str:
    if node_type not in GRAPH_NODE_TYPES:
        raise ValueError("unknown graph node type.")
    if not raw_id.strip():
        raise ValueError("raw graph node id must not be blank.")
    digest = sha256(f"{node_type}:{raw_id}".encode("utf-8")).hexdigest()[:16]
    return f"{node_type}_{digest}"
