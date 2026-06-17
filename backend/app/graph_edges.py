from hashlib import sha256
from typing import Any, Literal, TypeAlias

from pydantic import BaseModel, Field, field_validator, model_validator

from app.graph_nodes import GraphNodeType


GraphEdgeType: TypeAlias = Literal[
    "has_artifact",
    "defines",
    "has_parameter",
    "requires",
    "mentions",
    "calls",
    "depends_on",
    "contains",
    "triggers",
    "violates",
    "observed",
    "used",
    "produced",
]

GRAPH_EDGE_TYPES: tuple[str, ...] = (
    "has_artifact",
    "defines",
    "has_parameter",
    "requires",
    "mentions",
    "calls",
    "depends_on",
    "contains",
    "triggers",
    "violates",
    "observed",
    "used",
    "produced",
)

GRAPH_EDGE_SPECS: dict[str, tuple[GraphNodeType, GraphNodeType]] = {
    "has_artifact": ("source_repo", "artifact"),
    "defines": ("artifact", "tool"),
    "has_parameter": ("tool", "parameter"),
    "requires": ("tool", "capability"),
    "mentions": ("tool", "env_var"),
    "calls": ("tool", "external_domain"),
    "depends_on": ("tool", "dependency"),
    "contains": ("artifact", "evidence_span"),
    "triggers": ("evidence_span", "finding"),
    "violates": ("finding", "policy_rule"),
    "observed": ("scan_run", "finding"),
    "used": ("sandbox_task", "tool"),
    "produced": ("sandbox_task", "unsafe_action"),
}


class GraphEdge(BaseModel):
    edge_id: str
    edge_type: GraphEdgeType
    source_node_id: str
    source_node_type: GraphNodeType
    target_node_id: str
    target_node_type: GraphNodeType
    weight: float = Field(default=1.0, ge=0.0)
    evidence_span_ids: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("edge_id", "source_node_id", "target_node_id")
    @classmethod
    def _must_not_be_blank(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("graph edge identifiers must not be blank.")
        return value

    @field_validator("evidence_span_ids")
    @classmethod
    def _evidence_span_ids_must_not_be_blank(cls, value: list[str]) -> list[str]:
        if any(not span_id.strip() for span_id in value):
            raise ValueError("evidence span identifiers must not be blank.")
        return value

    @model_validator(mode="after")
    def _must_match_roadmap_edge_spec(self) -> "GraphEdge":
        expected_source, expected_target = GRAPH_EDGE_SPECS[self.edge_type]
        if self.source_node_type != expected_source or self.target_node_type != expected_target:
            raise ValueError(
                f"{self.edge_type} edges must connect {expected_source} to {expected_target}."
            )
        return self


def make_graph_edge_id(edge_type: GraphEdgeType, source_node_id: str, target_node_id: str) -> str:
    if edge_type not in GRAPH_EDGE_SPECS:
        raise ValueError("unknown graph edge type.")
    if not source_node_id.strip() or not target_node_id.strip():
        raise ValueError("graph edge endpoint ids must not be blank.")
    digest = sha256(f"{edge_type}:{source_node_id}:{target_node_id}".encode("utf-8")).hexdigest()[:16]
    return f"{edge_type}_{digest}"
