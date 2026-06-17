from collections import defaultdict, deque
from typing import Any, Iterable, TypeVar

from pydantic import BaseModel, Field

from app.graph_edges import GraphEdgeType
from app.graph_nodes import (
    ArtifactNode,
    CapabilityNode,
    DependencyNode,
    EnvVarNode,
    EvidenceSpanNode,
    ExternalDomainNode,
    FindingNode,
    GraphNode,
    ToolNode,
)
from app.graph_queries import GraphQueryIndex


TGraphNode = TypeVar("TGraphNode", bound=GraphNode)

GRAPH_RISK_FEATURE_NAMES: tuple[str, ...] = (
    "external_communication_degree",
    "sensitive_env_var_count",
    "permission_count",
    "high_risk_dependency_count",
    "suspicious_span_to_tool_description_distance",
    "recent_metadata_change_count",
    "independent_finding_count",
)

SUSPICIOUS_SPAN_MARKERS: tuple[str, ...] = (
    "suspicious",
    "prompt_injection",
    "prompt injection",
    "instruction",
)

HIGH_RISK_DEPENDENCY_MARKERS: tuple[str, ...] = (
    "abandoned",
    "deprecated",
    "malicious",
    "unmaintained",
    "vulnerable",
)

RECENT_METADATA_CHANGE_KEYS: tuple[str, ...] = (
    "recent_metadata_changes",
    "metadata_changes",
    "metadata_change_count",
    "recent_change_count",
)


class GraphRiskFeatures(BaseModel):
    tool_node_id: str
    tool_id: str
    tool_name: str
    external_communication_degree: int = Field(ge=0)
    sensitive_env_var_count: int = Field(ge=0)
    permission_count: int = Field(ge=0)
    high_risk_dependency_count: int = Field(ge=0)
    suspicious_span_to_tool_description_distance: int | None = Field(default=None, ge=0)
    recent_metadata_change_count: int = Field(ge=0)
    independent_finding_count: int = Field(ge=0)


def derive_graph_risk_features(index: GraphQueryIndex) -> list[GraphRiskFeatures]:
    tools = sorted(_nodes_of_type(index.nodes, ToolNode), key=lambda tool: (tool.label, tool.node_id))
    return [derive_tool_risk_features(index, tool) for tool in tools]


def derive_tool_risk_features(
    index: GraphQueryIndex,
    tool: ToolNode,
    high_risk_dependency_score_threshold: float = 70.0,
) -> GraphRiskFeatures:
    domains = _targets_of_type(index, tool.node_id, "calls", ExternalDomainNode)
    env_vars = _targets_of_type(index, tool.node_id, "mentions", EnvVarNode)
    capabilities = _targets_of_type(index, tool.node_id, "requires", CapabilityNode)
    dependencies = _targets_of_type(index, tool.node_id, "depends_on", DependencyNode)

    return GraphRiskFeatures(
        tool_node_id=tool.node_id,
        tool_id=tool.tool_id,
        tool_name=tool.name,
        external_communication_degree=len({domain.domain for domain in domains}),
        sensitive_env_var_count=sum(1 for env_var in env_vars if env_var.sensitive),
        permission_count=len({capability.capability_id for capability in capabilities}),
        high_risk_dependency_count=sum(
            1
            for dependency in dependencies
            if _is_high_risk_dependency(dependency, high_risk_dependency_score_threshold)
        ),
        suspicious_span_to_tool_description_distance=_suspicious_span_distance(index, tool),
        recent_metadata_change_count=_recent_metadata_change_count(tool.metadata),
        independent_finding_count=len(_finding_ids_for_tool(index, tool)),
    )


def _suspicious_span_distance(index: GraphQueryIndex, tool: ToolNode) -> int | None:
    distances = [
        distance
        for span in _evidence_spans_for_tool(index, tool)
        if _is_suspicious_span(index, span)
        for distance in [_shortest_undirected_distance(index, span.node_id, tool.node_id)]
        if distance is not None
    ]
    if not distances:
        return None
    return min(distances)


def _finding_ids_for_tool(index: GraphQueryIndex, tool: ToolNode) -> set[str]:
    finding_ids: set[str] = set()
    for span in _evidence_spans_for_tool(index, tool):
        for finding in _targets_of_type(index, span.node_id, "triggers", FindingNode):
            finding_ids.add(finding.finding_id)
    return finding_ids


def _evidence_spans_for_tool(index: GraphQueryIndex, tool: ToolNode) -> tuple[EvidenceSpanNode, ...]:
    spans: list[EvidenceSpanNode] = []
    for artifact in _sources_of_type(index, tool.node_id, "defines", ArtifactNode):
        spans.extend(_targets_of_type(index, artifact.node_id, "contains", EvidenceSpanNode))
    return tuple(spans)


def _is_suspicious_span(index: GraphQueryIndex, span: EvidenceSpanNode) -> bool:
    if span.metadata.get("suspicious") is True:
        return True
    if _contains_any_marker(_text_blob(span.span_type, span.label, span.metadata), SUSPICIOUS_SPAN_MARKERS):
        return True
    return any(
        _contains_any_marker(_text_blob(finding.finding_type, finding.severity, finding.metadata), SUSPICIOUS_SPAN_MARKERS)
        for finding in _targets_of_type(index, span.node_id, "triggers", FindingNode)
    )


def _is_high_risk_dependency(dependency: DependencyNode, score_threshold: float) -> bool:
    if dependency.metadata.get("high_risk") is True:
        return True
    risk_score = _metadata_number(dependency.metadata, "risk_score")
    if risk_score is not None and risk_score >= score_threshold:
        return True
    return _contains_any_marker(_text_blob(dependency.name, dependency.metadata), HIGH_RISK_DEPENDENCY_MARKERS)


def _recent_metadata_change_count(metadata: dict[str, Any]) -> int:
    for key in RECENT_METADATA_CHANGE_KEYS:
        if key in metadata:
            return _count_metadata_value(metadata[key])
    return 0


def _count_metadata_value(value: Any) -> int:
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int | float):
        return max(0, int(value))
    if isinstance(value, str):
        try:
            return max(0, int(float(value)))
        except ValueError:
            return 1 if value.strip() else 0
    if isinstance(value, dict):
        return len(value)
    if isinstance(value, list | tuple | set):
        return len(value)
    return 0


def _targets_of_type(
    index: GraphQueryIndex,
    node_id: str,
    edge_type: GraphEdgeType,
    model_type: type[TGraphNode],
) -> tuple[TGraphNode, ...]:
    return tuple(node for node in index.target_nodes(node_id, edge_type) if isinstance(node, model_type))


def _sources_of_type(
    index: GraphQueryIndex,
    node_id: str,
    edge_type: GraphEdgeType,
    model_type: type[TGraphNode],
) -> tuple[TGraphNode, ...]:
    return tuple(node for node in index.source_nodes(node_id, edge_type) if isinstance(node, model_type))


def _nodes_of_type(nodes: Iterable[GraphNode], model_type: type[TGraphNode]) -> tuple[TGraphNode, ...]:
    return tuple(node for node in nodes if isinstance(node, model_type))


def _shortest_undirected_distance(index: GraphQueryIndex, start_node_id: str, target_node_id: str) -> int | None:
    if start_node_id == target_node_id:
        return 0

    adjacency: dict[str, set[str]] = defaultdict(set)
    for edge in index.edges:
        adjacency[edge.source_node_id].add(edge.target_node_id)
        adjacency[edge.target_node_id].add(edge.source_node_id)

    visited = {start_node_id}
    queue: deque[tuple[str, int]] = deque([(start_node_id, 0)])

    while queue:
        node_id, distance = queue.popleft()
        for next_node_id in adjacency[node_id]:
            if next_node_id in visited:
                continue
            if next_node_id == target_node_id:
                return distance + 1
            visited.add(next_node_id)
            queue.append((next_node_id, distance + 1))

    return None


def _metadata_number(metadata: dict[str, Any], key: str) -> float | None:
    value = metadata.get(key)
    if isinstance(value, int | float):
        return float(value)
    if isinstance(value, str):
        try:
            return float(value)
        except ValueError:
            return None
    return None


def _contains_any_marker(text: str, markers: tuple[str, ...]) -> bool:
    lowered = text.lower()
    return any(marker in lowered for marker in markers)


def _text_blob(*values: Any) -> str:
    pieces: list[str] = []

    def collect(value: Any) -> None:
        if value is None:
            return
        if isinstance(value, dict):
            for key, nested_value in value.items():
                collect(key)
                collect(nested_value)
            return
        if isinstance(value, list | tuple | set):
            for nested_value in value:
                collect(nested_value)
            return
        pieces.append(str(value))

    for value in values:
        collect(value)
    return " ".join(pieces)
