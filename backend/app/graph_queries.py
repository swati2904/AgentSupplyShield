from collections import defaultdict
from typing import Any, Iterable, Literal, TypeVar

from pydantic import BaseModel

from app.graph_edges import GraphEdge, GraphEdgeType
from app.graph_nodes import (
    ArtifactNode,
    CapabilityNode,
    DependencyNode,
    EnvVarNode,
    EvidenceSpanNode,
    FindingNode,
    GraphNode,
    PolicyRuleNode,
    SandboxTaskNode,
    SourceRepoNode,
    ToolNode,
    UnsafeActionNode,
)


Direction = Literal["in", "out"]
TGraphNode = TypeVar("TGraphNode", bound=GraphNode)

INSTRUCTION_LIKE_MARKERS: tuple[str, ...] = (
    "ignore previous",
    "ignore all previous",
    "system prompt",
    "developer message",
    "follow these instructions",
    "secret instructions",
    "do not reveal",
    "prompt injection",
)

CREDENTIAL_MARKERS: tuple[str, ...] = (
    "api_key",
    "apikey",
    "credential",
    "password",
    "secret",
    "token",
)

ABANDONED_DEPENDENCY_MARKERS: tuple[str, ...] = (
    "abandoned",
    "deprecated",
    "unmaintained",
)

HIGH_SANDBOX_SEVERITIES: tuple[str, ...] = ("high", "critical")


class ToolPermissionChange(BaseModel):
    tool_id: str
    tool_name: str
    added_capability_ids: list[str]
    removed_capability_ids: list[str]


class GraphQueryIndex:
    def __init__(self, nodes: Iterable[GraphNode], edges: Iterable[GraphEdge]) -> None:
        self.nodes: tuple[GraphNode, ...] = tuple(nodes)
        self.edges: tuple[GraphEdge, ...] = tuple(edges)
        self.nodes_by_id: dict[str, GraphNode] = {}
        self._out_edges: dict[str, list[GraphEdge]] = defaultdict(list)
        self._in_edges: dict[str, list[GraphEdge]] = defaultdict(list)

        for node in self.nodes:
            if node.node_id in self.nodes_by_id:
                raise ValueError(f"duplicate graph node id: {node.node_id}")
            self.nodes_by_id[node.node_id] = node

        for edge in self.edges:
            self._require_node(edge.source_node_id)
            self._require_node(edge.target_node_id)
            self._out_edges[edge.source_node_id].append(edge)
            self._in_edges[edge.target_node_id].append(edge)

    def outgoing_edges(self, node_id: str, edge_type: GraphEdgeType | None = None) -> tuple[GraphEdge, ...]:
        return self._filtered_edges(node_id, "out", edge_type)

    def incoming_edges(self, node_id: str, edge_type: GraphEdgeType | None = None) -> tuple[GraphEdge, ...]:
        return self._filtered_edges(node_id, "in", edge_type)

    def target_nodes(self, node_id: str, edge_type: GraphEdgeType | None = None) -> tuple[GraphNode, ...]:
        return tuple(self.nodes_by_id[edge.target_node_id] for edge in self.outgoing_edges(node_id, edge_type))

    def source_nodes(self, node_id: str, edge_type: GraphEdgeType | None = None) -> tuple[GraphNode, ...]:
        return tuple(self.nodes_by_id[edge.source_node_id] for edge in self.incoming_edges(node_id, edge_type))

    def tools_with_network_access_and_credential_references(self) -> list[ToolNode]:
        return _sorted_nodes(
            tool
            for tool in self._nodes_of_type(ToolNode)
            if self._tool_has_network_access(tool) and self._tool_mentions_credentials(tool)
        )

    def repos_with_instruction_like_tool_metadata(self) -> list[SourceRepoNode]:
        repos_by_id: dict[str, SourceRepoNode] = {}
        for tool in self._nodes_of_type(ToolNode):
            if not _contains_any_marker(_text_blob(tool.name, tool.description, tool.metadata), INSTRUCTION_LIKE_MARKERS):
                continue
            for artifact in self.source_nodes(tool.node_id, "defines"):
                if not isinstance(artifact, ArtifactNode):
                    continue
                for repo in self.source_nodes(artifact.node_id, "has_artifact"):
                    if isinstance(repo, SourceRepoNode):
                        repos_by_id[repo.node_id] = repo
        return _sorted_nodes(repos_by_id.values())

    def tools_with_permission_changes(self, previous_index: "GraphQueryIndex") -> list[ToolPermissionChange]:
        previous_tools = {tool.tool_id: tool for tool in previous_index._nodes_of_type(ToolNode)}
        changes: list[ToolPermissionChange] = []

        for tool in self._nodes_of_type(ToolNode):
            previous_tool = previous_tools.get(tool.tool_id)
            if previous_tool is None:
                continue

            previous_capabilities = previous_index._tool_capability_ids(previous_tool)
            current_capabilities = self._tool_capability_ids(tool)
            added = sorted(current_capabilities - previous_capabilities)
            removed = sorted(previous_capabilities - current_capabilities)
            if added or removed:
                changes.append(
                    ToolPermissionChange(
                        tool_id=tool.tool_id,
                        tool_name=tool.name,
                        added_capability_ids=added,
                        removed_capability_ids=removed,
                    )
                )

        return sorted(changes, key=lambda change: (change.tool_name, change.tool_id))

    def high_risk_tools_connected_to_abandoned_dependencies(self, risk_weight_threshold: int = 3) -> list[ToolNode]:
        return _sorted_nodes(
            tool
            for tool in self._nodes_of_type(ToolNode)
            if self._tool_has_high_risk_capability(tool, risk_weight_threshold)
            and any(_is_abandoned_dependency(dependency) for dependency in self._tool_dependencies(tool))
        )

    def tools_with_low_static_risk_and_high_sandbox_risk(
        self,
        static_risk_threshold: float = 40.0,
        high_severities: tuple[str, ...] = HIGH_SANDBOX_SEVERITIES,
    ) -> list[ToolNode]:
        high_severity_set = {severity.lower() for severity in high_severities}
        matching_tools: list[ToolNode] = []

        for tool in self._nodes_of_type(ToolNode):
            static_risk_score = _metadata_number(tool.metadata, "static_risk_score")
            if static_risk_score is None or static_risk_score > static_risk_threshold:
                continue
            if any(
                action.severity.lower() in high_severity_set
                for task in self._sandbox_tasks_for_tool(tool)
                for action in self._unsafe_actions_for_task(task)
            ):
                matching_tools.append(tool)

        return _sorted_nodes(matching_tools)

    def evidence_for_quarantine_decisions(self) -> list[EvidenceSpanNode]:
        evidence_by_id: dict[str, EvidenceSpanNode] = {}
        for finding in self._nodes_of_type(FindingNode):
            if not self._finding_has_quarantine_decision(finding):
                continue
            for evidence_span in self.source_nodes(finding.node_id, "triggers"):
                if isinstance(evidence_span, EvidenceSpanNode):
                    evidence_by_id[evidence_span.node_id] = evidence_span
        return _sorted_nodes(evidence_by_id.values())

    def _filtered_edges(
        self, node_id: str, direction: Direction, edge_type: GraphEdgeType | None
    ) -> tuple[GraphEdge, ...]:
        self._require_node(node_id)
        edges = self._out_edges[node_id] if direction == "out" else self._in_edges[node_id]
        if edge_type is None:
            return tuple(edges)
        return tuple(edge for edge in edges if edge.edge_type == edge_type)

    def _nodes_of_type(self, model_type: type[TGraphNode]) -> tuple[TGraphNode, ...]:
        return tuple(node for node in self.nodes if isinstance(node, model_type))

    def _tool_capabilities(self, tool: ToolNode) -> tuple[CapabilityNode, ...]:
        return tuple(node for node in self.target_nodes(tool.node_id, "requires") if isinstance(node, CapabilityNode))

    def _tool_capability_ids(self, tool: ToolNode) -> set[str]:
        return {capability.capability_id for capability in self._tool_capabilities(tool)}

    def _tool_env_vars(self, tool: ToolNode) -> tuple[EnvVarNode, ...]:
        return tuple(node for node in self.target_nodes(tool.node_id, "mentions") if isinstance(node, EnvVarNode))

    def _tool_dependencies(self, tool: ToolNode) -> tuple[DependencyNode, ...]:
        return tuple(node for node in self.target_nodes(tool.node_id, "depends_on") if isinstance(node, DependencyNode))

    def _sandbox_tasks_for_tool(self, tool: ToolNode) -> tuple[SandboxTaskNode, ...]:
        return tuple(node for node in self.source_nodes(tool.node_id, "used") if isinstance(node, SandboxTaskNode))

    def _unsafe_actions_for_task(self, task: SandboxTaskNode) -> tuple[UnsafeActionNode, ...]:
        return tuple(node for node in self.target_nodes(task.node_id, "produced") if isinstance(node, UnsafeActionNode))

    def _tool_has_network_access(self, tool: ToolNode) -> bool:
        return any("network" in _text_blob(capability.capability_id, capability.name).lower() for capability in self._tool_capabilities(tool))

    def _tool_mentions_credentials(self, tool: ToolNode) -> bool:
        return any(
            env_var.sensitive or _contains_any_marker(_text_blob(env_var.name, env_var.metadata), CREDENTIAL_MARKERS)
            for env_var in self._tool_env_vars(tool)
        )

    def _tool_has_high_risk_capability(self, tool: ToolNode, risk_weight_threshold: int) -> bool:
        return any(capability.risk_weight >= risk_weight_threshold for capability in self._tool_capabilities(tool))

    def _finding_has_quarantine_decision(self, finding: FindingNode) -> bool:
        if str(finding.metadata.get("policy_decision", "")).lower() == "quarantine":
            return True
        return any(
            isinstance(rule, PolicyRuleNode) and rule.action.lower() == "quarantine"
            for rule in self.target_nodes(finding.node_id, "violates")
        )

    def _require_node(self, node_id: str) -> None:
        if node_id not in self.nodes_by_id:
            raise ValueError(f"graph edge references missing node: {node_id}")


def _is_abandoned_dependency(dependency: DependencyNode) -> bool:
    if dependency.metadata.get("abandoned") is True:
        return True
    return _contains_any_marker(_text_blob(dependency.metadata), ABANDONED_DEPENDENCY_MARKERS)


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


def _sorted_nodes(nodes: Iterable[TGraphNode]) -> list[TGraphNode]:
    return sorted(nodes, key=lambda node: (node.label, node.node_id))
