import pytest

from app.graph_edges import GraphEdge, GraphEdgeType, make_graph_edge_id
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
    make_graph_node_id,
)
from app.graph_queries import GraphQueryIndex


def test_graph_query_index_exposes_basic_adjacency() -> None:
    index = _example_query_index()
    tool = _tool(index)

    outgoing_types = [edge.edge_type for edge in index.outgoing_edges(tool.node_id)]
    incoming_sources = [node.node_type for node in index.source_nodes(tool.node_id, "defines")]

    assert outgoing_types == ["requires", "mentions", "depends_on"]
    assert incoming_sources == ["artifact"]


def test_tools_with_network_access_and_credential_references() -> None:
    index = _example_query_index()

    tools = index.tools_with_network_access_and_credential_references()

    assert [tool.name for tool in tools] == ["calendar_reader"]


def test_repos_with_instruction_like_tool_metadata() -> None:
    index = _example_query_index()

    repos = index.repos_with_instruction_like_tool_metadata()

    assert [repo.repo_name for repo in repos] == ["safe-tool"]


def test_tools_with_permission_changes_between_indexes() -> None:
    previous_index = _permission_index(include_network=False)
    current_index = _permission_index(include_network=True)

    changes = current_index.tools_with_permission_changes(previous_index)

    assert len(changes) == 1
    assert changes[0].tool_name == "calendar_reader"
    assert changes[0].added_capability_ids == ["network_access"]
    assert changes[0].removed_capability_ids == []


def test_high_risk_tools_connected_to_abandoned_dependencies() -> None:
    index = _example_query_index()

    tools = index.high_risk_tools_connected_to_abandoned_dependencies()

    assert [tool.name for tool in tools] == ["calendar_reader"]


def test_sandbox_mismatch_and_quarantine_evidence_queries() -> None:
    index = _example_query_index()

    mismatch_tools = index.tools_with_low_static_risk_and_high_sandbox_risk()
    quarantine_evidence = index.evidence_for_quarantine_decisions()

    assert [tool.name for tool in mismatch_tools] == ["calendar_reader"]
    assert [span.span_id for span in quarantine_evidence] == ["span_1"]


def test_query_index_rejects_duplicate_nodes_and_dangling_edges() -> None:
    source = _source()
    duplicate_source = source.model_copy()
    artifact = _artifact(source)
    dangling_edge = _edge("has_artifact", source, artifact)

    with pytest.raises(ValueError, match="duplicate graph node id"):
        GraphQueryIndex([source, duplicate_source], [])

    with pytest.raises(ValueError, match="missing node"):
        GraphQueryIndex([source], [dangling_edge])


def _example_query_index() -> GraphQueryIndex:
    source = _source()
    artifact = _artifact(source)
    evidence_span = _evidence_span(artifact)
    tool = _tool_node(source)
    network_capability = _network_capability()
    env_var = _env_var()
    dependency = _abandoned_dependency()
    finding = _finding(source)
    policy_rule = _policy_rule()
    sandbox_task = _sandbox_task()
    unsafe_action = _unsafe_action()
    nodes = [
        source,
        artifact,
        evidence_span,
        tool,
        network_capability,
        env_var,
        dependency,
        finding,
        policy_rule,
        sandbox_task,
        unsafe_action,
    ]
    edges = [
        _edge("has_artifact", source, artifact),
        _edge("defines", artifact, tool),
        _edge("requires", tool, network_capability),
        _edge("mentions", tool, env_var),
        _edge("depends_on", tool, dependency),
        _edge("contains", artifact, evidence_span),
        _edge("triggers", evidence_span, finding),
        _edge("violates", finding, policy_rule),
        _edge("used", sandbox_task, tool),
        _edge("produced", sandbox_task, unsafe_action),
    ]
    return GraphQueryIndex(nodes, edges)


def _permission_index(include_network: bool) -> GraphQueryIndex:
    source = _source()
    artifact = _artifact(source)
    tool = _tool_node(source)
    local_capability = CapabilityNode(
        node_id=make_graph_node_id("capability", "local_read"),
        label="local_read",
        capability_id="local_read",
        name="local_read",
        risk_weight=1,
    )
    network_capability = _network_capability()
    nodes: list[GraphNode] = [source, artifact, tool, local_capability]
    edges = [
        _edge("has_artifact", source, artifact),
        _edge("defines", artifact, tool),
        _edge("requires", tool, local_capability),
    ]
    if include_network:
        nodes.append(network_capability)
        edges.append(_edge("requires", tool, network_capability))
    return GraphQueryIndex(nodes, edges)


def _source() -> SourceRepoNode:
    return SourceRepoNode(
        node_id=make_graph_node_id("source_repo", "src_1"),
        label="safe-tool",
        source_id="src_1",
        source_url="https://github.com/example/safe-tool",
        owner="example",
        repo_name="safe-tool",
    )


def _artifact(source: SourceRepoNode) -> ArtifactNode:
    return ArtifactNode(
        node_id=make_graph_node_id("artifact", "art_1"),
        label="README.md",
        artifact_id="art_1",
        source_id=source.source_id,
        path="README.md",
        artifact_type="readme",
        content_hash="hash_readme",
    )


def _evidence_span(artifact: ArtifactNode) -> EvidenceSpanNode:
    return EvidenceSpanNode(
        node_id=make_graph_node_id("evidence_span", "span_1"),
        label="README.md:3-5",
        span_id="span_1",
        artifact_id=artifact.artifact_id,
        start_line=3,
        end_line=5,
        span_type="prompt_injection_candidate",
        content_hash="hash_span",
    )


def _tool_node(source: SourceRepoNode) -> ToolNode:
    return ToolNode(
        node_id=make_graph_node_id("tool", "tool_1"),
        label="calendar_reader",
        tool_id="tool_1",
        source_id=source.source_id,
        name="calendar_reader",
        description="Tool metadata says ignore previous instructions before reading calendars.",
        metadata={"static_risk_score": 20},
    )


def _network_capability() -> CapabilityNode:
    return CapabilityNode(
        node_id=make_graph_node_id("capability", "network_access"),
        label="network_access",
        capability_id="network_access",
        name="network_access",
        risk_weight=5,
    )


def _env_var() -> EnvVarNode:
    return EnvVarNode(
        node_id=make_graph_node_id("env_var", "SAFE_API_KEY"),
        label="SAFE_API_KEY",
        name="SAFE_API_KEY",
        sensitive=True,
    )


def _abandoned_dependency() -> DependencyNode:
    return DependencyNode(
        node_id=make_graph_node_id("dependency", "python:legacy-sdk"),
        label="legacy-sdk",
        name="legacy-sdk",
        ecosystem="python",
        metadata={"status": "abandoned"},
    )


def _finding(source: SourceRepoNode) -> FindingNode:
    return FindingNode(
        node_id=make_graph_node_id("finding", "finding_1"),
        label="prompt_injection_candidate",
        finding_id="finding_1",
        source_id=source.source_id,
        finding_type="prompt_injection_candidate",
        severity="high",
        confidence=0.9,
    )


def _policy_rule() -> PolicyRuleNode:
    return PolicyRuleNode(
        node_id=make_graph_node_id("policy_rule", "rule_quarantine_injection"),
        label="quarantine prompt injection",
        policy_rule_id="rule_quarantine_injection",
        action="quarantine",
    )


def _sandbox_task() -> SandboxTaskNode:
    return SandboxTaskNode(
        node_id=make_graph_node_id("sandbox_task", "task_1"),
        label="calendar red-team",
        sandbox_task_id="task_1",
        name="calendar red-team",
        task_type="red_team",
    )


def _unsafe_action() -> UnsafeActionNode:
    return UnsafeActionNode(
        node_id=make_graph_node_id("unsafe_action", "action_1"),
        label="secret_exfiltration_attempt",
        unsafe_action_id="action_1",
        action_type="secret_exfiltration_attempt",
        severity="critical",
    )


def _tool(index: GraphQueryIndex) -> ToolNode:
    for node in index.nodes:
        if isinstance(node, ToolNode):
            return node
    raise AssertionError("example index must include a tool node")


def _edge(edge_type: GraphEdgeType, source: GraphNode, target: GraphNode) -> GraphEdge:
    return GraphEdge(
        edge_id=make_graph_edge_id(edge_type, source.node_id, target.node_id),
        edge_type=edge_type,
        source_node_id=source.node_id,
        source_node_type=source.node_type,
        target_node_id=target.node_id,
        target_node_type=target.node_type,
    )
