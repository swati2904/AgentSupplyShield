import pytest
from pydantic import ValidationError

from app.graph_edges import GRAPH_EDGE_SPECS, GRAPH_EDGE_TYPES, GraphEdge, GraphEdgeType, make_graph_edge_id
from app.graph_nodes import (
    ArtifactNode,
    CapabilityNode,
    DependencyNode,
    EnvVarNode,
    EvidenceSpanNode,
    ExternalDomainNode,
    FindingNode,
    ParameterNode,
    PolicyRuleNode,
    SandboxTaskNode,
    ScanRunNode,
    SourceRepoNode,
    ToolNode,
    UnsafeActionNode,
    make_graph_node_id,
)


def test_graph_edge_types_and_specs_match_roadmap_edges() -> None:
    assert GRAPH_EDGE_TYPES == (
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
    assert GRAPH_EDGE_SPECS == {
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


def test_graph_edges_accept_roadmap_relationship_examples() -> None:
    nodes = _example_nodes()
    edges = [
        _edge("has_artifact", nodes["source"], nodes["artifact"]),
        _edge("defines", nodes["artifact"], nodes["tool"]),
        _edge("has_parameter", nodes["tool"], nodes["parameter"]),
        _edge("requires", nodes["tool"], nodes["capability"]),
        _edge("mentions", nodes["tool"], nodes["env_var"]),
        _edge("calls", nodes["tool"], nodes["domain"]),
        _edge("depends_on", nodes["tool"], nodes["dependency"]),
        _edge("contains", nodes["artifact"], nodes["evidence_span"]),
        _edge("triggers", nodes["evidence_span"], nodes["finding"]),
        _edge("violates", nodes["finding"], nodes["policy_rule"]),
        _edge("observed", nodes["scan_run"], nodes["finding"]),
        _edge("used", nodes["sandbox_task"], nodes["tool"]),
        _edge("produced", nodes["sandbox_task"], nodes["unsafe_action"]),
    ]

    assert [edge.edge_type for edge in edges] == list(GRAPH_EDGE_TYPES)
    assert edges[7].evidence_span_ids == []
    assert edges[8].source_node_type == "evidence_span"
    assert edges[12].target_node_type == "unsafe_action"


def test_graph_edge_ids_are_stable_namespaced_and_order_sensitive() -> None:
    first = make_graph_edge_id("defines", "artifact_1", "tool_1")
    second = make_graph_edge_id("defines", "artifact_1", "tool_1")
    reversed_edge = make_graph_edge_id("defines", "tool_1", "artifact_1")

    assert first == second
    assert first.startswith("defines_")
    assert first != reversed_edge


def test_graph_edge_validation_rejects_invalid_endpoint_types_and_values() -> None:
    with pytest.raises(ValidationError, match="defines edges must connect artifact to tool"):
        GraphEdge(
            edge_id=make_graph_edge_id("defines", "tool_1", "artifact_1"),
            edge_type="defines",
            source_node_id="tool_1",
            source_node_type="tool",
            target_node_id="artifact_1",
            target_node_type="artifact",
        )

    with pytest.raises(ValidationError):
        GraphEdge(
            edge_id=" ",
            edge_type="defines",
            source_node_id="artifact_1",
            source_node_type="artifact",
            target_node_id="tool_1",
            target_node_type="tool",
        )

    with pytest.raises(ValidationError):
        GraphEdge(
            edge_id=make_graph_edge_id("defines", "artifact_1", "tool_1"),
            edge_type="defines",
            source_node_id="artifact_1",
            source_node_type="artifact",
            target_node_id="tool_1",
            target_node_type="tool",
            weight=-1.0,
        )

    with pytest.raises(ValueError, match="endpoint ids"):
        make_graph_edge_id("defines", "artifact_1", " ")


def _edge(edge_type: GraphEdgeType, source: object, target: object) -> GraphEdge:
    source_node_id = getattr(source, "node_id")
    target_node_id = getattr(target, "node_id")
    return GraphEdge(
        edge_id=make_graph_edge_id(edge_type, source_node_id, target_node_id),
        edge_type=edge_type,
        source_node_id=source_node_id,
        source_node_type=getattr(source, "node_type"),
        target_node_id=target_node_id,
        target_node_type=getattr(target, "node_type"),
    )


def _example_nodes() -> dict[str, object]:
    source = SourceRepoNode(
        node_id=make_graph_node_id("source_repo", "src_1"),
        label="safe-tool",
        source_id="src_1",
        source_url="https://github.com/example/safe-tool",
    )
    artifact = ArtifactNode(
        node_id=make_graph_node_id("artifact", "art_1"),
        label="README.md",
        artifact_id="art_1",
        source_id=source.source_id,
        path="README.md",
        artifact_type="readme",
        content_hash="hash_readme",
    )
    evidence_span = EvidenceSpanNode(
        node_id=make_graph_node_id("evidence_span", "span_1"),
        label="README.md:3-5",
        span_id="span_1",
        artifact_id=artifact.artifact_id,
        start_line=3,
        end_line=5,
        span_type="tool_definition",
        content_hash="hash_span",
    )
    tool = ToolNode(
        node_id=make_graph_node_id("tool", "tool_1"),
        label="calendar_reader",
        tool_id="tool_1",
        source_id=source.source_id,
        name="calendar_reader",
    )
    parameter = ParameterNode(
        node_id=make_graph_node_id("parameter", "tool_1:limit"),
        label="limit",
        tool_id=tool.tool_id,
        name="limit",
    )
    capability = CapabilityNode(
        node_id=make_graph_node_id("capability", "network_access"),
        label="network_access",
        capability_id="network_access",
        name="network_access",
        risk_weight=3,
    )
    env_var = EnvVarNode(
        node_id=make_graph_node_id("env_var", "SAFE_API_KEY"),
        label="SAFE_API_KEY",
        name="SAFE_API_KEY",
        sensitive=True,
    )
    domain = ExternalDomainNode(
        node_id=make_graph_node_id("external_domain", "api.example.test"),
        label="api.example.test",
        domain="api.example.test",
    )
    dependency = DependencyNode(
        node_id=make_graph_node_id("dependency", "python:requests"),
        label="requests",
        name="requests",
        ecosystem="python",
    )
    finding = FindingNode(
        node_id=make_graph_node_id("finding", "finding_1"),
        label="prompt_injection_candidate",
        finding_id="finding_1",
        source_id=source.source_id,
        finding_type="prompt_injection_candidate",
        severity="high",
        confidence=0.9,
    )
    policy_rule = PolicyRuleNode(
        node_id=make_graph_node_id("policy_rule", "rule_block_injection"),
        label="block prompt injection",
        policy_rule_id="rule_block_injection",
        action="block",
    )
    scan_run = ScanRunNode(
        node_id=make_graph_node_id("scan_run", "run_1"),
        label="run_1",
        run_id="run_1",
        source_id=source.source_id,
        status="completed",
    )
    sandbox_task = SandboxTaskNode(
        node_id=make_graph_node_id("sandbox_task", "task_1"),
        label="safe summarization",
        sandbox_task_id="task_1",
        name="safe summarization",
        task_type="safe",
    )
    unsafe_action = UnsafeActionNode(
        node_id=make_graph_node_id("unsafe_action", "action_1"),
        label="secret_exfiltration_attempt",
        unsafe_action_id="action_1",
        action_type="secret_exfiltration_attempt",
        severity="critical",
    )

    return {
        "source": source,
        "artifact": artifact,
        "evidence_span": evidence_span,
        "tool": tool,
        "parameter": parameter,
        "capability": capability,
        "env_var": env_var,
        "domain": domain,
        "dependency": dependency,
        "finding": finding,
        "policy_rule": policy_rule,
        "scan_run": scan_run,
        "sandbox_task": sandbox_task,
        "unsafe_action": unsafe_action,
    }
