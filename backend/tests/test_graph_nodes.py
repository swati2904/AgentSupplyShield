import pytest
from pydantic import ValidationError

from app.graph_nodes import (
    GRAPH_NODE_TYPES,
    ArtifactNode,
    CapabilityNode,
    DependencyNode,
    EnvVarNode,
    EvidenceSpanNode,
    ExternalDomainNode,
    FindingNode,
    MaintainerNode,
    ParameterNode,
    PolicyRuleNode,
    SandboxTaskNode,
    ScanRunNode,
    SourceRepoNode,
    ToolNode,
    UnsafeActionNode,
    make_graph_node_id,
)


def test_graph_node_types_match_roadmap_nodes() -> None:
    assert GRAPH_NODE_TYPES == (
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


def test_core_graph_node_models_accept_example_objects() -> None:
    source = SourceRepoNode(
        node_id=make_graph_node_id("source_repo", "src_1"),
        label="safe-tool",
        source_id="src_1",
        source_url="https://github.com/example/safe-tool",
        canonical_url="https://github.com/example/safe-tool",
        owner="example",
        repo_name="safe-tool",
        trust_tier="unknown",
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
    tool = ToolNode(
        node_id=make_graph_node_id("tool", "tool_1"),
        label="calendar_reader",
        tool_id="tool_1",
        source_id=source.source_id,
        name="calendar_reader",
        description="Reads calendar summaries.",
    )
    parameter = ParameterNode(
        node_id=make_graph_node_id("parameter", "tool_1:limit"),
        label="limit",
        tool_id=tool.tool_id,
        name="limit",
        required=False,
    )
    capability = CapabilityNode(
        node_id=make_graph_node_id("capability", "network_access"),
        label="network_access",
        capability_id="network_access",
        name="network_access",
        risk_weight=3,
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

    assert source.node_type == "source_repo"
    assert artifact.source_id == source.source_id
    assert evidence_span.artifact_id == artifact.artifact_id
    assert tool.source_id == source.source_id
    assert parameter.tool_id == tool.tool_id
    assert capability.risk_weight == 3


def test_signal_and_runtime_graph_node_models_accept_example_objects() -> None:
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
        version="2.32.0",
    )
    maintainer = MaintainerNode(
        node_id=make_graph_node_id("maintainer", "github:example"),
        label="example",
        handle="example",
        platform="github",
    )
    finding = FindingNode(
        node_id=make_graph_node_id("finding", "finding_1"),
        label="prompt_injection_candidate",
        finding_id="finding_1",
        source_id="src_1",
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
        source_id="src_1",
        status="completed",
        risk_score=80,
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

    assert env_var.sensitive is True
    assert domain.node_type == "external_domain"
    assert dependency.ecosystem == "python"
    assert maintainer.platform == "github"
    assert finding.confidence == 0.9
    assert policy_rule.action == "block"
    assert scan_run.risk_score == 80
    assert sandbox_task.task_type == "safe"
    assert unsafe_action.severity == "critical"


def test_graph_node_ids_are_stable_and_namespaced() -> None:
    first = make_graph_node_id("tool", "calendar_reader")
    second = make_graph_node_id("tool", "calendar_reader")
    different_type = make_graph_node_id("capability", "calendar_reader")

    assert first == second
    assert first.startswith("tool_")
    assert different_type.startswith("capability_")
    assert first != different_type


def test_graph_node_validation_rejects_blank_ids_and_bad_values() -> None:
    with pytest.raises(ValidationError):
        ToolNode(node_id=" ", label="tool", tool_id="tool_1", source_id="src_1", name="tool")

    with pytest.raises(ValidationError):
        FindingNode(
            node_id="finding_1",
            label="finding",
            finding_id="finding_1",
            source_id="src_1",
            finding_type="prompt_injection_candidate",
            severity="high",
            confidence=1.5,
        )

    with pytest.raises(ValueError, match="raw graph node id"):
        make_graph_node_id("tool", " ")
