from app.graph_edges import GraphEdge, GraphEdgeType, make_graph_edge_id
from app.graph_nodes import (
    ArtifactNode,
    CapabilityNode,
    DependencyNode,
    EnvVarNode,
    EvidenceSpanNode,
    ExternalDomainNode,
    FindingNode,
    GraphNode,
    SourceRepoNode,
    ToolNode,
    make_graph_node_id,
)
from app.graph_queries import GraphQueryIndex
from app.graph_risk_features import GRAPH_RISK_FEATURE_NAMES, derive_graph_risk_features, derive_tool_risk_features


def test_graph_risk_feature_names_match_roadmap_features() -> None:
    assert GRAPH_RISK_FEATURE_NAMES == (
        "external_communication_degree",
        "sensitive_env_var_count",
        "permission_count",
        "high_risk_dependency_count",
        "suspicious_span_to_tool_description_distance",
        "recent_metadata_change_count",
        "independent_finding_count",
    )


def test_derive_tool_risk_features_from_graph_relationships() -> None:
    index, tool = _feature_index()

    features = derive_tool_risk_features(index, tool)

    assert features.tool_id == "tool_1"
    assert features.tool_name == "calendar_reader"
    assert features.external_communication_degree == 2
    assert features.sensitive_env_var_count == 1
    assert features.permission_count == 2
    assert features.high_risk_dependency_count == 1
    assert features.suspicious_span_to_tool_description_distance == 2
    assert features.recent_metadata_change_count == 2
    assert features.independent_finding_count == 2


def test_derive_graph_risk_features_returns_tools_sorted_by_label() -> None:
    index, first_tool = _feature_index()
    second_tool = ToolNode(
        node_id=make_graph_node_id("tool", "tool_0"),
        label="archive_reader",
        tool_id="tool_0",
        source_id="src_1",
        name="archive_reader",
    )
    expanded_index = GraphQueryIndex([*index.nodes, second_tool], index.edges)

    features = derive_graph_risk_features(expanded_index)

    assert [feature.tool_name for feature in features] == ["archive_reader", first_tool.name]
    assert features[0].external_communication_degree == 0
    assert features[0].suspicious_span_to_tool_description_distance is None


def test_recent_metadata_change_count_accepts_numeric_metadata() -> None:
    index, tool = _feature_index(metadata={"metadata_change_count": "3"})

    features = derive_tool_risk_features(index, tool)

    assert features.recent_metadata_change_count == 3


def test_suspicious_span_distance_is_none_without_suspicious_span() -> None:
    index, tool = _feature_index(suspicious_span=False)

    features = derive_tool_risk_features(index, tool)

    assert features.suspicious_span_to_tool_description_distance is None
    assert features.independent_finding_count == 2


def _feature_index(
    *,
    metadata: dict[str, object] | None = None,
    suspicious_span: bool = True,
) -> tuple[GraphQueryIndex, ToolNode]:
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
    tool = ToolNode(
        node_id=make_graph_node_id("tool", "tool_1"),
        label="calendar_reader",
        tool_id="tool_1",
        source_id=source.source_id,
        name="calendar_reader",
        metadata=metadata or {"recent_metadata_changes": ["description", "permissions"]},
    )
    domains = [
        ExternalDomainNode(
            node_id=make_graph_node_id("external_domain", "api.example.test"),
            label="api.example.test",
            domain="api.example.test",
        ),
        ExternalDomainNode(
            node_id=make_graph_node_id("external_domain", "cdn.example.test"),
            label="cdn.example.test",
            domain="cdn.example.test",
        ),
    ]
    env_vars = [
        EnvVarNode(
            node_id=make_graph_node_id("env_var", "SAFE_API_KEY"),
            label="SAFE_API_KEY",
            name="SAFE_API_KEY",
            sensitive=True,
        ),
        EnvVarNode(
            node_id=make_graph_node_id("env_var", "LOG_LEVEL"),
            label="LOG_LEVEL",
            name="LOG_LEVEL",
            sensitive=False,
        ),
    ]
    capabilities = [
        CapabilityNode(
            node_id=make_graph_node_id("capability", "network_access"),
            label="network_access",
            capability_id="network_access",
            name="network_access",
            risk_weight=5,
        ),
        CapabilityNode(
            node_id=make_graph_node_id("capability", "local_read"),
            label="local_read",
            capability_id="local_read",
            name="local_read",
            risk_weight=1,
        ),
    ]
    dependencies = [
        DependencyNode(
            node_id=make_graph_node_id("dependency", "python:legacy-sdk"),
            label="legacy-sdk",
            name="legacy-sdk",
            ecosystem="python",
            metadata={"risk_score": 90},
        ),
        DependencyNode(
            node_id=make_graph_node_id("dependency", "python:requests"),
            label="requests",
            name="requests",
            ecosystem="python",
        ),
    ]
    span = EvidenceSpanNode(
        node_id=make_graph_node_id("evidence_span", "span_1"),
        label="README.md:3-5",
        span_id="span_1",
        artifact_id=artifact.artifact_id,
        start_line=3,
        end_line=5,
        span_type="prompt_injection_candidate" if suspicious_span else "tool_description",
        content_hash="hash_span",
    )
    findings = [
        FindingNode(
            node_id=make_graph_node_id("finding", "finding_1"),
            label="prompt_injection_candidate" if suspicious_span else "metadata_note",
            finding_id="finding_1",
            source_id=source.source_id,
            finding_type="prompt_injection_candidate" if suspicious_span else "metadata_note",
            severity="high" if suspicious_span else "low",
            confidence=0.9,
        ),
        FindingNode(
            node_id=make_graph_node_id("finding", "finding_2"),
            label="credential_reference",
            finding_id="finding_2",
            source_id=source.source_id,
            finding_type="credential_reference",
            severity="medium",
            confidence=0.8,
        ),
    ]
    nodes: list[GraphNode] = [
        source,
        artifact,
        tool,
        *domains,
        *env_vars,
        *capabilities,
        *dependencies,
        span,
        *findings,
    ]
    edges = [
        _edge("has_artifact", source, artifact),
        _edge("defines", artifact, tool),
        *[_edge("calls", tool, domain) for domain in domains],
        *[_edge("mentions", tool, env_var) for env_var in env_vars],
        *[_edge("requires", tool, capability) for capability in capabilities],
        *[_edge("depends_on", tool, dependency) for dependency in dependencies],
        _edge("contains", artifact, span),
        *[_edge("triggers", span, finding) for finding in findings],
    ]
    return GraphQueryIndex(nodes, edges), tool


def _edge(edge_type: GraphEdgeType, source: GraphNode, target: GraphNode) -> GraphEdge:
    return GraphEdge(
        edge_id=make_graph_edge_id(edge_type, source.node_id, target.node_id),
        edge_type=edge_type,
        source_node_id=source.node_id,
        source_node_type=source.node_type,
        target_node_id=target.node_id,
        target_node_type=target.node_type,
    )
