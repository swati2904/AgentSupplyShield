from app.models import (
    Capability,
    DocumentArtifact,
    EvidenceSpan,
    ExperimentLog,
    Finding,
    ScanRun,
    Source,
    Tool,
)


def test_core_models_accept_example_objects() -> None:
    source = Source(
        source_id="src_1",
        source_type="local_upload",
        source_url="fixtures/clean_tool",
        crawl_status="crawled",
    )
    artifact = DocumentArtifact(
        artifact_id="art_1",
        source_id=source.source_id,
        artifact_type="readme",
        path="README.md",
        content_hash="hash_readme",
    )
    capability = Capability(
        capability_id="cap_read",
        name="filesystem_read",
        description="Reads local fixture files",
        risk_weight=2,
    )
    tool = Tool(
        tool_id="tool_1",
        source_id=source.source_id,
        name="read_docs",
        description="Reads documentation",
        capability_ids=[capability.capability_id],
    )
    span = EvidenceSpan(
        span_id="span_1",
        artifact_id=artifact.artifact_id,
        start_line=1,
        end_line=2,
        text="Tool reads documentation.",
        span_type="tool_description",
        content_hash="hash_span",
    )
    finding = Finding(
        finding_id="finding_1",
        source_id=source.source_id,
        finding_type="permission_signal",
        severity="low",
        confidence=0.75,
        evidence_span_ids=[span.span_id],
        rationale="Documentation references read access.",
        recommendation="Review declared purpose before approval.",
        policy_decision="allow",
    )
    run = ScanRun(
        run_id="run_1",
        source_id=source.source_id,
        status="completed",
        finding_ids=[finding.finding_id],
        risk_score=15,
    )
    experiment = ExperimentLog(
        experiment_id="exp_1",
        run_ids=[run.run_id],
        config={"detector_version": "test"},
        metrics={"finding_count": 1},
    )

    assert source.source_type == "local_upload"
    assert artifact.source_id == source.source_id
    assert tool.capability_ids == [capability.capability_id]
    assert finding.evidence_span_ids == [span.span_id]
    assert run.risk_score == 15
    assert experiment.metrics["finding_count"] == 1


def test_evidence_span_requires_positive_line_numbers() -> None:
    span = EvidenceSpan(
        span_id="span_2",
        artifact_id="art_1",
        start_line=3,
        end_line=5,
        text="Example evidence.",
        span_type="example",
        content_hash="hash_span_2",
    )

    assert span.start_line == 3
    assert span.end_line == 5
