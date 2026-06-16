from dataclasses import dataclass, field

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
from app.repositories import (
    CapabilityRepository,
    DocumentArtifactRepository,
    EvidenceSpanRepository,
    ExperimentLogRepository,
    FindingRepository,
    RepositorySet,
    ScanRunRepository,
    SourceRepository,
    ToolRepository,
)


class MemorySourceRepository:
    def __init__(self) -> None:
        self.records: dict[str, Source] = {}

    def upsert_source(self, source: Source) -> Source:
        self.records[source.source_id] = source
        return source

    def get_source(self, source_id: str) -> Source | None:
        return self.records.get(source_id)

    def list_sources(self) -> list[Source]:
        return list(self.records.values())


class MemoryDocumentArtifactRepository:
    def __init__(self) -> None:
        self.records: dict[str, DocumentArtifact] = {}

    def upsert_artifact(self, artifact: DocumentArtifact) -> DocumentArtifact:
        self.records[artifact.artifact_id] = artifact
        return artifact

    def get_artifact(self, artifact_id: str) -> DocumentArtifact | None:
        return self.records.get(artifact_id)

    def list_artifacts_for_source(self, source_id: str) -> list[DocumentArtifact]:
        return [artifact for artifact in self.records.values() if artifact.source_id == source_id]


class MemoryToolRepository:
    def __init__(self) -> None:
        self.records: dict[str, Tool] = {}

    def upsert_tool(self, tool: Tool) -> Tool:
        self.records[tool.tool_id] = tool
        return tool

    def get_tool(self, tool_id: str) -> Tool | None:
        return self.records.get(tool_id)

    def list_tools_for_source(self, source_id: str) -> list[Tool]:
        return [tool for tool in self.records.values() if tool.source_id == source_id]


class MemoryCapabilityRepository:
    def __init__(self) -> None:
        self.records: dict[str, Capability] = {}

    def upsert_capability(self, capability: Capability) -> Capability:
        self.records[capability.capability_id] = capability
        return capability

    def get_capability(self, capability_id: str) -> Capability | None:
        return self.records.get(capability_id)

    def list_capabilities(self) -> list[Capability]:
        return list(self.records.values())


class MemoryEvidenceSpanRepository:
    def __init__(self) -> None:
        self.records: dict[str, EvidenceSpan] = {}

    def upsert_evidence_span(self, evidence_span: EvidenceSpan) -> EvidenceSpan:
        self.records[evidence_span.span_id] = evidence_span
        return evidence_span

    def get_evidence_span(self, span_id: str) -> EvidenceSpan | None:
        return self.records.get(span_id)

    def list_evidence_spans_for_artifact(self, artifact_id: str) -> list[EvidenceSpan]:
        return [span for span in self.records.values() if span.artifact_id == artifact_id]


class MemoryFindingRepository:
    def __init__(self) -> None:
        self.records: dict[str, Finding] = {}
        self.run_index: dict[str, list[str]] = {}

    def upsert_finding(self, finding: Finding) -> Finding:
        self.records[finding.finding_id] = finding
        return finding

    def index_finding_for_run(self, run_id: str, finding_id: str) -> None:
        self.run_index.setdefault(run_id, []).append(finding_id)

    def get_finding(self, finding_id: str) -> Finding | None:
        return self.records.get(finding_id)

    def list_findings_for_source(self, source_id: str) -> list[Finding]:
        return [finding for finding in self.records.values() if finding.source_id == source_id]

    def list_findings_for_run(self, run_id: str) -> list[Finding]:
        return [self.records[finding_id] for finding_id in self.run_index.get(run_id, [])]


class MemoryScanRunRepository:
    def __init__(self) -> None:
        self.records: dict[str, ScanRun] = {}

    def upsert_scan_run(self, scan_run: ScanRun) -> ScanRun:
        self.records[scan_run.run_id] = scan_run
        return scan_run

    def get_scan_run(self, run_id: str) -> ScanRun | None:
        return self.records.get(run_id)

    def list_scan_runs_for_source(self, source_id: str) -> list[ScanRun]:
        return [scan_run for scan_run in self.records.values() if scan_run.source_id == source_id]


class MemoryExperimentLogRepository:
    def __init__(self) -> None:
        self.records: dict[str, ExperimentLog] = {}

    def upsert_experiment_log(self, experiment_log: ExperimentLog) -> ExperimentLog:
        self.records[experiment_log.experiment_id] = experiment_log
        return experiment_log

    def get_experiment_log(self, experiment_id: str) -> ExperimentLog | None:
        return self.records.get(experiment_id)

    def list_experiment_logs(self) -> list[ExperimentLog]:
        return list(self.records.values())


@dataclass
class MemoryRepositorySet:
    sources: MemorySourceRepository = field(default_factory=MemorySourceRepository)
    artifacts: MemoryDocumentArtifactRepository = field(default_factory=MemoryDocumentArtifactRepository)
    tools: MemoryToolRepository = field(default_factory=MemoryToolRepository)
    capabilities: MemoryCapabilityRepository = field(default_factory=MemoryCapabilityRepository)
    evidence_spans: MemoryEvidenceSpanRepository = field(default_factory=MemoryEvidenceSpanRepository)
    findings: MemoryFindingRepository = field(default_factory=MemoryFindingRepository)
    scan_runs: MemoryScanRunRepository = field(default_factory=MemoryScanRunRepository)
    experiment_logs: MemoryExperimentLogRepository = field(default_factory=MemoryExperimentLogRepository)


def test_repository_protocols_are_runtime_checkable() -> None:
    repositories = MemoryRepositorySet()

    assert isinstance(repositories.sources, SourceRepository)
    assert isinstance(repositories.artifacts, DocumentArtifactRepository)
    assert isinstance(repositories.tools, ToolRepository)
    assert isinstance(repositories.capabilities, CapabilityRepository)
    assert isinstance(repositories.evidence_spans, EvidenceSpanRepository)
    assert isinstance(repositories.findings, FindingRepository)
    assert isinstance(repositories.scan_runs, ScanRunRepository)
    assert isinstance(repositories.experiment_logs, ExperimentLogRepository)
    assert isinstance(repositories, RepositorySet)


def test_repository_interfaces_cover_phase_two_entities() -> None:
    repositories: RepositorySet = MemoryRepositorySet()
    source = Source(source_id="source_1", source_type="local_upload", source_url="fixtures/tool")
    artifact = DocumentArtifact(
        artifact_id="artifact_1",
        source_id=source.source_id,
        artifact_type="markdown",
        path="README.md",
        content_hash="hash_artifact",
    )
    capability = Capability(capability_id="cap_1", name="filesystem_read", risk_weight=2)
    tool = Tool(
        tool_id="tool_1",
        source_id=source.source_id,
        name="read_docs",
        capability_ids=[capability.capability_id],
    )
    evidence_span = EvidenceSpan(
        span_id="span_1",
        artifact_id=artifact.artifact_id,
        start_line=1,
        end_line=1,
        preview="Reads docs.",
        span_type="tool_description",
        content_hash="hash_span",
    )
    finding = Finding(
        finding_id="finding_1",
        source_id=source.source_id,
        finding_type="permission_signal",
        severity="low",
        confidence=0.8,
        evidence_span_ids=[evidence_span.span_id],
        rationale="Documentation references read access.",
        recommendation="Review declared purpose.",
        policy_decision="allow",
    )
    scan_run = ScanRun(
        run_id="run_1",
        source_id=source.source_id,
        status="completed",
        finding_ids=[finding.finding_id],
        risk_score=10,
    )
    experiment = ExperimentLog(experiment_id="experiment_1", run_ids=[scan_run.run_id])

    repositories.sources.upsert_source(source)
    repositories.artifacts.upsert_artifact(artifact)
    repositories.capabilities.upsert_capability(capability)
    repositories.tools.upsert_tool(tool)
    repositories.evidence_spans.upsert_evidence_span(evidence_span)
    repositories.findings.upsert_finding(finding)
    repositories.scan_runs.upsert_scan_run(scan_run)
    repositories.experiment_logs.upsert_experiment_log(experiment)

    assert repositories.sources.get_source(source.source_id) == source
    assert repositories.artifacts.list_artifacts_for_source(source.source_id) == [artifact]
    assert repositories.tools.list_tools_for_source(source.source_id) == [tool]
    assert repositories.capabilities.get_capability(capability.capability_id) == capability
    assert repositories.evidence_spans.list_evidence_spans_for_artifact(artifact.artifact_id) == [evidence_span]
    assert repositories.findings.list_findings_for_source(source.source_id) == [finding]
    assert repositories.scan_runs.list_scan_runs_for_source(source.source_id) == [scan_run]
    assert repositories.experiment_logs.get_experiment_log(experiment.experiment_id) == experiment
