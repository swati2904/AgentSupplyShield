from typing import Protocol, runtime_checkable

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


@runtime_checkable
class SourceRepository(Protocol):
    def upsert_source(self, source: Source) -> Source: ...

    def get_source(self, source_id: str) -> Source | None: ...

    def list_sources(self) -> list[Source]: ...


@runtime_checkable
class DocumentArtifactRepository(Protocol):
    def upsert_artifact(self, artifact: DocumentArtifact) -> DocumentArtifact: ...

    def get_artifact(self, artifact_id: str) -> DocumentArtifact | None: ...

    def list_artifacts_for_source(self, source_id: str) -> list[DocumentArtifact]: ...


@runtime_checkable
class ToolRepository(Protocol):
    def upsert_tool(self, tool: Tool) -> Tool: ...

    def get_tool(self, tool_id: str) -> Tool | None: ...

    def list_tools_for_source(self, source_id: str) -> list[Tool]: ...


@runtime_checkable
class CapabilityRepository(Protocol):
    def upsert_capability(self, capability: Capability) -> Capability: ...

    def get_capability(self, capability_id: str) -> Capability | None: ...

    def list_capabilities(self) -> list[Capability]: ...


@runtime_checkable
class EvidenceSpanRepository(Protocol):
    def upsert_evidence_span(self, evidence_span: EvidenceSpan) -> EvidenceSpan: ...

    def get_evidence_span(self, span_id: str) -> EvidenceSpan | None: ...

    def list_evidence_spans_for_artifact(self, artifact_id: str) -> list[EvidenceSpan]: ...


@runtime_checkable
class FindingRepository(Protocol):
    def upsert_finding(self, finding: Finding) -> Finding: ...

    def index_finding_for_run(self, run_id: str, finding_id: str) -> None: ...

    def get_finding(self, finding_id: str) -> Finding | None: ...

    def list_findings_for_source(self, source_id: str) -> list[Finding]: ...

    def list_findings_for_run(self, run_id: str) -> list[Finding]: ...


@runtime_checkable
class ScanRunRepository(Protocol):
    def upsert_scan_run(self, scan_run: ScanRun) -> ScanRun: ...

    def get_scan_run(self, run_id: str) -> ScanRun | None: ...

    def list_scan_runs_for_source(self, source_id: str) -> list[ScanRun]: ...


@runtime_checkable
class ExperimentLogRepository(Protocol):
    def upsert_experiment_log(self, experiment_log: ExperimentLog) -> ExperimentLog: ...

    def get_experiment_log(self, experiment_id: str) -> ExperimentLog | None: ...

    def list_experiment_logs(self) -> list[ExperimentLog]: ...


@runtime_checkable
class RepositorySet(Protocol):
    @property
    def sources(self) -> SourceRepository: ...

    @property
    def artifacts(self) -> DocumentArtifactRepository: ...

    @property
    def tools(self) -> ToolRepository: ...

    @property
    def capabilities(self) -> CapabilityRepository: ...

    @property
    def evidence_spans(self) -> EvidenceSpanRepository: ...

    @property
    def findings(self) -> FindingRepository: ...

    @property
    def scan_runs(self) -> ScanRunRepository: ...

    @property
    def experiment_logs(self) -> ExperimentLogRepository: ...
