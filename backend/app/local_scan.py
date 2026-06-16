from hashlib import sha256
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from app.credential_permission_detector import detect_credential_and_permission_signals
from app.ingestion import LocalFileArtifact, ingest_local_folder
from app.markdown_parser import parse_markdown_text
from app.models import EvidenceSpan
from app.prompt_injection_detector import detect_prompt_injection
from app.reporting import ReportFinding, build_evidence_grounded_report, report_to_json, report_to_markdown
from app.risk_scoring import assess_risk
from app.schema_parser import parse_tool_schema_text


class ParsedArtifactSummary(BaseModel):
    artifact_id: str
    relative_path: str
    artifact_type: str
    parsed_item_count: int = Field(ge=0)
    parse_error: str | None = None


class LocalScanResult(BaseModel):
    run_id: str
    source_id: str
    root_path: str
    scanned_file_count: int = Field(ge=0)
    skipped_count: int = Field(ge=0)
    parsed_artifacts: list[ParsedArtifactSummary]
    risk_score: int = Field(ge=0, le=100)
    risk_level: str
    policy_decision: str
    findings: list[ReportFinding]
    evidence_spans: list[EvidenceSpan]
    report_json_path: str
    report_markdown_path: str


def scan_local_folder(root_path: str | Path, *, output_dir: str | Path) -> LocalScanResult:
    ingestion = ingest_local_folder(root_path)
    root = Path(ingestion.root_path)
    output = Path(output_dir).expanduser().resolve()
    output.mkdir(parents=True, exist_ok=True)

    run_id = _run_id(ingestion.root_path, ingestion.files)
    source_id = f"source_{sha256(ingestion.root_path.encode('utf-8')).hexdigest()[:16]}"
    artifact_paths: dict[str, str] = {}
    parsed_artifacts: list[ParsedArtifactSummary] = []
    detector_findings: list[Any] = []

    for file_artifact in ingestion.files:
        artifact_id = _artifact_id(file_artifact)
        artifact_paths[artifact_id] = file_artifact.relative_path
        raw_text = Path(file_artifact.absolute_path).read_text(encoding="utf-8", errors="replace")
        parsed_artifacts.append(_parse_artifact(file_artifact, artifact_id, raw_text))
        detector_findings.extend(detect_prompt_injection(raw_text, artifact_id=artifact_id))
        detector_findings.extend(detect_credential_and_permission_signals(raw_text, artifact_id=artifact_id))

    risk_assessment = assess_risk(detector_findings)
    report = build_evidence_grounded_report(
        run_id=run_id,
        source_id=source_id,
        source_path=str(root),
        findings=detector_findings,
        risk_assessment=risk_assessment,
        artifact_paths=artifact_paths,
    )
    report_json_path = output / f"{run_id}.json"
    report_markdown_path = output / f"{run_id}.md"
    report_json_path.write_text(report_to_json(report), encoding="utf-8")
    report_markdown_path.write_text(report_to_markdown(report), encoding="utf-8")

    return LocalScanResult(
        run_id=run_id,
        source_id=source_id,
        root_path=str(root),
        scanned_file_count=len(ingestion.files),
        skipped_count=len(ingestion.skipped),
        parsed_artifacts=parsed_artifacts,
        risk_score=risk_assessment.risk_score,
        risk_level=risk_assessment.risk_level,
        policy_decision=risk_assessment.policy_decision,
        findings=report.findings,
        evidence_spans=[finding.evidence_span for finding in detector_findings],
        report_json_path=str(report_json_path),
        report_markdown_path=str(report_markdown_path),
    )


def _parse_artifact(file_artifact: LocalFileArtifact, artifact_id: str, raw_text: str) -> ParsedArtifactSummary:
    extension = file_artifact.extension
    if extension in {".md", ".markdown"}:
        parsed = parse_markdown_text(raw_text, path=file_artifact.relative_path)
        return ParsedArtifactSummary(
            artifact_id=artifact_id,
            relative_path=file_artifact.relative_path,
            artifact_type="markdown",
            parsed_item_count=len(parsed.headings)
            + len(parsed.paragraphs)
            + len(parsed.code_blocks)
            + len(parsed.links)
            + len(parsed.env_vars),
        )
    if extension in {".json", ".yaml", ".yml"}:
        schema_format = "json" if extension == ".json" else "yaml"
        parsed_schema = parse_tool_schema_text(raw_text, schema_format=schema_format, path=file_artifact.relative_path)
        return ParsedArtifactSummary(
            artifact_id=artifact_id,
            relative_path=file_artifact.relative_path,
            artifact_type=schema_format,
            parsed_item_count=len(parsed_schema.tools) + len(parsed_schema.urls),
            parse_error=parsed_schema.parse_error,
        )
    return ParsedArtifactSummary(
        artifact_id=artifact_id,
        relative_path=file_artifact.relative_path,
        artifact_type=extension.lstrip(".") or "text",
        parsed_item_count=0,
    )


def _artifact_id(file_artifact: LocalFileArtifact) -> str:
    stable_key = f"{file_artifact.relative_path}:{file_artifact.content_hash}"
    return f"artifact_{sha256(stable_key.encode('utf-8')).hexdigest()[:16]}"


def _run_id(root_path: str, files: list[LocalFileArtifact]) -> str:
    digest = sha256(root_path.encode("utf-8"))
    for file_artifact in files:
        digest.update(file_artifact.relative_path.encode("utf-8"))
        digest.update(file_artifact.content_hash.encode("utf-8"))
    return f"run_{digest.hexdigest()[:16]}"
