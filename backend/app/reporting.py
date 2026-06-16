from typing import Any
import json

from pydantic import BaseModel, Field

from app.models import Severity
from app.risk_scoring import RiskAssessment


class EvidenceCitation(BaseModel):
    evidence_id: str
    artifact_id: str
    file_path: str
    start_line: int = Field(ge=1)
    end_line: int = Field(ge=1)
    preview: str
    content_hash: str


class ReportFinding(BaseModel):
    finding_id: str
    finding_type: str
    severity: Severity
    confidence: float = Field(ge=0.0, le=1.0)
    rule_id: str | None = None
    evidence_ids: list[str]
    detected_evidence: list[EvidenceCitation]
    inferred_risk: str
    recommendation: str


class EvidenceGroundedReport(BaseModel):
    report_id: str
    run_id: str
    source_id: str
    source_path: str
    risk_score: int = Field(ge=0, le=100)
    risk_level: str
    policy_decision: str
    summary: str
    findings: list[ReportFinding]
    recommendations: list[str]


def build_evidence_grounded_report(
    *,
    run_id: str,
    source_id: str,
    source_path: str,
    findings: list[Any],
    risk_assessment: RiskAssessment,
    artifact_paths: dict[str, str],
) -> EvidenceGroundedReport:
    report_findings = [_normalize_finding(finding, artifact_paths) for finding in findings]
    recommendations = _unique_recommendations(report_findings)
    return EvidenceGroundedReport(
        report_id=f"report_{run_id}",
        run_id=run_id,
        source_id=source_id,
        source_path=source_path,
        risk_score=risk_assessment.risk_score,
        risk_level=risk_assessment.risk_level,
        policy_decision=risk_assessment.policy_decision,
        summary=_summary(risk_assessment, len(report_findings)),
        findings=report_findings,
        recommendations=recommendations,
    )


def report_to_json(report: EvidenceGroundedReport) -> str:
    return json.dumps(report.model_dump(mode="json"), indent=2, sort_keys=True)


def report_to_markdown(report: EvidenceGroundedReport) -> str:
    lines = [
        f"# AgentSupplyShield Report: {report.run_id}",
        "",
        "## Summary",
        "",
        f"- Source: `{report.source_path}`",
        f"- Risk score: {report.risk_score}",
        f"- Risk level: {report.risk_level}",
        f"- Policy decision: {report.policy_decision}",
        f"- Finding count: {len(report.findings)}",
        "",
        "## Findings",
        "",
    ]

    if not report.findings:
        lines.extend(["No findings detected.", ""])
    for finding in report.findings:
        lines.extend(
            [
                f"### {finding.finding_type}",
                "",
                f"- Finding ID: `{finding.finding_id}`",
                f"- Severity: {finding.severity}",
                f"- Confidence: {finding.confidence:.2f}",
                f"- Inferred risk: {finding.inferred_risk}",
                f"- Recommendation: {finding.recommendation}",
                "- Evidence:",
            ]
        )
        for citation in finding.detected_evidence:
            lines.append(
                f"  - `{citation.evidence_id}` at `{citation.file_path}:{citation.start_line}-{citation.end_line}`: "
                f"{citation.preview}"
            )
        lines.append("")

    lines.extend(["## Recommendations", ""])
    if not report.recommendations:
        lines.append("- No action required.")
    else:
        lines.extend(f"- {recommendation}" for recommendation in report.recommendations)
    lines.append("")
    return "\n".join(lines)


def _normalize_finding(finding: Any, artifact_paths: dict[str, str]) -> ReportFinding:
    evidence_span = _field_value(finding, "evidence_span")
    citation = EvidenceCitation(
        evidence_id=evidence_span.span_id,
        artifact_id=evidence_span.artifact_id,
        file_path=artifact_paths.get(evidence_span.artifact_id, evidence_span.artifact_id),
        start_line=evidence_span.start_line,
        end_line=evidence_span.end_line,
        preview=evidence_span.preview,
        content_hash=evidence_span.content_hash,
    )
    return ReportFinding(
        finding_id=_field_value(finding, "finding_id"),
        finding_type=str(_field_value(finding, "category", default=_field_value(finding, "finding_type", default="unknown"))),
        severity=_field_value(finding, "severity"),
        confidence=float(_field_value(finding, "confidence")),
        rule_id=_field_value(finding, "rule_id", default=None),
        evidence_ids=[citation.evidence_id],
        detected_evidence=[citation],
        inferred_risk=_field_value(finding, "rationale"),
        recommendation=_field_value(finding, "recommendation"),
    )


def _field_value(item: Any, field_name: str, *, default: Any = None) -> Any:
    if isinstance(item, dict):
        return item.get(field_name, default)
    return getattr(item, field_name, default)


def _unique_recommendations(findings: list[ReportFinding]) -> list[str]:
    recommendations: list[str] = []
    for finding in findings:
        if finding.recommendation not in recommendations:
            recommendations.append(finding.recommendation)
    return recommendations


def _summary(risk_assessment: RiskAssessment, finding_count: int) -> str:
    return (
        f"Detected {finding_count} evidence-backed finding(s). "
        f"Risk is {risk_assessment.risk_level} with policy decision {risk_assessment.policy_decision}."
    )
