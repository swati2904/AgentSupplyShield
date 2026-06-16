from typing import Any, Literal

from pydantic import BaseModel, Field

from app.models import PolicyDecision, Severity


RiskLevel = Literal["low", "medium", "high", "critical"]

SEVERITY_WEIGHTS: dict[Severity, int] = {
    "low": 10,
    "medium": 35,
    "high": 65,
    "critical": 90,
}


class RiskContribution(BaseModel):
    finding_id: str | None = None
    severity: Severity
    confidence: float = Field(ge=0.0, le=1.0)
    points: int = Field(ge=0)


class RiskAssessment(BaseModel):
    risk_score: int = Field(ge=0, le=100)
    risk_level: RiskLevel
    policy_decision: PolicyDecision
    finding_count: int = Field(ge=0)
    severity_counts: dict[Severity, int]
    contributions: list[RiskContribution]


def assess_risk(findings: list[Any]) -> RiskAssessment:
    contributions = [_contribution(finding) for finding in findings]
    risk_score = min(sum(contribution.points for contribution in contributions), 100)
    risk_level = risk_level_for_score(risk_score)
    return RiskAssessment(
        risk_score=risk_score,
        risk_level=risk_level,
        policy_decision=policy_decision_for_level(risk_level),
        finding_count=len(contributions),
        severity_counts=_severity_counts(contributions),
        contributions=contributions,
    )


def risk_level_for_score(score: int) -> RiskLevel:
    if score >= 75:
        return "critical"
    if score >= 50:
        return "high"
    if score >= 25:
        return "medium"
    return "low"


def policy_decision_for_level(risk_level: RiskLevel) -> PolicyDecision:
    return {
        "low": "allow",
        "medium": "warn",
        "high": "quarantine",
        "critical": "block",
    }[risk_level]


def _contribution(finding: Any) -> RiskContribution:
    severity = _field_value(finding, "severity")
    confidence = float(_field_value(finding, "confidence", default=1.0))
    confidence = max(0.0, min(confidence, 1.0))
    points = round(SEVERITY_WEIGHTS[severity] * confidence)
    return RiskContribution(
        finding_id=_field_value(finding, "finding_id", default=None),
        severity=severity,
        confidence=confidence,
        points=points,
    )


def _field_value(finding: Any, field_name: str, *, default: Any = None) -> Any:
    if isinstance(finding, dict):
        return finding.get(field_name, default)
    return getattr(finding, field_name, default)


def _severity_counts(contributions: list[RiskContribution]) -> dict[Severity, int]:
    counts: dict[Severity, int] = {"low": 0, "medium": 0, "high": 0, "critical": 0}
    for contribution in contributions:
        counts[contribution.severity] += 1
    return counts
