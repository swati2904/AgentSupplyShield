from typing import Any

from pydantic import BaseModel, Field, field_validator, model_validator

from app.policy_yaml import PolicyAction, PolicyRuleDefinition


DEFAULT_RECOMMENDED_ACTIONS: dict[PolicyAction, str] = {
    "allow": "Proceed with normal tool use.",
    "warn": "Show the policy warning before use.",
    "quarantine": "Review tool metadata manually before connecting to production agents.",
    "block": "Do not connect or execute this tool.",
    "human_approval": "Require explicit human approval before use.",
    "sandbox_only": "Run only inside an isolated sandbox.",
}


class PolicyEvidenceCitation(BaseModel):
    evidence_span_id: str
    artifact_id: str | None = None
    file_path: str | None = None
    start_line: int | None = Field(default=None, ge=1)
    end_line: int | None = Field(default=None, ge=1)
    preview: str | None = None

    @field_validator("evidence_span_id")
    @classmethod
    def _evidence_span_id_must_not_be_blank(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("evidence span id must not be blank.")
        return value

    @model_validator(mode="after")
    def _line_range_must_be_ordered(self) -> "PolicyEvidenceCitation":
        if self.start_line is not None and self.end_line is not None and self.end_line < self.start_line:
            raise ValueError("evidence citation end_line must be greater than or equal to start_line.")
        return self


class PolicyExplanation(BaseModel):
    decision: PolicyAction
    policy_id: str
    triggered_by: list[str]
    evidence_span_ids: list[str] = Field(default_factory=list)
    confidence: float = Field(ge=0.0, le=1.0)
    recommended_action: str
    reason: str
    evidence: list[PolicyEvidenceCitation] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("policy_id", "recommended_action", "reason")
    @classmethod
    def _strings_must_not_be_blank(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("policy explanation text fields must not be blank.")
        return value

    @field_validator("triggered_by", "evidence_span_ids")
    @classmethod
    def _lists_must_not_include_blank_values(cls, value: list[str]) -> list[str]:
        if any(not item.strip() for item in value):
            raise ValueError("policy explanation list values must not be blank.")
        return value

    @model_validator(mode="after")
    def _must_include_trigger_and_sync_evidence_ids(self) -> "PolicyExplanation":
        if not self.triggered_by:
            raise ValueError("policy explanation must include at least one trigger.")

        citation_ids = [citation.evidence_span_id for citation in self.evidence]
        if citation_ids and not self.evidence_span_ids:
            self.evidence_span_ids = citation_ids
        missing_ids = [citation_id for citation_id in citation_ids if citation_id not in self.evidence_span_ids]
        if missing_ids:
            raise ValueError("policy explanation evidence citations must be listed in evidence_span_ids.")
        return self


def build_policy_explanation(
    *,
    policy: PolicyRuleDefinition,
    triggered_by: list[str],
    evidence_span_ids: list[str] | None = None,
    evidence: list[PolicyEvidenceCitation] | None = None,
    confidence: float = 1.0,
    reason: str | None = None,
    recommended_action: str | None = None,
    metadata: dict[str, Any] | None = None,
) -> PolicyExplanation:
    return PolicyExplanation(
        decision=policy.action,
        policy_id=policy.policy_id,
        triggered_by=triggered_by,
        evidence_span_ids=evidence_span_ids or [],
        confidence=confidence,
        recommended_action=recommended_action or DEFAULT_RECOMMENDED_ACTIONS[policy.action],
        reason=reason or policy.description,
        evidence=evidence or [],
        metadata=metadata or {},
    )


def policy_explanation_to_markdown(explanation: PolicyExplanation) -> str:
    lines = [
        "Decision:",
        explanation.decision,
        "",
        "Policy ID:",
        explanation.policy_id,
        "",
        "Reason:",
        explanation.reason,
        "",
        "Triggered by:",
    ]
    lines.extend(f"- {trigger}" for trigger in explanation.triggered_by)
    lines.extend(["", "Evidence:"])

    if not explanation.evidence_span_ids:
        lines.append("- None")
    elif explanation.evidence:
        lines.extend(f"- {citation.evidence_span_id}: {_citation_label(citation)}" for citation in explanation.evidence)
    else:
        lines.extend(f"- {evidence_span_id}" for evidence_span_id in explanation.evidence_span_ids)

    lines.extend(
        [
            "",
            "Confidence:",
            f"{explanation.confidence:.2f}",
            "",
            "Recommendation:",
            explanation.recommended_action,
            "",
        ]
    )
    return "\n".join(lines)


def _citation_label(citation: PolicyEvidenceCitation) -> str:
    location = citation.file_path or citation.artifact_id or "unknown artifact"
    if citation.start_line is not None and citation.end_line is not None:
        location = f"{location} lines {citation.start_line}-{citation.end_line}"
    if citation.preview:
        return f"{location} - {citation.preview}"
    return location
