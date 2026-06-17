import pytest
from pydantic import ValidationError

from app.policy_explanations import (
    DEFAULT_RECOMMENDED_ACTIONS,
    PolicyEvidenceCitation,
    PolicyExplanation,
    build_policy_explanation,
    policy_explanation_to_markdown,
)
from app.policy_yaml import default_policy_pack


def test_policy_explanation_includes_roadmap_fields() -> None:
    explanation = PolicyExplanation(
        decision="quarantine",
        policy_id="P2",
        triggered_by=["sensitive_env_var_count >= 1", "external_communication_degree >= 1"],
        evidence_span_ids=["span_1"],
        confidence=0.92,
        recommended_action="Review tool metadata manually before connecting to production agents.",
        reason="Tool combines credential references with external network access.",
    )

    payload = explanation.model_dump()

    assert payload["decision"] == "quarantine"
    assert payload["policy_id"] == "P2"
    assert payload["triggered_by"] == ["sensitive_env_var_count >= 1", "external_communication_degree >= 1"]
    assert payload["evidence_span_ids"] == ["span_1"]
    assert payload["confidence"] == 0.92
    assert payload["recommended_action"].startswith("Review tool metadata")


def test_policy_explanation_can_derive_evidence_span_ids_from_citations() -> None:
    citation = PolicyEvidenceCitation(
        evidence_span_id="span_1",
        artifact_id="artifact_1",
        file_path="README.md",
        start_line=42,
        end_line=45,
        preview="ignore previous instructions",
    )

    explanation = PolicyExplanation(
        decision="block",
        policy_id="P1",
        triggered_by=["tool_metadata_text contains instruction override"],
        confidence=0.95,
        recommended_action=DEFAULT_RECOMMENDED_ACTIONS["block"],
        reason="Tool metadata contains instruction override text.",
        evidence=[citation],
    )

    assert explanation.evidence_span_ids == ["span_1"]


def test_build_policy_explanation_from_policy_rule_defaults_reason_and_recommendation() -> None:
    policy = default_policy_pack().policies[1]

    explanation = build_policy_explanation(
        policy=policy,
        triggered_by=["sensitive_env_var_count >= 1", "external_communication_degree >= 1"],
        evidence_span_ids=["span_1"],
        confidence=0.88,
    )

    assert explanation.decision == "quarantine"
    assert explanation.policy_id == "P2"
    assert explanation.reason == policy.description
    assert explanation.recommended_action == DEFAULT_RECOMMENDED_ACTIONS["quarantine"]


def test_policy_explanation_markdown_matches_roadmap_shape() -> None:
    citation = PolicyEvidenceCitation(
        evidence_span_id="span_1",
        file_path="tool_schema.json",
        start_line=12,
        end_line=12,
    )
    explanation = PolicyExplanation(
        decision="quarantine",
        policy_id="P2",
        triggered_by=["credential reference", "external network access"],
        confidence=0.9,
        recommended_action="Review tool metadata manually before connecting to production agents.",
        reason="Tool description contains a credential reference and the tool has network access.",
        evidence=[citation],
    )

    markdown = policy_explanation_to_markdown(explanation)

    assert "Decision:\nquarantine" in markdown
    assert "Policy ID:\nP2" in markdown
    assert "- credential reference" in markdown
    assert "- span_1: tool_schema.json lines 12-12" in markdown
    assert "Confidence:\n0.90" in markdown
    assert "Recommendation:\nReview tool metadata" in markdown


def test_policy_explanation_validation_rejects_missing_or_invalid_fields() -> None:
    with pytest.raises(ValidationError, match="at least one trigger"):
        PolicyExplanation(
            decision="warn",
            policy_id="P5",
            triggered_by=[],
            confidence=0.7,
            recommended_action="Warn before use.",
            reason="Tool purpose does not match detected capabilities.",
        )

    with pytest.raises(ValidationError):
        PolicyExplanation(
            decision="block",
            policy_id=" ",
            triggered_by=["instruction override"],
            confidence=0.7,
            recommended_action="Block tool use.",
            reason="Instruction override detected.",
        )

    with pytest.raises(ValidationError):
        PolicyExplanation(
            decision="block",
            policy_id="P1",
            triggered_by=["instruction override"],
            confidence=1.5,
            recommended_action="Block tool use.",
            reason="Instruction override detected.",
        )


def test_policy_evidence_citation_validates_line_order_and_evidence_id_consistency() -> None:
    with pytest.raises(ValidationError, match="end_line"):
        PolicyEvidenceCitation(
            evidence_span_id="span_1",
            file_path="README.md",
            start_line=45,
            end_line=42,
        )

    with pytest.raises(ValidationError, match="citations must be listed"):
        PolicyExplanation(
            decision="block",
            policy_id="P1",
            triggered_by=["instruction override"],
            evidence_span_ids=["span_2"],
            confidence=0.9,
            recommended_action="Block tool use.",
            reason="Instruction override detected.",
            evidence=[PolicyEvidenceCitation(evidence_span_id="span_1")],
        )
