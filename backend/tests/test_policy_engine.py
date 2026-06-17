from app.policy_engine import evaluate_default_policies, evaluate_policy_pack
from app.policy_yaml import load_policy_yaml_text


def test_policy_engine_allows_low_risk_tool_without_policy_match() -> None:
    result = evaluate_default_policies(
        context={"tool_id": "read_only_tool", "capability_ids": ["local_read"]},
        risk_level="low",
        mode="benchmark_mode",
    )

    assert result.final_action == "allow"
    assert result.matched_policy_ids == []


def test_policy_engine_warns_medium_risk_tool_without_policy_match() -> None:
    result = evaluate_default_policies(
        context={"tool_id": "formatting_tool", "capability_ids": ["local_read"]},
        risk_level="medium",
        mode="benchmark_mode",
    )

    assert result.final_action == "warn"
    assert result.matched_policy_ids == []


def test_policy_engine_quarantines_injection_risk_tool() -> None:
    policy_pack = load_policy_yaml_text(
        """
version: "0.1"
policies:
  - policy_id: injection_quarantine
    name: quarantine_indirect_prompt_injection
    description: Quarantine tool metadata with indirect prompt injection evidence.
    action: quarantine
    tags: [prompt_injection]
    evidence_required: true
    match:
      any:
        - signal: finding_type
          operator: equals
          value: indirect_prompt_injection
"""
    )

    result = evaluate_policy_pack(
        policy_pack=policy_pack,
        context={
            "finding_type": "indirect_prompt_injection",
            "evidence_span_ids": ["span_1"],
            "confidence": 0.91,
        },
        risk_level="high",
        mode="benchmark_mode",
    )

    assert result.final_action == "quarantine"
    assert result.matched_policy_ids == ["injection_quarantine"]
    assert result.matches[0].explanation.evidence_span_ids == ["span_1"]
    assert result.matches[0].explanation.confidence == 0.91


def test_policy_engine_blocks_shell_execution_tool() -> None:
    result = evaluate_default_policies(
        context={
            "tool_id": "shell_runner",
            "capability_ids": ["shell_execution"],
            "shell_execution_allowlist": [],
            "evidence_span_ids": ["span_shell"],
        },
        risk_level="critical",
        mode="benchmark_mode",
    )

    assert result.final_action == "block"
    assert result.matched_policy_ids == ["P4"]
    assert result.matches[0].effective_action == "block"
    assert "capability_ids contains shell_execution" in result.matches[0].triggered_by
    assert "tool_id not_allowlisted shell_execution_allowlist" in result.matches[0].triggered_by


def test_policy_engine_respects_shell_execution_allowlist() -> None:
    result = evaluate_default_policies(
        context={
            "tool_id": "approved_shell_runner",
            "capability_ids": ["shell_execution"],
            "shell_execution_allowlist": ["approved_shell_runner"],
        },
        risk_level="low",
        mode="benchmark_mode",
    )

    assert result.final_action == "allow"
    assert result.matched_policy_ids == []


def test_policy_engine_requires_approval_for_state_changing_action() -> None:
    result = evaluate_default_policies(
        context={
            "tool_id": "ticket_writer",
            "capability_ids": ["ticket_update"],
            "evidence_span_ids": ["span_ticket"],
        },
        risk_level="medium",
        mode="benchmark_mode",
    )

    assert result.final_action == "human_approval"
    assert result.matched_policy_ids == ["P8"]
    assert result.matches[0].policy_action == "human_approval"
    assert result.matches[0].explanation.decision == "human_approval"


def test_policy_engine_applies_policy_modes_to_matched_actions() -> None:
    warn_result = evaluate_default_policies(
        context={
            "tool_id": "shell_runner",
            "capability_ids": ["shell_execution"],
            "shell_execution_allowlist": [],
        },
        risk_level="critical",
        mode="warn_mode",
    )
    research_result = evaluate_default_policies(
        context={
            "tool_id": "shell_runner",
            "capability_ids": ["shell_execution"],
            "shell_execution_allowlist": [],
        },
        risk_level="critical",
        mode="research_mode",
    )

    assert warn_result.final_action == "warn"
    assert warn_result.matches[0].policy_action == "block"
    assert warn_result.matches[0].effective_action == "warn"
    assert research_result.final_action == "allow"
