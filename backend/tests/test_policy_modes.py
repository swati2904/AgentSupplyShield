import pytest
from pydantic import ValidationError

from app.policy_modes import (
    HIGH_RISK_LEVELS,
    POLICY_MODE_DEFINITIONS,
    PolicyModeDefinition,
    apply_policy_mode,
    default_policy_modes,
    policy_mode_definition,
)


def test_default_policy_modes_match_roadmap_modes() -> None:
    modes = default_policy_modes()

    assert [mode.mode for mode in modes] == [
        "research_mode",
        "warn_mode",
        "strict_mode",
        "enterprise_mode",
        "benchmark_mode",
    ]
    assert POLICY_MODE_DEFINITIONS["research_mode"].description == "Logs everything, blocks nothing."
    assert POLICY_MODE_DEFINITIONS["warn_mode"].description == "Allows execution but marks risk."
    assert POLICY_MODE_DEFINITIONS["strict_mode"].blocks_risk_levels == HIGH_RISK_LEVELS
    assert POLICY_MODE_DEFINITIONS["enterprise_mode"].approval_required_tags
    assert POLICY_MODE_DEFINITIONS["benchmark_mode"].synthetic_attack_mode is True


def test_policy_mode_lookup_returns_definition() -> None:
    definition = policy_mode_definition("strict_mode")

    assert definition.mode == "strict_mode"
    assert definition.blocks_execution is True
    assert definition.marks_risk is True


def test_research_and_warn_modes_do_not_block_execution() -> None:
    research_decision = apply_policy_mode(mode="research_mode", action="block", risk_level="critical")
    warn_decision = apply_policy_mode(mode="warn_mode", action="quarantine", risk_level="high")

    assert research_decision.effective_action == "allow"
    assert research_decision.reason == "Research mode logs decisions but blocks nothing."
    assert warn_decision.effective_action == "warn"
    assert warn_decision.reason == "Warn mode allows execution while marking risk."


def test_strict_mode_blocks_high_and_critical_risk_levels() -> None:
    medium_decision = apply_policy_mode(mode="strict_mode", action="warn", risk_level="medium")
    high_decision = apply_policy_mode(mode="strict_mode", action="warn", risk_level="high")
    critical_decision = apply_policy_mode(mode="strict_mode", action="allow", risk_level="critical")

    assert medium_decision.effective_action == "warn"
    assert high_decision.effective_action == "block"
    assert critical_decision.effective_action == "block"


def test_enterprise_mode_requires_approval_for_high_risk_categories() -> None:
    approval_decision = apply_policy_mode(
        mode="enterprise_mode",
        action="warn",
        risk_level="medium",
        policy_tags=["state_change"],
    )
    critical_decision = apply_policy_mode(
        mode="enterprise_mode",
        action="warn",
        risk_level="critical",
        policy_tags=["state_change"],
    )
    unchanged_decision = apply_policy_mode(
        mode="enterprise_mode",
        action="warn",
        risk_level="medium",
        policy_tags=["metadata"],
    )

    assert approval_decision.effective_action == "human_approval"
    assert critical_decision.effective_action == "block"
    assert unchanged_decision.effective_action == "warn"


def test_benchmark_mode_records_outcomes_without_changing_policy_action() -> None:
    decision = apply_policy_mode(mode="benchmark_mode", action="sandbox_only", risk_level="high")

    assert decision.effective_action == "sandbox_only"
    assert decision.reason == "Benchmark mode records outcomes for synthetic attacks."
    assert policy_mode_definition("benchmark_mode").records_outcomes is True


def test_policy_mode_definition_rejects_blank_description() -> None:
    with pytest.raises(ValidationError, match="description"):
        PolicyModeDefinition(
            mode="research_mode",
            description=" ",
            logs_decisions=True,
            blocks_execution=False,
            marks_risk=True,
            records_outcomes=True,
        )
