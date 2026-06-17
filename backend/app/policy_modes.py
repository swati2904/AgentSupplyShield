from typing import Literal, TypeAlias

from pydantic import BaseModel, Field, field_validator

from app.policy_yaml import PolicyAction
from app.risk_scoring import RiskLevel


PolicyModeName: TypeAlias = Literal[
    "research_mode",
    "warn_mode",
    "strict_mode",
    "enterprise_mode",
    "benchmark_mode",
]

HIGH_RISK_LEVELS: tuple[RiskLevel, ...] = ("high", "critical")
STATE_CHANGING_POLICY_TAGS: tuple[str, ...] = (
    "state_change",
    "filesystem",
    "shell_execution",
    "database_write",
    "email_send",
)


class PolicyModeDefinition(BaseModel):
    mode: PolicyModeName
    description: str
    logs_decisions: bool
    blocks_execution: bool
    marks_risk: bool
    records_outcomes: bool
    blocks_risk_levels: tuple[RiskLevel, ...] = ()
    approval_required_tags: tuple[str, ...] = ()
    synthetic_attack_mode: bool = False

    @field_validator("description")
    @classmethod
    def _description_must_not_be_blank(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("policy mode description must not be blank.")
        return value


POLICY_MODE_DEFINITIONS: dict[PolicyModeName, PolicyModeDefinition] = {
    "research_mode": PolicyModeDefinition(
        mode="research_mode",
        description="Logs everything, blocks nothing.",
        logs_decisions=True,
        blocks_execution=False,
        marks_risk=True,
        records_outcomes=True,
    ),
    "warn_mode": PolicyModeDefinition(
        mode="warn_mode",
        description="Allows execution but marks risk.",
        logs_decisions=True,
        blocks_execution=False,
        marks_risk=True,
        records_outcomes=True,
    ),
    "strict_mode": PolicyModeDefinition(
        mode="strict_mode",
        description="Blocks high and critical risks.",
        logs_decisions=True,
        blocks_execution=True,
        marks_risk=True,
        records_outcomes=True,
        blocks_risk_levels=HIGH_RISK_LEVELS,
    ),
    "enterprise_mode": PolicyModeDefinition(
        mode="enterprise_mode",
        description="Requires human approval for high-risk tool categories.",
        logs_decisions=True,
        blocks_execution=True,
        marks_risk=True,
        records_outcomes=True,
        blocks_risk_levels=("critical",),
        approval_required_tags=STATE_CHANGING_POLICY_TAGS,
    ),
    "benchmark_mode": PolicyModeDefinition(
        mode="benchmark_mode",
        description="Uses synthetic attacks and records outcomes.",
        logs_decisions=True,
        blocks_execution=False,
        marks_risk=True,
        records_outcomes=True,
        synthetic_attack_mode=True,
    ),
}


class PolicyModeDecision(BaseModel):
    mode: PolicyModeName
    original_action: PolicyAction
    effective_action: PolicyAction
    risk_level: RiskLevel
    reason: str


def default_policy_modes() -> tuple[PolicyModeDefinition, ...]:
    return tuple(POLICY_MODE_DEFINITIONS.values())


def policy_mode_definition(mode: PolicyModeName) -> PolicyModeDefinition:
    return POLICY_MODE_DEFINITIONS[mode]


def apply_policy_mode(
    *,
    mode: PolicyModeName,
    action: PolicyAction,
    risk_level: RiskLevel,
    policy_tags: list[str] | tuple[str, ...] = (),
) -> PolicyModeDecision:
    definition = policy_mode_definition(mode)
    effective_action = action
    reason = "Policy action unchanged by mode."

    if mode == "research_mode":
        effective_action = "allow"
        reason = "Research mode logs decisions but blocks nothing."
    elif mode == "warn_mode" and action != "allow":
        effective_action = "warn"
        reason = "Warn mode allows execution while marking risk."
    elif mode == "strict_mode" and risk_level in definition.blocks_risk_levels:
        effective_action = "block"
        reason = "Strict mode blocks high and critical risks."
    elif mode == "enterprise_mode":
        if risk_level in definition.blocks_risk_levels:
            effective_action = "block"
            reason = "Enterprise mode blocks critical risks."
        elif _has_approval_required_tag(policy_tags, definition.approval_required_tags):
            effective_action = "human_approval"
            reason = "Enterprise mode requires approval for high-risk tool categories."
    elif mode == "benchmark_mode":
        effective_action = action
        reason = "Benchmark mode records outcomes for synthetic attacks."

    return PolicyModeDecision(
        mode=mode,
        original_action=action,
        effective_action=effective_action,
        risk_level=risk_level,
        reason=reason,
    )


def _has_approval_required_tag(policy_tags: list[str] | tuple[str, ...], approval_tags: tuple[str, ...]) -> bool:
    normalized_policy_tags = {tag.lower() for tag in policy_tags}
    return any(tag in normalized_policy_tags for tag in approval_tags)
