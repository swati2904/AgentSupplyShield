from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


PolicyAction = Literal["allow", "warn", "quarantine", "block", "human_approval", "sandbox_only"]
PolicyOperator = Literal[
    "equals",
    "not_equals",
    "contains",
    "contains_any",
    "in",
    "gte",
    "lte",
    "exists",
    "changed",
    "not_allowlisted",
]

DEFAULT_POLICY_YAML = """
version: "0.1"
metadata:
  name: AgentSupplyShield default policies
  description: Default policy categories from the AgentSupplyShield roadmap.
policies:
  - policy_id: P1
    name: block_instruction_override_metadata
    description: Block tool metadata containing instruction override patterns.
    action: block
    enabled: true
    tags: [prompt_injection, metadata]
    evidence_required: true
    match:
      any:
        - signal: finding_type
          operator: contains_any
          values: [direct_instruction, indirect_prompt_injection, tool_poisoning]
        - signal: tool_metadata_text
          operator: contains_any
          values: [ignore previous, system prompt, developer message]

  - policy_id: P2
    name: quarantine_credentials_with_network
    description: Quarantine tools combining credential references with external network access.
    action: quarantine
    enabled: true
    tags: [credential_exposure, network_access]
    evidence_required: true
    match:
      all:
        - signal: sensitive_env_var_count
          operator: gte
          value: 1
        - signal: external_communication_degree
          operator: gte
          value: 1

  - policy_id: P3
    name: approve_filesystem_write
    description: Require approval for tools with filesystem write.
    action: human_approval
    enabled: true
    tags: [filesystem, state_change]
    evidence_required: true
    match:
      any:
        - signal: capability_ids
          operator: contains
          value: filesystem_write

  - policy_id: P4
    name: block_shell_execution_without_allowlist
    description: Block shell execution unless explicitly allowlisted.
    action: block
    enabled: true
    tags: [shell_execution, allowlist]
    evidence_required: true
    match:
      all:
        - signal: capability_ids
          operator: contains
          value: shell_execution
        - signal: tool_id
          operator: not_allowlisted
          value: shell_execution_allowlist

  - policy_id: P5
    name: warn_purpose_capability_mismatch
    description: Warn when tool purpose does not match detected capabilities.
    action: warn
    enabled: true
    tags: [capability_mismatch]
    evidence_required: true
    match:
      any:
        - signal: finding_type
          operator: equals
          value: permission_overreach

  - policy_id: P6
    name: quarantine_metadata_changed_after_approval
    description: Quarantine if metadata changed after previous approval.
    action: quarantine
    enabled: true
    tags: [metadata_change, approval]
    evidence_required: true
    match:
      all:
        - signal: approval_status
          operator: equals
          value: approved
        - signal: recent_metadata_change_count
          operator: gte
          value: 1

  - policy_id: P7
    name: block_output_instruction_override
    description: Block tool output that attempts to alter system, developer, or user instructions.
    action: block
    enabled: true
    tags: [runtime_output, prompt_injection]
    evidence_required: true
    match:
      any:
        - signal: tool_output_text
          operator: contains_any
          values: [ignore previous, system message, developer instruction]

  - policy_id: P8
    name: approve_state_changing_tools
    description: Require human approval for state-changing tools.
    action: human_approval
    enabled: true
    tags: [state_change]
    evidence_required: true
    match:
      any:
        - signal: capability_ids
          operator: contains_any
          values: [email_send, database_write, ticket_update, filesystem_write]
""".strip()


class PolicyCondition(BaseModel):
    signal: str
    operator: PolicyOperator
    value: Any | None = None
    values: list[Any] = Field(default_factory=list)
    description: str | None = None

    @field_validator("signal")
    @classmethod
    def _signal_must_not_be_blank(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("policy condition signal must not be blank.")
        return value

    @model_validator(mode="after")
    def _value_shape_must_match_operator(self) -> "PolicyCondition":
        if self.operator in {"contains_any", "in"} and not self.values:
            raise ValueError(f"{self.operator} policy conditions require values.")
        if self.operator not in {"contains_any", "in", "exists", "changed"} and self.value is None:
            raise ValueError(f"{self.operator} policy conditions require value.")
        return self


class PolicyConditionGroup(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    all_of: list[PolicyCondition] = Field(default_factory=list, alias="all")
    any_of: list[PolicyCondition] = Field(default_factory=list, alias="any")

    @model_validator(mode="after")
    def _must_have_at_least_one_condition(self) -> "PolicyConditionGroup":
        if not self.all_of and not self.any_of:
            raise ValueError("policy match group must include at least one condition.")
        return self


class PolicyRuleDefinition(BaseModel):
    policy_id: str
    name: str
    description: str
    action: PolicyAction
    enabled: bool = True
    tags: list[str] = Field(default_factory=list)
    evidence_required: bool = True
    match: PolicyConditionGroup

    @field_validator("policy_id", "name", "description")
    @classmethod
    def _strings_must_not_be_blank(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("policy identifiers, names, and descriptions must not be blank.")
        return value

    @field_validator("tags")
    @classmethod
    def _tags_must_not_be_blank(cls, value: list[str]) -> list[str]:
        if any(not tag.strip() for tag in value):
            raise ValueError("policy tags must not be blank.")
        return value


class PolicyPack(BaseModel):
    version: str
    metadata: dict[str, Any] = Field(default_factory=dict)
    policies: list[PolicyRuleDefinition]

    @field_validator("version")
    @classmethod
    def _version_must_not_be_blank(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("policy pack version must not be blank.")
        return value

    @model_validator(mode="after")
    def _policy_ids_must_be_unique(self) -> "PolicyPack":
        seen_policy_ids: set[str] = set()
        for policy in self.policies:
            if policy.policy_id in seen_policy_ids:
                raise ValueError(f"duplicate policy id: {policy.policy_id}")
            seen_policy_ids.add(policy.policy_id)
        return self


def load_policy_yaml_text(text: str) -> PolicyPack:
    try:
        import yaml
    except ImportError as error:
        raise ValueError("PyYAML is required to load policy YAML.") from error

    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as error:
        raise ValueError(f"Invalid policy YAML: {error}") from error

    if not isinstance(data, dict):
        raise ValueError("Policy YAML must contain a mapping at the document root.")
    return PolicyPack.model_validate(data)


def load_policy_yaml_file(path: str | Path) -> PolicyPack:
    policy_path = Path(path)
    return load_policy_yaml_text(policy_path.read_text(encoding="utf-8"))


def default_policy_pack() -> PolicyPack:
    return load_policy_yaml_text(DEFAULT_POLICY_YAML)
