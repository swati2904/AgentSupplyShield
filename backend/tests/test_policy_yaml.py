import pytest
from pydantic import ValidationError

from app.policy_yaml import (
    DEFAULT_POLICY_YAML,
    PolicyCondition,
    PolicyConditionGroup,
    PolicyPack,
    default_policy_pack,
    load_policy_yaml_file,
    load_policy_yaml_text,
)


def test_default_policy_yaml_contains_roadmap_policy_categories() -> None:
    policy_pack = default_policy_pack()

    actions_by_id = {policy.policy_id: policy.action for policy in policy_pack.policies}

    assert policy_pack.version == "0.1"
    assert list(actions_by_id) == ["P1", "P2", "P3", "P4", "P5", "P6", "P7", "P8"]
    assert actions_by_id == {
        "P1": "block",
        "P2": "quarantine",
        "P3": "human_approval",
        "P4": "block",
        "P5": "warn",
        "P6": "quarantine",
        "P7": "block",
        "P8": "human_approval",
    }
    assert all(policy.evidence_required for policy in policy_pack.policies)


def test_load_policy_yaml_text_parses_condition_groups() -> None:
    policy_pack = load_policy_yaml_text(
        """
version: "0.1"
metadata:
  owner: security
policies:
  - policy_id: custom_policy
    name: quarantine_network_with_secrets
    description: Quarantine tools that combine secrets and network access.
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
"""
    )

    policy = policy_pack.policies[0]

    assert policy_pack.metadata["owner"] == "security"
    assert policy.policy_id == "custom_policy"
    assert policy.match.all_of[0].signal == "sensitive_env_var_count"
    assert policy.match.all_of[1].value == 1
    assert policy.match.any_of == []


def test_load_policy_yaml_file_reads_utf8_yaml(tmp_path) -> None:
    path = tmp_path / "policies.yaml"
    path.write_text(DEFAULT_POLICY_YAML, encoding="utf-8")

    policy_pack = load_policy_yaml_file(path)

    assert len(policy_pack.policies) == 8
    assert policy_pack.policies[0].policy_id == "P1"


def test_policy_yaml_rejects_duplicate_policy_ids() -> None:
    with pytest.raises(ValidationError, match="duplicate policy id"):
        PolicyPack(
            version="0.1",
            policies=[
                _policy_dict("P1"),
                _policy_dict("P1"),
            ],
        )


def test_policy_conditions_validate_required_value_shapes() -> None:
    with pytest.raises(ValidationError, match="contains_any policy conditions require values"):
        PolicyCondition(signal="finding_type", operator="contains_any")

    with pytest.raises(ValidationError, match="gte policy conditions require value"):
        PolicyCondition(signal="risk_score", operator="gte")

    exists_condition = PolicyCondition(signal="policy_decision", operator="exists")

    assert exists_condition.value is None
    assert exists_condition.values == []


def test_policy_yaml_rejects_empty_match_groups_and_blank_strings() -> None:
    with pytest.raises(ValidationError, match="match group"):
        PolicyConditionGroup()

    with pytest.raises(ValidationError, match="must not be blank"):
        PolicyPack(version=" ", policies=[_policy_dict("P1")])

    with pytest.raises(ValueError, match="document root"):
        load_policy_yaml_text("- just\n- a\n- list\n")


def _policy_dict(policy_id: str) -> dict[str, object]:
    return {
        "policy_id": policy_id,
        "name": "block_instruction_override_metadata",
        "description": "Block tool metadata containing instruction override patterns.",
        "action": "block",
        "match": {
            "any": [
                {
                    "signal": "finding_type",
                    "operator": "contains_any",
                    "values": ["direct_instruction", "indirect_prompt_injection"],
                }
            ]
        },
    }
