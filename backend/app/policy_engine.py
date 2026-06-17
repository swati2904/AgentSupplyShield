from typing import Any

from pydantic import BaseModel, Field

from app.policy_explanations import PolicyExplanation, build_policy_explanation
from app.policy_modes import PolicyModeName, apply_policy_mode
from app.policy_yaml import PolicyAction, PolicyCondition, PolicyPack, PolicyRuleDefinition, default_policy_pack
from app.risk_scoring import RiskLevel, policy_decision_for_level


ACTION_PRIORITY: dict[PolicyAction, int] = {
    "allow": 0,
    "warn": 1,
    "sandbox_only": 2,
    "human_approval": 3,
    "quarantine": 4,
    "block": 5,
}


class PolicyMatch(BaseModel):
    policy_id: str
    policy_name: str
    policy_action: PolicyAction
    effective_action: PolicyAction
    triggered_by: list[str]
    evidence_span_ids: list[str] = Field(default_factory=list)
    explanation: PolicyExplanation


class PolicyEvaluationResult(BaseModel):
    mode: PolicyModeName
    risk_level: RiskLevel
    final_action: PolicyAction
    matched_policy_ids: list[str]
    matches: list[PolicyMatch]


def evaluate_default_policies(
    *,
    context: dict[str, Any],
    risk_level: RiskLevel,
    mode: PolicyModeName,
) -> PolicyEvaluationResult:
    return evaluate_policy_pack(policy_pack=default_policy_pack(), context=context, risk_level=risk_level, mode=mode)


def evaluate_policy_pack(
    *,
    policy_pack: PolicyPack,
    context: dict[str, Any],
    risk_level: RiskLevel,
    mode: PolicyModeName,
) -> PolicyEvaluationResult:
    matches = [
        match
        for policy in policy_pack.policies
        if policy.enabled
        for match in [_evaluate_policy(policy, context, risk_level, mode)]
        if match is not None
    ]

    final_action = _highest_priority_action([match.effective_action for match in matches])
    if final_action is None:
        fallback_action = policy_decision_for_level(risk_level)
        final_action = apply_policy_mode(mode=mode, action=fallback_action, risk_level=risk_level).effective_action

    return PolicyEvaluationResult(
        mode=mode,
        risk_level=risk_level,
        final_action=final_action,
        matched_policy_ids=[match.policy_id for match in matches],
        matches=matches,
    )


def _evaluate_policy(
    policy: PolicyRuleDefinition,
    context: dict[str, Any],
    risk_level: RiskLevel,
    mode: PolicyModeName,
) -> PolicyMatch | None:
    matched, triggered_by = _match_policy(policy, context)
    if not matched:
        return None

    mode_decision = apply_policy_mode(
        mode=mode,
        action=policy.action,
        risk_level=risk_level,
        policy_tags=policy.tags,
    )
    evidence_span_ids = _string_list(context.get("evidence_span_ids", []))
    explanation = build_policy_explanation(
        policy=policy,
        triggered_by=triggered_by,
        evidence_span_ids=evidence_span_ids,
        confidence=_confidence(context),
        metadata={"mode": mode, "mode_reason": mode_decision.reason},
    )
    return PolicyMatch(
        policy_id=policy.policy_id,
        policy_name=policy.name,
        policy_action=policy.action,
        effective_action=mode_decision.effective_action,
        triggered_by=triggered_by,
        evidence_span_ids=evidence_span_ids,
        explanation=explanation,
    )


def _match_policy(policy: PolicyRuleDefinition, context: dict[str, Any]) -> tuple[bool, list[str]]:
    all_results = [_condition_matches(condition, context) for condition in policy.match.all_of]
    if any(not matched for matched, _ in all_results):
        return False, []

    any_results = [_condition_matches(condition, context) for condition in policy.match.any_of]
    if any_results and not any(matched for matched, _ in any_results):
        return False, []

    triggered_by = [label for matched, label in [*all_results, *any_results] if matched]
    return True, triggered_by


def _condition_matches(condition: PolicyCondition, context: dict[str, Any]) -> tuple[bool, str]:
    actual = _signal_value(context, condition.signal)
    expected = condition.value

    if condition.operator == "equals":
        matched = _values_equal(actual, expected)
    elif condition.operator == "not_equals":
        matched = not _values_equal(actual, expected)
    elif condition.operator == "contains":
        matched = _contains(actual, expected)
    elif condition.operator == "contains_any":
        matched = any(_contains(actual, value) for value in condition.values)
    elif condition.operator == "in":
        matched = any(_values_equal(actual, value) for value in condition.values)
    elif condition.operator == "gte":
        matched = _numeric_compare(actual, expected, ">=")
    elif condition.operator == "lte":
        matched = _numeric_compare(actual, expected, "<=")
    elif condition.operator == "exists":
        matched = actual is not None
    elif condition.operator == "changed":
        matched = _is_changed(actual)
    elif condition.operator == "not_allowlisted":
        matched = not _contains(_signal_value(context, str(expected)), actual)
    else:
        matched = False

    return matched, _condition_label(condition)


def _signal_value(context: dict[str, Any], signal: str) -> Any:
    if signal in context:
        return context[signal]

    current: Any = context
    for part in signal.split("."):
        if isinstance(current, dict) and part in current:
            current = current[part]
        else:
            return None
    return current


def _contains(actual: Any, expected: Any) -> bool:
    if actual is None:
        return False
    if isinstance(actual, dict):
        return _normalized(expected) in {_normalized(key) for key in actual}
    if isinstance(actual, list | tuple | set):
        return any(_values_equal(item, expected) for item in actual)
    if isinstance(actual, str):
        return _normalized(expected) in _normalized(actual)
    return _values_equal(actual, expected)


def _values_equal(actual: Any, expected: Any) -> bool:
    if isinstance(actual, list | tuple | set):
        return any(_values_equal(item, expected) for item in actual)
    return _normalized(actual) == _normalized(expected)


def _numeric_compare(actual: Any, expected: Any, operator: str) -> bool:
    actual_number = _as_number(actual)
    expected_number = _as_number(expected)
    if actual_number is None or expected_number is None:
        return False
    if operator == ">=":
        return actual_number >= expected_number
    return actual_number <= expected_number


def _is_changed(actual: Any) -> bool:
    if isinstance(actual, bool):
        return actual
    if isinstance(actual, int | float):
        return actual > 0
    if isinstance(actual, str):
        return bool(actual.strip())
    if isinstance(actual, list | tuple | set | dict):
        return bool(actual)
    return actual is not None


def _as_number(value: Any) -> float | None:
    if isinstance(value, int | float):
        return float(value)
    if isinstance(value, str):
        try:
            return float(value)
        except ValueError:
            return None
    return None


def _condition_label(condition: PolicyCondition) -> str:
    if condition.operator in {"contains_any", "in"}:
        return f"{condition.signal} {condition.operator} {condition.values}"
    if condition.operator in {"exists", "changed"}:
        return f"{condition.signal} {condition.operator}"
    return f"{condition.signal} {condition.operator} {condition.value}"


def _highest_priority_action(actions: list[PolicyAction]) -> PolicyAction | None:
    if not actions:
        return None
    return max(actions, key=lambda action: ACTION_PRIORITY[action])


def _confidence(context: dict[str, Any]) -> float:
    confidence = _as_number(context.get("confidence", 1.0))
    if confidence is None:
        return 1.0
    return max(0.0, min(confidence, 1.0))


def _string_list(value: Any) -> list[str]:
    if isinstance(value, list | tuple | set):
        return [str(item) for item in value]
    if value is None:
        return []
    return [str(value)]


def _normalized(value: Any) -> str:
    return str(value).strip().lower()
