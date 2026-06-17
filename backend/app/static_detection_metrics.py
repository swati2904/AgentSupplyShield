from typing import Any

from pydantic import BaseModel, Field, field_validator

from app.models import PolicyDecision, Severity


STATIC_DETECTION_LABEL_FIELDS: tuple[str, ...] = (
    "has_prompt_injection",
    "has_tool_poisoning",
    "has_permission_overreach",
    "has_credential_risk",
    "has_external_exfiltration_risk",
    "has_suspicious_obfuscation",
)

STATIC_DETECTION_METRIC_FIELDS: tuple[str, ...] = (
    "sample_count",
    "positive_count",
    "negative_count",
    "true_positive_count",
    "false_positive_count",
    "true_negative_count",
    "false_negative_count",
    "precision",
    "recall",
    "f1",
    "false_positive_rate",
    "false_negative_rate",
    "severity_calibration",
    "finding_level_accuracy",
    "tool_level_accuracy",
)

POLICY_DECISION_SEVERITY: dict[PolicyDecision, Severity] = {
    "allow": "low",
    "warn": "medium",
    "quarantine": "high",
    "block": "critical",
}


class StaticDetectionGroundTruth(BaseModel):
    record_id: str
    tool_id: str
    is_positive: bool
    expected_policy_decision: PolicyDecision
    severity: Severity | None = None

    @field_validator("record_id", "tool_id")
    @classmethod
    def _strings_must_not_be_blank(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("static detection ground-truth strings must not be blank.")
        return value


class StaticDetectionPrediction(BaseModel):
    record_id: str
    is_positive: bool
    predicted_policy_decision: PolicyDecision | None = None
    severity: Severity | None = None

    @field_validator("record_id")
    @classmethod
    def _record_id_must_not_be_blank(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("static detection prediction record id must not be blank.")
        return value


class StaticDetectionMetrics(BaseModel):
    sample_count: int = Field(ge=0)
    positive_count: int = Field(ge=0)
    negative_count: int = Field(ge=0)
    true_positive_count: int = Field(ge=0)
    false_positive_count: int = Field(ge=0)
    true_negative_count: int = Field(ge=0)
    false_negative_count: int = Field(ge=0)
    precision: float = Field(ge=0.0, le=1.0)
    recall: float = Field(ge=0.0, le=1.0)
    f1: float = Field(ge=0.0, le=1.0)
    false_positive_rate: float = Field(ge=0.0, le=1.0)
    false_negative_rate: float = Field(ge=0.0, le=1.0)
    severity_calibration: float = Field(ge=0.0, le=1.0)
    finding_level_accuracy: float = Field(ge=0.0, le=1.0)
    tool_level_accuracy: float = Field(ge=0.0, le=1.0)


def ground_truth_from_label_record(label_record: dict[str, Any], *, tool_id: str) -> StaticDetectionGroundTruth:
    labels = label_record["labels"]
    expected_policy_decision: PolicyDecision = labels["expected_policy_decision"]
    return StaticDetectionGroundTruth(
        record_id=label_record["record_id"],
        tool_id=tool_id,
        is_positive=any(bool(labels[field]) for field in STATIC_DETECTION_LABEL_FIELDS),
        expected_policy_decision=expected_policy_decision,
        severity=POLICY_DECISION_SEVERITY[expected_policy_decision],
    )


def summarize_static_detection_metrics(
    ground_truth: list[StaticDetectionGroundTruth],
    predictions: list[StaticDetectionPrediction],
) -> StaticDetectionMetrics:
    truth_by_id = _index_ground_truth_by_record_id(ground_truth)
    prediction_by_id = _index_predictions_by_record_id(predictions)

    if set(truth_by_id) != set(prediction_by_id):
        raise ValueError("static detection predictions must match ground truth record ids.")

    true_positive_count = 0
    false_positive_count = 0
    true_negative_count = 0
    false_negative_count = 0
    severity_match_count = 0
    severity_comparison_count = 0
    truth_positive_by_tool: dict[str, bool] = {}
    prediction_positive_by_tool: dict[str, bool] = {}

    for truth in ground_truth:
        prediction = prediction_by_id[truth.record_id]
        if truth.is_positive and prediction.is_positive:
            true_positive_count += 1
        elif truth.is_positive and not prediction.is_positive:
            false_negative_count += 1
        elif not truth.is_positive and prediction.is_positive:
            false_positive_count += 1
        else:
            true_negative_count += 1

        if truth.severity is not None and prediction.severity is not None:
            severity_comparison_count += 1
            if truth.severity == prediction.severity:
                severity_match_count += 1

        truth_positive_by_tool[truth.tool_id] = truth_positive_by_tool.get(truth.tool_id, False) or truth.is_positive
        prediction_positive_by_tool[truth.tool_id] = (
            prediction_positive_by_tool.get(truth.tool_id, False) or prediction.is_positive
        )

    sample_count = len(ground_truth)
    positive_count = true_positive_count + false_negative_count
    negative_count = true_negative_count + false_positive_count
    precision = _rate(true_positive_count, true_positive_count + false_positive_count)
    recall = _rate(true_positive_count, true_positive_count + false_negative_count)
    f1 = _rate(2 * precision * recall, precision + recall)
    tool_match_count = sum(
        1
        for tool_id, has_positive_truth in truth_positive_by_tool.items()
        if prediction_positive_by_tool[tool_id] == has_positive_truth
    )

    return StaticDetectionMetrics(
        sample_count=sample_count,
        positive_count=positive_count,
        negative_count=negative_count,
        true_positive_count=true_positive_count,
        false_positive_count=false_positive_count,
        true_negative_count=true_negative_count,
        false_negative_count=false_negative_count,
        precision=precision,
        recall=recall,
        f1=f1,
        false_positive_rate=_rate(false_positive_count, false_positive_count + true_negative_count),
        false_negative_rate=_rate(false_negative_count, false_negative_count + true_positive_count),
        severity_calibration=_rate(severity_match_count, severity_comparison_count),
        finding_level_accuracy=_rate(true_positive_count + true_negative_count, sample_count),
        tool_level_accuracy=_rate(tool_match_count, len(truth_positive_by_tool)),
    )


def _index_ground_truth_by_record_id(
    ground_truth: list[StaticDetectionGroundTruth],
) -> dict[str, StaticDetectionGroundTruth]:
    indexed: dict[str, StaticDetectionGroundTruth] = {}
    for record in ground_truth:
        if record.record_id in indexed:
            raise ValueError(f"duplicate static detection ground-truth record id: {record.record_id}")
        indexed[record.record_id] = record
    return indexed


def _index_predictions_by_record_id(
    predictions: list[StaticDetectionPrediction],
) -> dict[str, StaticDetectionPrediction]:
    indexed: dict[str, StaticDetectionPrediction] = {}
    for prediction in predictions:
        if prediction.record_id in indexed:
            raise ValueError(f"duplicate static detection prediction record id: {prediction.record_id}")
        indexed[prediction.record_id] = prediction
    return indexed


def _rate(numerator: float, denominator: int | float) -> float:
    if denominator == 0:
        return 0.0
    return numerator / denominator
