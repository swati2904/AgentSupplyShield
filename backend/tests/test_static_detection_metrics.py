import json
from pathlib import Path
from typing import Any

import pytest

from app.static_detection_metrics import (
    STATIC_DETECTION_METRIC_FIELDS,
    StaticDetectionGroundTruth,
    StaticDetectionMetrics,
    StaticDetectionPrediction,
    ground_truth_from_label_record,
    summarize_static_detection_metrics,
)


DATASET_DIR = Path(__file__).resolve().parents[2] / "datasets"
SPECS_PATH = DATASET_DIR / "synthetic_tool_specs.jsonl"
LABELS_PATH = DATASET_DIR / "synthetic_tool_labels.jsonl"


def test_static_detection_metric_fields_cover_phase_11_4() -> None:
    assert STATIC_DETECTION_METRIC_FIELDS == (
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
    assert tuple(StaticDetectionMetrics.model_fields) == STATIC_DETECTION_METRIC_FIELDS


def test_static_detection_metrics_compute_binary_rates() -> None:
    ground_truth = [
        StaticDetectionGroundTruth(
            record_id="true_positive",
            tool_id="tool_a",
            is_positive=True,
            expected_policy_decision="block",
            severity="critical",
        ),
        StaticDetectionGroundTruth(
            record_id="false_negative",
            tool_id="tool_b",
            is_positive=True,
            expected_policy_decision="quarantine",
            severity="high",
        ),
        StaticDetectionGroundTruth(
            record_id="false_positive",
            tool_id="tool_c",
            is_positive=False,
            expected_policy_decision="allow",
            severity="low",
        ),
        StaticDetectionGroundTruth(
            record_id="true_negative",
            tool_id="tool_d",
            is_positive=False,
            expected_policy_decision="allow",
            severity="low",
        ),
    ]
    predictions = [
        StaticDetectionPrediction(record_id="true_positive", is_positive=True, severity="critical"),
        StaticDetectionPrediction(record_id="false_negative", is_positive=False, severity="low"),
        StaticDetectionPrediction(record_id="false_positive", is_positive=True, severity="medium"),
        StaticDetectionPrediction(record_id="true_negative", is_positive=False, severity="low"),
    ]

    metrics = summarize_static_detection_metrics(ground_truth, predictions)

    assert metrics.sample_count == 4
    assert metrics.positive_count == 2
    assert metrics.negative_count == 2
    assert metrics.true_positive_count == 1
    assert metrics.false_positive_count == 1
    assert metrics.true_negative_count == 1
    assert metrics.false_negative_count == 1
    assert metrics.precision == 0.5
    assert metrics.recall == 0.5
    assert metrics.f1 == 0.5
    assert metrics.false_positive_rate == 0.5
    assert metrics.false_negative_rate == 0.5
    assert metrics.finding_level_accuracy == 0.5


def test_static_detection_metrics_compute_severity_and_tool_accuracy() -> None:
    ground_truth = [
        StaticDetectionGroundTruth(
            record_id="tool_a_positive",
            tool_id="tool_a",
            is_positive=True,
            expected_policy_decision="quarantine",
            severity="high",
        ),
        StaticDetectionGroundTruth(
            record_id="tool_a_clean",
            tool_id="tool_a",
            is_positive=False,
            expected_policy_decision="allow",
            severity="low",
        ),
        StaticDetectionGroundTruth(
            record_id="tool_b_clean",
            tool_id="tool_b",
            is_positive=False,
            expected_policy_decision="allow",
            severity="low",
        ),
    ]
    predictions = [
        StaticDetectionPrediction(record_id="tool_a_positive", is_positive=True, severity="high"),
        StaticDetectionPrediction(record_id="tool_a_clean", is_positive=False, severity="medium"),
        StaticDetectionPrediction(record_id="tool_b_clean", is_positive=True, severity="low"),
    ]

    metrics = summarize_static_detection_metrics(ground_truth, predictions)

    assert metrics.severity_calibration == pytest.approx(2 / 3)
    assert metrics.tool_level_accuracy == 0.5


def test_ground_truth_from_label_record_uses_dataset_labels() -> None:
    specs_by_id = {record["record_id"]: record for record in _load_jsonl(SPECS_PATH)}
    labels_by_id = {record["record_id"]: record for record in _load_jsonl(LABELS_PATH)}

    clean = _ground_truth_from_dataset_record("clean_markdown_summarizer", specs_by_id, labels_by_id)
    poisoned = _ground_truth_from_dataset_record("poison_markdown_summarizer_readme", specs_by_id, labels_by_id)
    overreach = _ground_truth_from_dataset_record(
        "perm_overreach_calendar_reader_filesystem_write",
        specs_by_id,
        labels_by_id,
    )

    assert clean.tool_id == "markdown_summarizer"
    assert clean.is_positive is False
    assert clean.expected_policy_decision == "allow"
    assert clean.severity == "low"

    assert poisoned.tool_id == "markdown_summarizer"
    assert poisoned.is_positive is True
    assert poisoned.expected_policy_decision == "block"
    assert poisoned.severity == "critical"

    assert overreach.tool_id == "calendar_reader"
    assert overreach.is_positive is True
    assert overreach.expected_policy_decision == "quarantine"
    assert overreach.severity == "high"


def test_static_detection_metrics_reject_mismatched_and_duplicate_record_ids() -> None:
    ground_truth = [
        StaticDetectionGroundTruth(
            record_id="known_record",
            tool_id="tool_a",
            is_positive=True,
            expected_policy_decision="block",
        )
    ]

    with pytest.raises(ValueError, match="match ground truth record ids"):
        summarize_static_detection_metrics(
            ground_truth,
            [StaticDetectionPrediction(record_id="unknown_record", is_positive=True)],
        )

    with pytest.raises(ValueError, match="duplicate static detection prediction record id"):
        summarize_static_detection_metrics(
            ground_truth,
            [
                StaticDetectionPrediction(record_id="known_record", is_positive=True),
                StaticDetectionPrediction(record_id="known_record", is_positive=False),
            ],
        )


def test_static_detection_metrics_handle_empty_inputs() -> None:
    metrics = summarize_static_detection_metrics([], [])

    assert metrics.sample_count == 0
    assert metrics.precision == 0.0
    assert metrics.recall == 0.0
    assert metrics.f1 == 0.0
    assert metrics.false_positive_rate == 0.0
    assert metrics.false_negative_rate == 0.0
    assert metrics.severity_calibration == 0.0
    assert metrics.finding_level_accuracy == 0.0
    assert metrics.tool_level_accuracy == 0.0


def _ground_truth_from_dataset_record(
    record_id: str,
    specs_by_id: dict[str, dict[str, Any]],
    labels_by_id: dict[str, dict[str, Any]],
) -> StaticDetectionGroundTruth:
    return ground_truth_from_label_record(
        labels_by_id[record_id],
        tool_id=specs_by_id[record_id]["base_tool_id"],
    )


def _load_jsonl(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
