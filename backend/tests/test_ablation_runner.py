import pytest
from pydantic import ValidationError

from app.ablation_runner import (
    ABLATION_METRIC_FIELDS,
    ABLATION_VARIANT_DEFINITIONS,
    ABLATION_VARIANT_ORDER,
    AblationMetricSnapshot,
    AblationVariantInput,
    ablation_metric_snapshot_from_components,
    run_ablation_study,
)
from app.evaluation_metrics import ReportingEvaluationMetrics, SandboxEvaluationMetrics
from app.static_detection_metrics import StaticDetectionMetrics


def test_ablation_variant_definitions_match_phase_11_7() -> None:
    assert ABLATION_VARIANT_ORDER == ("A1", "A2", "A3", "A4", "A5", "A6", "A7", "A8")
    assert [(definition.variant_id, definition.label) for definition in ABLATION_VARIANT_DEFINITIONS] == [
        ("A1", "rules only"),
        ("A2", "rules + embeddings"),
        ("A3", "rules + graph features"),
        ("A4", "rules + graph + sandbox"),
        ("A5", "unguarded agent"),
        ("A6", "guarded agent"),
        ("A7", "guarded agent + critic"),
        ("A8", "guarded agent + strict policy"),
    ]
    assert ABLATION_VARIANT_DEFINITIONS[0].enabled_components == ("rules",)
    assert ABLATION_VARIANT_DEFINITIONS[-1].enabled_components == ("agent", "guarded", "strict_policy")


def test_ablation_metric_fields_include_static_reporting_and_sandbox_metrics() -> None:
    assert ABLATION_METRIC_FIELDS == (
        "static_precision",
        "static_recall",
        "static_f1",
        "static_false_positive_rate",
        "static_false_negative_rate",
        "citation_faithfulness",
        "evidence_completeness",
        "unsupported_claim_rate",
        "retrieval_recall_at_k",
        "evidence_diversity",
        "source_trust_correctness",
        "unsafe_action_rate",
        "attack_success_rate",
        "blocked_unsafe_action_rate",
        "task_success_under_guard",
        "false_block_rate",
        "latency_overhead",
    )
    assert tuple(AblationMetricSnapshot.model_fields) == ABLATION_METRIC_FIELDS


def test_ablation_metric_snapshot_from_components_flattens_existing_metrics() -> None:
    static_metrics = StaticDetectionMetrics(
        sample_count=10,
        positive_count=6,
        negative_count=4,
        true_positive_count=5,
        false_positive_count=1,
        true_negative_count=3,
        false_negative_count=1,
        precision=0.83,
        recall=0.75,
        f1=0.79,
        false_positive_rate=0.25,
        false_negative_rate=0.17,
        severity_calibration=0.8,
        finding_level_accuracy=0.8,
        tool_level_accuracy=0.7,
    )
    reporting_metrics = ReportingEvaluationMetrics(
        sample_count=4,
        citation_faithfulness=0.9,
        evidence_completeness=0.75,
        unsupported_claim_rate=0.1,
        retrieval_recall_at_k=0.8,
        evidence_diversity=0.6,
        source_trust_correctness=0.5,
    )
    sandbox_metrics = SandboxEvaluationMetrics(
        run_count=5,
        attack_run_count=2,
        guarded_run_count=3,
        unsafe_action_run_count=2,
        unsafe_action_attempt_count=2,
        blocked_unsafe_action_count=1,
        false_block_count=1,
        unsafe_action_rate=0.4,
        attack_success_rate=0.5,
        blocked_unsafe_action_rate=0.5,
        task_success_under_guard=0.5,
        false_block_rate=0.33,
        latency_overhead=1.25,
    )

    snapshot = ablation_metric_snapshot_from_components(
        static_detection=static_metrics,
        reporting=reporting_metrics,
        sandbox=sandbox_metrics,
    )

    assert snapshot.static_precision == 0.83
    assert snapshot.static_recall == 0.75
    assert snapshot.static_f1 == 0.79
    assert snapshot.unsupported_claim_rate == 0.1
    assert snapshot.retrieval_recall_at_k == 0.8
    assert snapshot.unsafe_action_rate == 0.4
    assert snapshot.blocked_unsafe_action_rate == 0.5
    assert snapshot.latency_overhead == 1.25


def test_run_ablation_study_orders_variants_and_computes_improvements() -> None:
    baseline = AblationVariantInput(
        variant_id="A1",
        metrics=AblationMetricSnapshot(
            static_f1=0.55,
            static_false_positive_rate=0.2,
            unsupported_claim_rate=0.3,
        ),
    )
    embeddings = AblationVariantInput(
        variant_id="A2",
        metrics=AblationMetricSnapshot(
            static_f1=0.7,
            static_false_positive_rate=0.12,
            unsupported_claim_rate=0.25,
        ),
    )
    graph_sandbox = AblationVariantInput(
        variant_id="A4",
        metrics=AblationMetricSnapshot(
            static_f1=0.74,
            static_false_positive_rate=0.1,
            unsupported_claim_rate=0.2,
            unsafe_action_rate=0.3,
        ),
    )

    result = run_ablation_study(study_id="phase_11_7_ablation", variants=[graph_sandbox, embeddings, baseline])

    assert result.study_id == "phase_11_7_ablation"
    assert result.baseline_variant_id == "A1"
    assert result.compared_variant_count == 3
    assert [variant.variant_id for variant in result.variant_results] == ["A1", "A2", "A4"]
    assert result.metric_names == (
        "static_f1",
        "static_false_positive_rate",
        "unsupported_claim_rate",
        "unsafe_action_rate",
    )

    baseline_result, embeddings_result, graph_sandbox_result = result.variant_results
    assert baseline_result.delta_from_baseline["static_f1"] == 0.0
    assert embeddings_result.delta_from_baseline["static_f1"] == pytest.approx(0.15)
    assert embeddings_result.improvement_from_baseline["static_f1"] == pytest.approx(0.15)
    assert embeddings_result.delta_from_baseline["static_false_positive_rate"] == pytest.approx(-0.08)
    assert embeddings_result.improvement_from_baseline["static_false_positive_rate"] == pytest.approx(0.08)
    assert graph_sandbox_result.improvement_from_baseline["unsupported_claim_rate"] == pytest.approx(0.1)
    assert "unsafe_action_rate" not in graph_sandbox_result.delta_from_baseline


def test_run_ablation_study_supports_all_phase_11_7_variants() -> None:
    variants = [
        AblationVariantInput(
            variant_id=variant_id,
            metrics=AblationMetricSnapshot(static_f1=0.5 + index * 0.01),
        )
        for index, variant_id in enumerate(ABLATION_VARIANT_ORDER)
    ]

    result = run_ablation_study(study_id="all_variants", variants=list(reversed(variants)))

    assert result.compared_variant_count == 8
    assert [variant.variant_id for variant in result.variant_results] == list(ABLATION_VARIANT_ORDER)
    assert result.variant_results[-1].label == "guarded agent + strict policy"


def test_run_ablation_study_validates_inputs() -> None:
    with pytest.raises(ValidationError):
        AblationVariantInput(variant_id="A9", metrics=AblationMetricSnapshot())

    with pytest.raises(ValueError, match="duplicate ablation variant id"):
        run_ablation_study(
            study_id="duplicate_variant",
            variants=[
                AblationVariantInput(variant_id="A1", metrics=AblationMetricSnapshot(static_f1=0.5)),
                AblationVariantInput(variant_id="A1", metrics=AblationMetricSnapshot(static_f1=0.6)),
            ],
        )

    with pytest.raises(ValueError, match="baseline variant must be included"):
        run_ablation_study(
            study_id="missing_baseline",
            variants=[AblationVariantInput(variant_id="A2", metrics=AblationMetricSnapshot(static_f1=0.6))],
        )
