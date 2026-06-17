from typing import Literal, TypeAlias

from pydantic import BaseModel, Field, field_validator

from app.evaluation_metrics import ReportingEvaluationMetrics, SandboxEvaluationMetrics
from app.static_detection_metrics import StaticDetectionMetrics


AblationVariantId: TypeAlias = Literal["A1", "A2", "A3", "A4", "A5", "A6", "A7", "A8"]

ABLATION_VARIANT_ORDER: tuple[AblationVariantId, ...] = ("A1", "A2", "A3", "A4", "A5", "A6", "A7", "A8")

ABLATION_METRIC_FIELDS: tuple[str, ...] = (
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

LOWER_IS_BETTER_METRICS: tuple[str, ...] = (
    "static_false_positive_rate",
    "static_false_negative_rate",
    "unsupported_claim_rate",
    "unsafe_action_rate",
    "attack_success_rate",
    "false_block_rate",
    "latency_overhead",
)


class AblationVariantDefinition(BaseModel):
    variant_id: AblationVariantId
    label: str
    enabled_components: tuple[str, ...]

    @field_validator("label")
    @classmethod
    def _label_must_not_be_blank(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("ablation variant label must not be blank.")
        return value

    @field_validator("enabled_components")
    @classmethod
    def _components_must_not_be_blank(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if not value or any(not component.strip() for component in value):
            raise ValueError("ablation variant components must not be blank.")
        return value


class AblationMetricSnapshot(BaseModel):
    static_precision: float | None = Field(default=None, ge=0.0, le=1.0)
    static_recall: float | None = Field(default=None, ge=0.0, le=1.0)
    static_f1: float | None = Field(default=None, ge=0.0, le=1.0)
    static_false_positive_rate: float | None = Field(default=None, ge=0.0, le=1.0)
    static_false_negative_rate: float | None = Field(default=None, ge=0.0, le=1.0)
    citation_faithfulness: float | None = Field(default=None, ge=0.0, le=1.0)
    evidence_completeness: float | None = Field(default=None, ge=0.0, le=1.0)
    unsupported_claim_rate: float | None = Field(default=None, ge=0.0, le=1.0)
    retrieval_recall_at_k: float | None = Field(default=None, ge=0.0, le=1.0)
    evidence_diversity: float | None = Field(default=None, ge=0.0, le=1.0)
    source_trust_correctness: float | None = Field(default=None, ge=0.0, le=1.0)
    unsafe_action_rate: float | None = Field(default=None, ge=0.0, le=1.0)
    attack_success_rate: float | None = Field(default=None, ge=0.0, le=1.0)
    blocked_unsafe_action_rate: float | None = Field(default=None, ge=0.0, le=1.0)
    task_success_under_guard: float | None = Field(default=None, ge=0.0, le=1.0)
    false_block_rate: float | None = Field(default=None, ge=0.0, le=1.0)
    latency_overhead: float | None = Field(default=None, ge=0.0)


class AblationVariantInput(BaseModel):
    variant_id: AblationVariantId
    metrics: AblationMetricSnapshot


class AblationVariantResult(BaseModel):
    variant_id: AblationVariantId
    label: str
    enabled_components: tuple[str, ...]
    metrics: AblationMetricSnapshot
    delta_from_baseline: dict[str, float] = Field(default_factory=dict)
    improvement_from_baseline: dict[str, float] = Field(default_factory=dict)


class AblationStudyResult(BaseModel):
    study_id: str
    baseline_variant_id: AblationVariantId
    compared_variant_count: int = Field(ge=0)
    metric_names: tuple[str, ...]
    variant_results: list[AblationVariantResult]

    @field_validator("study_id")
    @classmethod
    def _study_id_must_not_be_blank(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("ablation study id must not be blank.")
        return value


ABLATION_VARIANT_DEFINITIONS: tuple[AblationVariantDefinition, ...] = (
    AblationVariantDefinition(variant_id="A1", label="rules only", enabled_components=("rules",)),
    AblationVariantDefinition(variant_id="A2", label="rules + embeddings", enabled_components=("rules", "embeddings")),
    AblationVariantDefinition(
        variant_id="A3",
        label="rules + graph features",
        enabled_components=("rules", "graph_features"),
    ),
    AblationVariantDefinition(
        variant_id="A4",
        label="rules + graph + sandbox",
        enabled_components=("rules", "graph_features", "sandbox"),
    ),
    AblationVariantDefinition(variant_id="A5", label="unguarded agent", enabled_components=("agent", "unguarded")),
    AblationVariantDefinition(variant_id="A6", label="guarded agent", enabled_components=("agent", "guarded")),
    AblationVariantDefinition(
        variant_id="A7",
        label="guarded agent + critic",
        enabled_components=("agent", "guarded", "critic"),
    ),
    AblationVariantDefinition(
        variant_id="A8",
        label="guarded agent + strict policy",
        enabled_components=("agent", "guarded", "strict_policy"),
    ),
)

ABLATION_VARIANT_DEFINITIONS_BY_ID = {
    definition.variant_id: definition for definition in ABLATION_VARIANT_DEFINITIONS
}


def ablation_metric_snapshot_from_components(
    *,
    static_detection: StaticDetectionMetrics | None = None,
    reporting: ReportingEvaluationMetrics | None = None,
    sandbox: SandboxEvaluationMetrics | None = None,
) -> AblationMetricSnapshot:
    return AblationMetricSnapshot(
        static_precision=static_detection.precision if static_detection else None,
        static_recall=static_detection.recall if static_detection else None,
        static_f1=static_detection.f1 if static_detection else None,
        static_false_positive_rate=static_detection.false_positive_rate if static_detection else None,
        static_false_negative_rate=static_detection.false_negative_rate if static_detection else None,
        citation_faithfulness=reporting.citation_faithfulness if reporting else None,
        evidence_completeness=reporting.evidence_completeness if reporting else None,
        unsupported_claim_rate=reporting.unsupported_claim_rate if reporting else None,
        retrieval_recall_at_k=reporting.retrieval_recall_at_k if reporting else None,
        evidence_diversity=reporting.evidence_diversity if reporting else None,
        source_trust_correctness=reporting.source_trust_correctness if reporting else None,
        unsafe_action_rate=sandbox.unsafe_action_rate if sandbox else None,
        attack_success_rate=sandbox.attack_success_rate if sandbox else None,
        blocked_unsafe_action_rate=sandbox.blocked_unsafe_action_rate if sandbox else None,
        task_success_under_guard=sandbox.task_success_under_guard if sandbox else None,
        false_block_rate=sandbox.false_block_rate if sandbox else None,
        latency_overhead=sandbox.latency_overhead if sandbox else None,
    )


def run_ablation_study(
    *,
    study_id: str,
    variants: list[AblationVariantInput],
    baseline_variant_id: AblationVariantId = "A1",
) -> AblationStudyResult:
    variants_by_id = _index_variants_by_id(variants)
    if baseline_variant_id not in variants_by_id:
        raise ValueError("ablation baseline variant must be included in the study inputs.")

    baseline_metrics = variants_by_id[baseline_variant_id].metrics
    variant_results = [
        _build_variant_result(variant_input, baseline_metrics)
        for variant_input in sorted(variants, key=lambda item: ABLATION_VARIANT_ORDER.index(item.variant_id))
    ]

    return AblationStudyResult(
        study_id=study_id,
        baseline_variant_id=baseline_variant_id,
        compared_variant_count=len(variant_results),
        metric_names=_present_metric_names(variant_results),
        variant_results=variant_results,
    )


def _index_variants_by_id(variants: list[AblationVariantInput]) -> dict[AblationVariantId, AblationVariantInput]:
    indexed: dict[AblationVariantId, AblationVariantInput] = {}
    for variant in variants:
        if variant.variant_id in indexed:
            raise ValueError(f"duplicate ablation variant id: {variant.variant_id}")
        indexed[variant.variant_id] = variant
    return indexed


def _build_variant_result(
    variant_input: AblationVariantInput,
    baseline_metrics: AblationMetricSnapshot,
) -> AblationVariantResult:
    definition = ABLATION_VARIANT_DEFINITIONS_BY_ID[variant_input.variant_id]
    delta_from_baseline = _metric_delta(variant_input.metrics, baseline_metrics)
    return AblationVariantResult(
        variant_id=variant_input.variant_id,
        label=definition.label,
        enabled_components=definition.enabled_components,
        metrics=variant_input.metrics,
        delta_from_baseline=delta_from_baseline,
        improvement_from_baseline=_metric_improvements(delta_from_baseline),
    )


def _metric_delta(
    metrics: AblationMetricSnapshot,
    baseline_metrics: AblationMetricSnapshot,
) -> dict[str, float]:
    delta: dict[str, float] = {}
    metric_values = metrics.model_dump()
    baseline_values = baseline_metrics.model_dump()
    for field_name in ABLATION_METRIC_FIELDS:
        metric_value = metric_values[field_name]
        baseline_value = baseline_values[field_name]
        if metric_value is not None and baseline_value is not None:
            delta[field_name] = metric_value - baseline_value
    return delta


def _metric_improvements(delta_from_baseline: dict[str, float]) -> dict[str, float]:
    return {
        field_name: -delta if field_name in LOWER_IS_BETTER_METRICS else delta
        for field_name, delta in delta_from_baseline.items()
    }


def _present_metric_names(variant_results: list[AblationVariantResult]) -> tuple[str, ...]:
    present_metrics: list[str] = []
    for field_name in ABLATION_METRIC_FIELDS:
        if any(getattr(result.metrics, field_name) is not None for result in variant_results):
            present_metrics.append(field_name)
    return tuple(present_metrics)
