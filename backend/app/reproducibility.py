import json
from hashlib import sha256
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, Field, field_validator, model_validator

from app.models import EvidenceSpan


RetrievalMode = Literal["none", "lexical", "embeddings", "hybrid", "graph_hybrid"]

EXPERIMENT_CONFIG_FIELDS: tuple[str, ...] = (
    "experiment_name",
    "dataset_path",
    "detector_version",
    "policy_version",
    "retrieval_mode",
    "model_name",
    "sandbox_enabled",
    "random_seed",
    "output_path",
)

REPRODUCIBILITY_ARTIFACT_FILENAMES: tuple[str, ...] = (
    "config.yaml",
    "results.jsonl",
    "metrics_summary.json",
    "scan_manifest.json",
    "detector_versions.json",
    "policy_versions.json",
    "evidence_snapshot_hashes.json",
)


class ExperimentConfig(BaseModel):
    experiment_name: str
    dataset_path: str
    detector_version: str
    policy_version: str
    retrieval_mode: RetrievalMode
    model_name: str
    sandbox_enabled: bool
    random_seed: int = Field(ge=0)
    output_path: str

    @field_validator(
        "experiment_name",
        "dataset_path",
        "detector_version",
        "policy_version",
        "model_name",
        "output_path",
    )
    @classmethod
    def _strings_must_not_be_blank(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("experiment config strings must not be blank.")
        return value


class ReproducibilityArtifactBundle(BaseModel):
    files: dict[str, str]

    @model_validator(mode="after")
    def _files_must_match_expected_artifacts(self) -> "ReproducibilityArtifactBundle":
        if tuple(self.files) != REPRODUCIBILITY_ARTIFACT_FILENAMES:
            raise ValueError("reproducibility artifact files must match the roadmap artifact set and order.")
        if any(content and not content.endswith("\n") for content in self.files.values()):
            raise ValueError("reproducibility artifact files must end with a newline.")
        return self


def load_experiment_config_text(text: str) -> ExperimentConfig:
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as error:
        raise ValueError(f"Invalid experiment config YAML: {error}") from error

    if not isinstance(data, dict):
        raise ValueError("Experiment config YAML must contain a mapping at the document root.")
    return ExperimentConfig.model_validate(data)


def load_experiment_config_file(path: str | Path) -> ExperimentConfig:
    config_path = Path(path)
    return load_experiment_config_text(config_path.read_text(encoding="utf-8"))


def experiment_config_to_yaml(config: ExperimentConfig) -> str:
    payload = {field: getattr(config, field) for field in EXPERIMENT_CONFIG_FIELDS}
    return yaml.safe_dump(payload, sort_keys=False)


def serialize_results_jsonl(records: list[dict[str, Any] | BaseModel]) -> str:
    if not records:
        return ""
    lines = [_json_line(record) for record in records]
    return "\n".join(lines) + "\n"


def build_evidence_snapshot_hashes(evidence_spans: list[EvidenceSpan | dict[str, Any]]) -> dict[str, str]:
    hashes: dict[str, str] = {}
    for span in evidence_spans:
        payload = _evidence_hash_payload(span)
        span_id = payload["span_id"]
        if span_id in hashes:
            raise ValueError(f"duplicate evidence snapshot id: {span_id}")
        hashes[span_id] = _hash_json_payload(payload)
    return hashes


def build_scan_manifest(
    config: ExperimentConfig,
    *,
    dataset_hash: str,
    result_count: int,
    artifact_filenames: tuple[str, ...] = REPRODUCIBILITY_ARTIFACT_FILENAMES,
) -> dict[str, Any]:
    if not dataset_hash.strip():
        raise ValueError("dataset hash must not be blank.")
    if result_count < 0:
        raise ValueError("result count must be non-negative.")
    return {
        "experiment_name": config.experiment_name,
        "dataset_path": config.dataset_path,
        "dataset_hash": dataset_hash,
        "result_count": result_count,
        "artifact_filenames": list(artifact_filenames),
        "random_seed": config.random_seed,
    }


def build_reproducibility_artifacts(
    *,
    config: ExperimentConfig,
    results: list[dict[str, Any] | BaseModel],
    metrics_summary: dict[str, Any] | BaseModel,
    scan_manifest: dict[str, Any] | BaseModel,
    detector_versions: dict[str, Any] | BaseModel,
    policy_versions: dict[str, Any] | BaseModel,
    evidence_snapshot_hashes: dict[str, str],
) -> ReproducibilityArtifactBundle:
    files = {
        "config.yaml": experiment_config_to_yaml(config),
        "results.jsonl": serialize_results_jsonl(results),
        "metrics_summary.json": _json_document(metrics_summary),
        "scan_manifest.json": _json_document(scan_manifest),
        "detector_versions.json": _json_document(detector_versions),
        "policy_versions.json": _json_document(policy_versions),
        "evidence_snapshot_hashes.json": _json_document(evidence_snapshot_hashes),
    }
    return ReproducibilityArtifactBundle(files=files)


def write_reproducibility_artifacts(bundle: ReproducibilityArtifactBundle, output_dir: str | Path) -> list[Path]:
    artifact_dir = Path(output_dir)
    artifact_dir.mkdir(parents=True, exist_ok=True)
    written_paths: list[Path] = []
    for filename, content in bundle.files.items():
        path = artifact_dir / filename
        path.write_text(content, encoding="utf-8")
        written_paths.append(path)
    return written_paths


def hash_file(path: str | Path) -> str:
    return sha256(Path(path).read_bytes()).hexdigest()


def _evidence_hash_payload(span: EvidenceSpan | dict[str, Any]) -> dict[str, Any]:
    if isinstance(span, EvidenceSpan):
        return {
            "span_id": span.span_id,
            "artifact_id": span.artifact_id,
            "start_line": span.start_line,
            "end_line": span.end_line,
            "preview": span.preview,
            "span_type": span.span_type,
            "content_hash": span.content_hash,
        }
    return {
        "span_id": span["span_id"],
        "artifact_id": span["artifact_id"],
        "start_line": span["start_line"],
        "end_line": span["end_line"],
        "preview": span["preview"],
        "span_type": span["span_type"],
        "content_hash": span["content_hash"],
    }


def _json_line(record: dict[str, Any] | BaseModel) -> str:
    return json.dumps(_normalize(record), sort_keys=True, separators=(",", ":"))


def _json_document(record: dict[str, Any] | BaseModel) -> str:
    return json.dumps(_normalize(record), indent=2, sort_keys=True) + "\n"


def _hash_json_payload(payload: dict[str, Any]) -> str:
    return sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()


def _normalize(record: dict[str, Any] | BaseModel) -> dict[str, Any]:
    if isinstance(record, BaseModel):
        return record.model_dump(mode="json")
    return record
