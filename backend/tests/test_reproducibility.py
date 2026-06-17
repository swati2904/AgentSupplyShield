import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from app.models import EvidenceSpan
from app.reproducibility import (
    EXPERIMENT_CONFIG_FIELDS,
    REPRODUCIBILITY_ARTIFACT_FILENAMES,
    ExperimentConfig,
    build_evidence_snapshot_hashes,
    build_reproducibility_artifacts,
    build_scan_manifest,
    experiment_config_to_yaml,
    hash_file,
    load_experiment_config_file,
    load_experiment_config_text,
    serialize_results_jsonl,
    write_reproducibility_artifacts,
)


CONFIG_PATH = Path(__file__).resolve().parents[2] / "experiments" / "configs" / "milestone8_evaluation.yaml"
DATASET_PATH = Path(__file__).resolve().parents[2] / "datasets" / "synthetic_tool_specs.jsonl"


def test_experiment_config_fields_match_phase_11_8() -> None:
    assert EXPERIMENT_CONFIG_FIELDS == (
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
    assert tuple(ExperimentConfig.model_fields) == EXPERIMENT_CONFIG_FIELDS


def test_reproducibility_artifact_filenames_match_phase_11_9() -> None:
    assert REPRODUCIBILITY_ARTIFACT_FILENAMES == (
        "config.yaml",
        "results.jsonl",
        "metrics_summary.json",
        "scan_manifest.json",
        "detector_versions.json",
        "policy_versions.json",
        "evidence_snapshot_hashes.json",
    )


def test_sample_milestone8_config_loads_and_round_trips() -> None:
    config = load_experiment_config_file(CONFIG_PATH)
    serialized = experiment_config_to_yaml(config)
    reloaded = load_experiment_config_text(serialized)

    assert config.experiment_name == "milestone8_synthetic_evaluation"
    assert config.dataset_path == "datasets/synthetic_tool_specs.jsonl"
    assert config.detector_version == "static-detectors/v0.1"
    assert config.policy_version == "default-policy/v0.1"
    assert config.retrieval_mode == "hybrid"
    assert config.model_name == "local-hash-embedding-v1"
    assert config.sandbox_enabled is True
    assert config.random_seed == 20260617
    assert config.output_path == "experiments/runs/milestone8_synthetic_evaluation"
    assert reloaded == config


def test_results_jsonl_and_evidence_snapshot_hashes_are_deterministic() -> None:
    jsonl = serialize_results_jsonl(
        [
            {"record_id": "sample_1", "policy_decision": "allow", "risk_score": 0},
            {"risk_score": 90, "record_id": "sample_2", "policy_decision": "block"},
        ]
    )
    evidence_span = EvidenceSpan(
        span_id="span_1",
        artifact_id="artifact_readme",
        start_line=2,
        end_line=2,
        preview="Ignore previous instructions.",
        span_type="prompt_injection",
        content_hash="abc123",
    )
    hashes = build_evidence_snapshot_hashes([evidence_span])
    changed_hashes = build_evidence_snapshot_hashes(
        [evidence_span.model_copy(update={"preview": "Different evidence preview."})]
    )

    assert jsonl.splitlines() == [
        '{"policy_decision":"allow","record_id":"sample_1","risk_score":0}',
        '{"policy_decision":"block","record_id":"sample_2","risk_score":90}',
    ]
    assert set(hashes) == {"span_1"}
    assert len(hashes["span_1"]) == 64
    assert hashes["span_1"] != changed_hashes["span_1"]


def test_build_reproducibility_artifacts_and_write_files(tmp_path: Path) -> None:
    config = load_experiment_config_file(CONFIG_PATH)
    result_records = [{"run_id": "run_1", "policy_decision": "block"}]
    metrics_summary = {"static_f1": 0.8, "unsafe_action_rate": 0.2}
    scan_manifest = build_scan_manifest(
        config,
        dataset_hash=hash_file(DATASET_PATH),
        result_count=len(result_records),
    )
    detector_versions = {"detector_version": config.detector_version, "components": {"rules": "v0.1"}}
    policy_versions = {"policy_version": config.policy_version, "policy_pack": "default"}
    evidence_hashes = {"span_1": "a" * 64}

    bundle = build_reproducibility_artifacts(
        config=config,
        results=result_records,
        metrics_summary=metrics_summary,
        scan_manifest=scan_manifest,
        detector_versions=detector_versions,
        policy_versions=policy_versions,
        evidence_snapshot_hashes=evidence_hashes,
    )
    written_paths = write_reproducibility_artifacts(bundle, tmp_path)

    assert tuple(bundle.files) == REPRODUCIBILITY_ARTIFACT_FILENAMES
    assert [path.name for path in written_paths] == list(REPRODUCIBILITY_ARTIFACT_FILENAMES)
    assert load_experiment_config_text((tmp_path / "config.yaml").read_text(encoding="utf-8")) == config
    assert (tmp_path / "results.jsonl").read_text(encoding="utf-8") == (
        '{"policy_decision":"block","run_id":"run_1"}\n'
    )
    assert json.loads((tmp_path / "metrics_summary.json").read_text(encoding="utf-8")) == metrics_summary
    assert json.loads((tmp_path / "scan_manifest.json").read_text(encoding="utf-8"))["artifact_filenames"] == list(
        REPRODUCIBILITY_ARTIFACT_FILENAMES
    )
    assert json.loads((tmp_path / "evidence_snapshot_hashes.json").read_text(encoding="utf-8")) == evidence_hashes


def test_reproducibility_validation_rejects_invalid_inputs() -> None:
    with pytest.raises(ValueError, match="mapping at the document root"):
        load_experiment_config_text("- not\n- a\n- mapping\n")

    with pytest.raises(ValidationError):
        ExperimentConfig(
            experiment_name="bad_config",
            dataset_path="datasets/synthetic_tool_specs.jsonl",
            detector_version="static-detectors/v0.1",
            policy_version="default-policy/v0.1",
            retrieval_mode="invalid",
            model_name="local-hash-embedding-v1",
            sandbox_enabled=True,
            random_seed=1,
            output_path="experiments/runs/bad_config",
        )

    evidence_span = EvidenceSpan(
        span_id="duplicate_span",
        artifact_id="artifact_readme",
        start_line=1,
        end_line=1,
        preview="Evidence.",
        span_type="prompt_injection",
        content_hash="abc123",
    )
    with pytest.raises(ValueError, match="duplicate evidence snapshot id"):
        build_evidence_snapshot_hashes([evidence_span, evidence_span])

    config = load_experiment_config_file(CONFIG_PATH)
    with pytest.raises(ValueError, match="dataset hash must not be blank"):
        build_scan_manifest(config, dataset_hash=" ", result_count=1)
