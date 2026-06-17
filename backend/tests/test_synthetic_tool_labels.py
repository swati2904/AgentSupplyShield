import json
from pathlib import Path
from typing import Any


DATASET_DIR = Path(__file__).resolve().parents[2] / "datasets"
SPECS_PATH = DATASET_DIR / "synthetic_tool_specs.jsonl"
LABELS_PATH = DATASET_DIR / "synthetic_tool_labels.jsonl"
GUIDELINES_PATH = DATASET_DIR / "annotation_guidelines.md"

LABEL_FIELDS = {
    "has_prompt_injection",
    "has_tool_poisoning",
    "has_permission_overreach",
    "has_credential_risk",
    "has_external_exfiltration_risk",
    "has_suspicious_obfuscation",
    "expected_policy_decision",
}

BOOLEAN_LABEL_FIELDS = LABEL_FIELDS - {"expected_policy_decision"}
POLICY_DECISIONS = {"allow", "warn", "quarantine", "block"}
ANNOTATION_TAGS = {
    "prompt_injection_candidate",
    "benign_instruction",
    "permission_evidence",
    "credential_reference",
    "external_domain",
    "obfuscation",
    "policy_violation",
}

POISON_VARIANTS = {
    "tool_description_injection",
    "parameter_description_injection",
    "readme_injection",
    "tool_output_injection",
    "hidden_html_comment_injection",
    "obfuscated_unicode_injection",
}


def test_ground_truth_labels_cover_every_synthetic_record_once() -> None:
    specs = _load_jsonl(SPECS_PATH)
    labels = _load_jsonl(LABELS_PATH)

    spec_ids = [record["record_id"] for record in specs]
    label_ids = [record["record_id"] for record in labels]

    assert len(labels) == len(specs) == 52
    assert label_ids == spec_ids
    assert len(label_ids) == len(set(label_ids))


def test_ground_truth_label_schema_matches_phase_11_fields() -> None:
    labels = _load_jsonl(LABELS_PATH)

    for record in labels:
        assert set(record) == {"record_id", "labels", "annotation_tags", "label_rationale"}
        assert set(record["labels"]) == LABEL_FIELDS
        assert all(isinstance(record["labels"][field], bool) for field in BOOLEAN_LABEL_FIELDS)
        assert record["labels"]["expected_policy_decision"] in POLICY_DECISIONS
        assert set(record["annotation_tags"]).issubset(ANNOTATION_TAGS)
        assert record["annotation_tags"]
        assert record["label_rationale"].strip()


def test_ground_truth_labels_match_expected_variant_families() -> None:
    specs_by_id = {record["record_id"]: record for record in _load_jsonl(SPECS_PATH)}
    labels_by_id = {record["record_id"]: record for record in _load_jsonl(LABELS_PATH)}

    for record_id, spec in specs_by_id.items():
        label_record = labels_by_id[record_id]
        labels = label_record["labels"]
        tags = set(label_record["annotation_tags"])
        variant = spec["variant_type"]

        if variant == "clean" or variant.endswith("_v1"):
            assert labels == {
                "has_prompt_injection": False,
                "has_tool_poisoning": False,
                "has_permission_overreach": False,
                "has_credential_risk": False,
                "has_external_exfiltration_risk": False,
                "has_suspicious_obfuscation": False,
                "expected_policy_decision": "allow",
            }
            assert tags == {"benign_instruction"}

        if variant in POISON_VARIANTS:
            assert labels["has_prompt_injection"] is True
            assert labels["has_tool_poisoning"] is True
            assert labels["expected_policy_decision"] == "block"
            assert "prompt_injection_candidate" in tags
            assert "policy_violation" in tags

        if variant.startswith("permission_overreach_"):
            assert labels["has_permission_overreach"] is True
            assert labels["expected_policy_decision"] in {"quarantine", "block"}
            assert "permission_evidence" in tags
            assert "policy_violation" in tags

        if variant.endswith("_v2"):
            assert labels["has_tool_poisoning"] is True
            assert labels["expected_policy_decision"] in {"quarantine", "block"}
            assert "policy_violation" in tags


def test_ground_truth_labels_cover_specific_risk_signals() -> None:
    labels_by_id = {record["record_id"]: record for record in _load_jsonl(LABELS_PATH)}

    assert labels_by_id["poison_markdown_summarizer_readme"]["labels"]["has_external_exfiltration_risk"] is True
    assert labels_by_id["poison_calendar_reader_hidden_html_comment"]["labels"]["has_suspicious_obfuscation"] is True
    assert labels_by_id["poison_weather_fetcher_obfuscated_unicode"]["labels"]["has_suspicious_obfuscation"] is True
    assert labels_by_id["perm_overreach_weather_fetcher_api_key_dump"]["labels"]["has_credential_risk"] is True
    assert labels_by_id["perm_overreach_docs_search_email_send"]["labels"]["has_external_exfiltration_risk"] is True
    assert labels_by_id["rugpull_weather_fetcher_callback_domain_v2"]["labels"]["has_external_exfiltration_risk"] is True


def test_annotation_guidelines_define_all_labels_and_tags() -> None:
    text = GUIDELINES_PATH.read_text(encoding="utf-8")

    for field in LABEL_FIELDS:
        assert f"`{field}`" in text
    for tag in ANNOTATION_TAGS:
        assert f"`{tag}`" in text


def _load_jsonl(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
