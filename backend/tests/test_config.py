from pathlib import Path

import pytest
from pydantic import ValidationError

from app.config import (
    APP_CONFIG_FILENAME,
    CONFIG_DIR_ENV_VAR,
    CONFIG_FILENAMES,
    AppConfig,
    CrawlerConfig,
    ProjectConfig,
    SandboxConfig,
    config_hash,
    load_config_file,
    load_project_config,
)


CONFIG_ROOT = Path(__file__).resolve().parents[2] / "configs"


def test_phase_14_1_default_config_files_exist_and_load() -> None:
    assert CONFIG_FILENAMES == (
        "app_config.yaml",
        "crawler_config.yaml",
        "detector_config.yaml",
        "policy_config.yaml",
        "retrieval_config.yaml",
        "sandbox_config.yaml",
    )
    assert all((CONFIG_ROOT / filename).is_file() for filename in CONFIG_FILENAMES)

    config = load_project_config(CONFIG_ROOT)

    assert isinstance(config, ProjectConfig)
    assert config.app.service_name == "agentsupplyshield-api"
    assert config.app.environment == "local"
    assert config.crawler.mode == "text_only"
    assert config.crawler.execute_remote_code is False
    assert "prompt_injection" in config.detector.enabled_detectors
    assert config.policy.default_mode == "strict_mode"
    assert config.retrieval.retrieval_mode == "hybrid"
    assert config.retrieval.lexical_weight + config.retrieval.embedding_weight > 0
    assert config.sandbox.default_mode == "guarded"
    assert config.sandbox.mock_secrets_only is True
    assert config.sandbox.allow_network is False


def test_config_hash_is_deterministic_and_changes_with_config() -> None:
    config = load_project_config(CONFIG_ROOT)
    changed = config.model_copy(update={"app": config.app.model_copy(update={"debug": True})})

    assert len(config_hash(config)) == 64
    assert config_hash(config) == config_hash(load_project_config(CONFIG_ROOT))
    assert config_hash(config) != config_hash(changed)


def test_config_dir_can_be_selected_with_environment_variable(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    for filename in CONFIG_FILENAMES:
        source = CONFIG_ROOT / filename
        target = tmp_path / filename
        target.write_text(source.read_text(encoding="utf-8"), encoding="utf-8")

    app_config_path = tmp_path / APP_CONFIG_FILENAME
    app_config_path.write_text(
        app_config_path.read_text(encoding="utf-8").replace("environment: local", "environment: test"),
        encoding="utf-8",
    )
    monkeypatch.setenv(CONFIG_DIR_ENV_VAR, str(tmp_path))

    config = load_project_config()

    assert config.app.environment == "test"


def test_config_loader_rejects_non_mapping_documents_and_extra_fields(tmp_path: Path) -> None:
    list_config = tmp_path / "list_config.yaml"
    list_config.write_text("- not\n- a\n- mapping\n", encoding="utf-8")

    with pytest.raises(ValueError, match="mapping at the document root"):
        load_config_file(list_config, AppConfig)

    extra_field_config = tmp_path / "app_config.yaml"
    extra_field_config.write_text(
        """
service_name: agentsupplyshield-api
environment: local
debug: false
api_prefix: /api
cors_allowed_origins: []
max_upload_bytes: 1000000
default_output_dir: tmp/agentsupplyshield_outputs
unexpected: value
""".lstrip(),
        encoding="utf-8",
    )

    with pytest.raises(ValidationError):
        load_config_file(extra_field_config, AppConfig)


def test_security_boundary_config_validation_rejects_unsafe_values() -> None:
    with pytest.raises(ValidationError, match="execute remote code"):
        CrawlerConfig(
            allowed_hosts=["github.com"],
            max_selected_files=100,
            max_file_size_bytes=1000000,
            request_timeout_seconds=10,
            execute_remote_code=True,
        )

    with pytest.raises(ValidationError, match="mock secrets only"):
        SandboxConfig(max_actions_per_run=20, mock_secrets_only=False)

    with pytest.raises(ValidationError, match="network access"):
        SandboxConfig(max_actions_per_run=20, allow_network=True)
