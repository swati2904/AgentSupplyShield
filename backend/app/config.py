import json
import os
from hashlib import sha256
from pathlib import Path
from typing import Literal, TypeAlias, TypeVar

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


CONFIG_DIR_ENV_VAR = "AGENTSUPPLYSHIELD_CONFIG_DIR"
DEFAULT_CONFIG_DIR = Path(__file__).resolve().parents[2] / "configs"

APP_CONFIG_FILENAME = "app_config.yaml"
CRAWLER_CONFIG_FILENAME = "crawler_config.yaml"
DETECTOR_CONFIG_FILENAME = "detector_config.yaml"
POLICY_CONFIG_FILENAME = "policy_config.yaml"
RETRIEVAL_CONFIG_FILENAME = "retrieval_config.yaml"
SANDBOX_CONFIG_FILENAME = "sandbox_config.yaml"

CONFIG_FILENAMES: tuple[str, ...] = (
    APP_CONFIG_FILENAME,
    CRAWLER_CONFIG_FILENAME,
    DETECTOR_CONFIG_FILENAME,
    POLICY_CONFIG_FILENAME,
    RETRIEVAL_CONFIG_FILENAME,
    SANDBOX_CONFIG_FILENAME,
)

EnvironmentName: TypeAlias = Literal["local", "test", "staging", "production"]
CrawlerMode: TypeAlias = Literal["text_only"]
DetectorName: TypeAlias = Literal["prompt_injection", "credential_reference", "permission_signal"]
PolicyModeName: TypeAlias = Literal[
    "research_mode",
    "warn_mode",
    "strict_mode",
    "enterprise_mode",
    "benchmark_mode",
]
PolicyActionName: TypeAlias = Literal["allow", "warn", "quarantine", "block", "human_approval", "sandbox_only"]
RetrievalMode: TypeAlias = Literal["lexical", "embeddings", "hybrid", "graph_hybrid"]
SandboxModeName: TypeAlias = Literal["baseline", "guarded"]

ConfigModel = TypeVar("ConfigModel", bound=BaseModel)


class StrictConfigModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class AppConfig(StrictConfigModel):
    service_name: str
    environment: EnvironmentName = "local"
    debug: bool = False
    api_prefix: str = "/api"
    cors_allowed_origins: list[str] = Field(default_factory=list)
    max_upload_bytes: int = Field(gt=0)
    default_output_dir: str

    @field_validator("service_name", "api_prefix", "default_output_dir")
    @classmethod
    def _strings_must_not_be_blank(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("app config strings must not be blank.")
        return value

    @field_validator("api_prefix")
    @classmethod
    def _api_prefix_must_start_with_slash(cls, value: str) -> str:
        if not value.startswith("/"):
            raise ValueError("api_prefix must start with '/'.")
        return value

    @field_validator("cors_allowed_origins")
    @classmethod
    def _cors_origins_must_not_be_blank(cls, value: list[str]) -> list[str]:
        _validate_non_blank_list(value, "cors_allowed_origins")
        return value


class CrawlerConfig(StrictConfigModel):
    mode: CrawlerMode = "text_only"
    allowed_hosts: list[str]
    default_ref: str = "main"
    max_selected_files: int = Field(gt=0)
    max_file_size_bytes: int = Field(gt=0)
    request_timeout_seconds: float = Field(gt=0)
    follow_redirects: bool = False
    execute_remote_code: bool = False

    @field_validator("allowed_hosts")
    @classmethod
    def _allowed_hosts_must_be_hostnames(cls, value: list[str]) -> list[str]:
        _validate_non_blank_list(value, "allowed_hosts")
        for host in value:
            if "://" in host or "/" in host:
                raise ValueError("allowed_hosts must contain hostnames, not URLs.")
        return value

    @field_validator("default_ref")
    @classmethod
    def _default_ref_must_not_be_blank(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("default_ref must not be blank.")
        return value

    @model_validator(mode="after")
    def _crawler_must_stay_text_only(self) -> "CrawlerConfig":
        if self.execute_remote_code:
            raise ValueError("crawler config must not execute remote code.")
        return self


class DetectorConfig(StrictConfigModel):
    detector_version: str
    enabled_detectors: list[DetectorName]
    min_confidence: float = Field(ge=0.0, le=1.0)
    evidence_preview_chars: int = Field(gt=0)
    suspicious_formatting_enabled: bool = True

    @field_validator("detector_version")
    @classmethod
    def _detector_version_must_not_be_blank(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("detector_version must not be blank.")
        return value

    @field_validator("enabled_detectors")
    @classmethod
    def _enabled_detectors_must_not_be_empty(cls, value: list[DetectorName]) -> list[DetectorName]:
        if not value:
            raise ValueError("enabled_detectors must not be empty.")
        return value


class PolicyConfig(StrictConfigModel):
    policy_version: str
    default_mode: PolicyModeName = "strict_mode"
    policy_pack_name: str
    require_evidence: bool = True
    audit_decisions: bool = True
    allowed_actions: list[PolicyActionName]

    @field_validator("policy_version", "policy_pack_name")
    @classmethod
    def _policy_strings_must_not_be_blank(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("policy config strings must not be blank.")
        return value

    @field_validator("allowed_actions")
    @classmethod
    def _allowed_actions_must_not_be_empty(cls, value: list[PolicyActionName]) -> list[PolicyActionName]:
        if not value:
            raise ValueError("allowed_actions must not be empty.")
        return value


class RetrievalConfig(StrictConfigModel):
    retrieval_mode: RetrievalMode = "hybrid"
    max_results: int = Field(gt=0)
    lexical_weight: float = Field(ge=0.0)
    embedding_weight: float = Field(ge=0.0)
    snippet_chars: int = Field(gt=0)
    embedding_provider: str
    embedding_model_name: str
    embedding_dimensions: int = Field(gt=0)

    @field_validator("embedding_provider", "embedding_model_name")
    @classmethod
    def _retrieval_strings_must_not_be_blank(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("retrieval config strings must not be blank.")
        return value

    @model_validator(mode="after")
    def _retrieval_weights_must_be_enabled(self) -> "RetrievalConfig":
        if self.lexical_weight + self.embedding_weight <= 0:
            raise ValueError("at least one retrieval weight must be greater than 0.")
        return self


class SandboxConfig(StrictConfigModel):
    enabled: bool = True
    default_mode: SandboxModeName = "guarded"
    mock_secrets_only: bool = True
    allow_network: bool = False
    allow_filesystem_write: bool = False
    record_trace: bool = True
    max_actions_per_run: int = Field(gt=0)

    @model_validator(mode="after")
    def _sandbox_must_stay_mocked_and_offline(self) -> "SandboxConfig":
        if not self.mock_secrets_only:
            raise ValueError("sandbox config must use mock secrets only.")
        if self.allow_network:
            raise ValueError("sandbox config must not allow network access.")
        if self.allow_filesystem_write:
            raise ValueError("sandbox config must not allow filesystem writes.")
        return self


class ProjectConfig(StrictConfigModel):
    app: AppConfig
    crawler: CrawlerConfig
    detector: DetectorConfig
    policy: PolicyConfig
    retrieval: RetrievalConfig
    sandbox: SandboxConfig


def resolve_config_dir(config_dir: str | Path | None = None) -> Path:
    if config_dir is not None:
        return Path(config_dir)
    configured_dir = os.environ.get(CONFIG_DIR_ENV_VAR)
    if configured_dir:
        return Path(configured_dir)
    return DEFAULT_CONFIG_DIR


def load_config_file(path: str | Path, model_type: type[ConfigModel]) -> ConfigModel:
    config_path = Path(path)
    try:
        data = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    except yaml.YAMLError as error:
        raise ValueError(f"Invalid config YAML in {config_path}: {error}") from error

    if not isinstance(data, dict):
        raise ValueError(f"Config file must contain a mapping at the document root: {config_path}")
    return model_type.model_validate(data)


def load_project_config(config_dir: str | Path | None = None) -> ProjectConfig:
    root = resolve_config_dir(config_dir)
    return ProjectConfig(
        app=load_config_file(root / APP_CONFIG_FILENAME, AppConfig),
        crawler=load_config_file(root / CRAWLER_CONFIG_FILENAME, CrawlerConfig),
        detector=load_config_file(root / DETECTOR_CONFIG_FILENAME, DetectorConfig),
        policy=load_config_file(root / POLICY_CONFIG_FILENAME, PolicyConfig),
        retrieval=load_config_file(root / RETRIEVAL_CONFIG_FILENAME, RetrievalConfig),
        sandbox=load_config_file(root / SANDBOX_CONFIG_FILENAME, SandboxConfig),
    )


def config_hash(config: BaseModel) -> str:
    payload = config.model_dump(mode="json")
    serialized = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return sha256(serialized.encode("utf-8")).hexdigest()


def _validate_non_blank_list(value: list[str], field_name: str) -> None:
    if not value or any(not item.strip() for item in value):
        raise ValueError(f"{field_name} must contain non-blank values.")
