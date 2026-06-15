from datetime import datetime, timezone
from typing import Any, Literal

from pydantic import BaseModel, Field


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


SourceType = Literal["github_repo", "url", "package", "local_upload", "mcp_manifest"]
CrawlStatus = Literal["pending", "crawled", "failed"]
ArtifactType = Literal["readme", "markdown", "json", "yaml", "package_manifest", "other"]
Severity = Literal["low", "medium", "high", "critical"]
PolicyDecision = Literal["allow", "warn", "quarantine", "block"]
ScanStatus = Literal["pending", "running", "completed", "failed"]


class Source(BaseModel):
    source_id: str
    source_type: SourceType
    source_url: str
    canonical_url: str | None = None
    owner: str | None = None
    repo_name: str | None = None
    branch_or_commit: str | None = None
    first_seen_at: datetime = Field(default_factory=utc_now)
    last_seen_at: datetime | None = None
    crawl_status: CrawlStatus = "pending"
    trust_tier: str = "unknown"


class DocumentArtifact(BaseModel):
    artifact_id: str
    source_id: str
    artifact_type: ArtifactType
    path: str
    content_hash: str
    raw_text: str | None = None
    parsed_metadata: dict[str, Any] = Field(default_factory=dict)


class Capability(BaseModel):
    capability_id: str
    name: str
    description: str | None = None
    risk_weight: int = Field(default=0, ge=0)


class Tool(BaseModel):
    tool_id: str
    source_id: str
    name: str
    description: str | None = None
    parameters: dict[str, Any] = Field(default_factory=dict)
    capability_ids: list[str] = Field(default_factory=list)


class EvidenceSpan(BaseModel):
    span_id: str
    artifact_id: str
    start_line: int = Field(ge=1)
    end_line: int = Field(ge=1)
    text: str
    span_type: str
    content_hash: str


class Finding(BaseModel):
    finding_id: str
    source_id: str
    finding_type: str
    severity: Severity
    confidence: float = Field(ge=0.0, le=1.0)
    evidence_span_ids: list[str] = Field(default_factory=list)
    rationale: str
    recommendation: str
    policy_decision: PolicyDecision | None = None


class ScanRun(BaseModel):
    run_id: str
    source_id: str
    status: ScanStatus = "pending"
    started_at: datetime = Field(default_factory=utc_now)
    completed_at: datetime | None = None
    finding_ids: list[str] = Field(default_factory=list)
    risk_score: int | None = Field(default=None, ge=0, le=100)


class ExperimentLog(BaseModel):
    experiment_id: str
    run_ids: list[str] = Field(default_factory=list)
    config: dict[str, Any] = Field(default_factory=dict)
    metrics: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=utc_now)
