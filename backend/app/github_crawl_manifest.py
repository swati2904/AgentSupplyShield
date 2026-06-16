import json
from collections import Counter
from datetime import datetime
from hashlib import sha256
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field

from app.github_file_discovery import GitHubFileDiscoveryResult, RelevantGitHubFile, SkippedGitHubPath
from app.github_file_fetcher import FetchedGitHubTextFile, GitHubFileFetchResult, SkippedGitHubFetch
from app.github_url import GitHubRepositoryURL
from app.models import utc_now


GITHUB_CRAWL_MANIFEST_VERSION = "github-text-crawl-manifest/v0.1"


class GitHubCrawlSelectedFile(BaseModel):
    path: str
    artifact_type: str
    selection_reason: str
    priority: int = Field(ge=0)
    expected_size_bytes: int | None = Field(default=None, ge=0)


class GitHubCrawlFetchedFile(BaseModel):
    path: str
    raw_url: str
    artifact_type: str
    selection_reason: str
    size_bytes: int = Field(ge=0)
    content_hash: str
    content_type: str | None = None
    encoding: str = "utf-8"


class GitHubCrawlSkippedPath(BaseModel):
    path: str
    stage: Literal["discovery", "fetch"]
    reason: str


class GitHubCrawlSummary(BaseModel):
    selected_file_count: int = Field(ge=0)
    fetched_file_count: int = Field(ge=0)
    skipped_path_count: int = Field(ge=0)
    total_fetched_bytes: int = Field(ge=0)
    fetched_artifact_type_counts: dict[str, int] = Field(default_factory=dict)


class GitHubCrawlManifest(BaseModel):
    manifest_version: str = GITHUB_CRAWL_MANIFEST_VERSION
    source_type: Literal["github_repo"] = "github_repo"
    source_url: str
    canonical_url: str
    owner: str
    repo_name: str
    ref: str
    generated_at: datetime = Field(default_factory=utc_now)
    summary: GitHubCrawlSummary
    selected_files: list[GitHubCrawlSelectedFile] = Field(default_factory=list)
    fetched_files: list[GitHubCrawlFetchedFile] = Field(default_factory=list)
    skipped_paths: list[GitHubCrawlSkippedPath] = Field(default_factory=list)
    manifest_hash: str


def build_github_crawl_manifest(
    repo: GitHubRepositoryURL,
    *,
    ref: str,
    discovery_result: GitHubFileDiscoveryResult,
    fetch_result: GitHubFileFetchResult,
    generated_at: datetime | None = None,
) -> GitHubCrawlManifest:
    selected_files = [_selected_file(file) for file in discovery_result.selected_files]
    fetched_files = [_fetched_file(file) for file in fetch_result.fetched_files]
    skipped_paths = [
        *[_skipped_discovery_path(path) for path in discovery_result.skipped_paths],
        *[_skipped_fetch_path(path) for path in fetch_result.skipped_files],
    ]
    summary = GitHubCrawlSummary(
        selected_file_count=len(selected_files),
        fetched_file_count=len(fetched_files),
        skipped_path_count=len(skipped_paths),
        total_fetched_bytes=sum(file.size_bytes for file in fetched_files),
        fetched_artifact_type_counts=dict(sorted(Counter(file.artifact_type for file in fetched_files).items())),
    )
    manifest = GitHubCrawlManifest(
        source_url=repo.raw_url,
        canonical_url=repo.canonical_url,
        owner=repo.owner,
        repo_name=repo.repo_name,
        ref=ref,
        generated_at=generated_at or utc_now(),
        summary=summary,
        selected_files=selected_files,
        fetched_files=fetched_files,
        skipped_paths=skipped_paths,
        manifest_hash="",
    )
    return manifest.model_copy(update={"manifest_hash": _hash_manifest(manifest)})


def crawl_manifest_to_json(manifest: GitHubCrawlManifest) -> str:
    return json.dumps(manifest.model_dump(mode="json"), indent=2, sort_keys=True) + "\n"


def write_github_crawl_manifest(manifest: GitHubCrawlManifest, path: str | Path) -> Path:
    output_path = Path(path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(crawl_manifest_to_json(manifest), encoding="utf-8")
    return output_path


def _selected_file(file: RelevantGitHubFile) -> GitHubCrawlSelectedFile:
    return GitHubCrawlSelectedFile(
        path=file.path,
        artifact_type=file.artifact_type,
        selection_reason=file.selection_reason,
        priority=file.priority,
        expected_size_bytes=file.size_bytes,
    )


def _fetched_file(file: FetchedGitHubTextFile) -> GitHubCrawlFetchedFile:
    return GitHubCrawlFetchedFile(
        path=file.path,
        raw_url=file.raw_url,
        artifact_type=file.artifact_type,
        selection_reason=file.selection_reason,
        size_bytes=file.size_bytes,
        content_hash=file.content_hash,
        content_type=file.content_type,
        encoding=file.encoding,
    )


def _skipped_discovery_path(path: SkippedGitHubPath) -> GitHubCrawlSkippedPath:
    return GitHubCrawlSkippedPath(path=path.path, stage="discovery", reason=path.reason)


def _skipped_fetch_path(path: SkippedGitHubFetch) -> GitHubCrawlSkippedPath:
    return GitHubCrawlSkippedPath(path=path.path, stage="fetch", reason=path.reason)


def _hash_manifest(manifest: GitHubCrawlManifest) -> str:
    payload = manifest.model_dump(mode="json", exclude={"manifest_hash"})
    serialized = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return sha256(serialized.encode("utf-8")).hexdigest()
