import json
from collections import Counter
from hashlib import sha256
from typing import Literal
from urllib.parse import unquote, urlparse

from pydantic import BaseModel, Field

from app.github_crawl_manifest import GitHubCrawlManifest


DEFAULT_MAX_FETCH_SKIP_RATIO = 0.5
_HASH_HEX_LENGTH = 64
_RAW_GITHUB_HOST = "raw.githubusercontent.com"


QualitySeverity = Literal["warning", "error"]
QualityStatus = Literal["pass", "warn", "fail"]


class GitHubCrawlQualityIssue(BaseModel):
    code: str
    severity: QualitySeverity
    message: str
    path: str | None = None


class GitHubCrawlQualityReport(BaseModel):
    status: QualityStatus
    error_count: int = Field(ge=0)
    warning_count: int = Field(ge=0)
    issues: list[GitHubCrawlQualityIssue] = Field(default_factory=list)


def assess_github_crawl_quality(
    manifest: GitHubCrawlManifest,
    *,
    min_fetched_files: int = 1,
    max_fetch_skip_ratio: float = DEFAULT_MAX_FETCH_SKIP_RATIO,
    require_readme: bool = True,
) -> GitHubCrawlQualityReport:
    issues: list[GitHubCrawlQualityIssue] = []
    _check_manifest_hash(manifest, issues)
    _check_summary_consistency(manifest, issues)
    _check_unique_paths(manifest, issues)
    _check_fetched_files_were_selected(manifest, issues)
    _check_fetched_file_metadata(manifest, issues)
    _check_fetch_volume(manifest, min_fetched_files=min_fetched_files, issues=issues)
    _check_fetch_skip_ratio(manifest, max_fetch_skip_ratio=max_fetch_skip_ratio, issues=issues)
    if require_readme:
        _check_readme_fetched(manifest, issues)

    error_count = sum(1 for issue in issues if issue.severity == "error")
    warning_count = sum(1 for issue in issues if issue.severity == "warning")
    status: QualityStatus = "fail" if error_count else "warn" if warning_count else "pass"
    return GitHubCrawlQualityReport(
        status=status,
        error_count=error_count,
        warning_count=warning_count,
        issues=issues,
    )


def _check_manifest_hash(manifest: GitHubCrawlManifest, issues: list[GitHubCrawlQualityIssue]) -> None:
    expected_hash = _hash_manifest(manifest)
    if manifest.manifest_hash != expected_hash:
        issues.append(
            GitHubCrawlQualityIssue(
                code="manifest_hash_mismatch",
                severity="error",
                message="Manifest hash does not match manifest contents.",
            )
        )


def _check_summary_consistency(manifest: GitHubCrawlManifest, issues: list[GitHubCrawlQualityIssue]) -> None:
    if manifest.summary.selected_file_count != len(manifest.selected_files):
        issues.append(_summary_error("selected_file_count", "selected file list length"))
    if manifest.summary.fetched_file_count != len(manifest.fetched_files):
        issues.append(_summary_error("fetched_file_count", "fetched file list length"))
    if manifest.summary.skipped_path_count != len(manifest.skipped_paths):
        issues.append(_summary_error("skipped_path_count", "skipped path list length"))

    total_fetched_bytes = sum(file.size_bytes for file in manifest.fetched_files)
    if manifest.summary.total_fetched_bytes != total_fetched_bytes:
        issues.append(_summary_error("total_fetched_bytes", "sum of fetched file sizes"))

    artifact_type_counts = dict(sorted(Counter(file.artifact_type for file in manifest.fetched_files).items()))
    if manifest.summary.fetched_artifact_type_counts != artifact_type_counts:
        issues.append(_summary_error("fetched_artifact_type_counts", "fetched file artifact type counts"))


def _summary_error(field_name: str, expected: str) -> GitHubCrawlQualityIssue:
    return GitHubCrawlQualityIssue(
        code="summary_mismatch",
        severity="error",
        message=f"Manifest summary field {field_name} does not match {expected}.",
    )


def _check_unique_paths(manifest: GitHubCrawlManifest, issues: list[GitHubCrawlQualityIssue]) -> None:
    _add_duplicate_path_issues([file.path for file in manifest.selected_files], "duplicate_selected_path", issues)
    _add_duplicate_path_issues([file.path for file in manifest.fetched_files], "duplicate_fetched_path", issues)


def _add_duplicate_path_issues(paths: list[str], code: str, issues: list[GitHubCrawlQualityIssue]) -> None:
    counts = Counter(paths)
    for path, count in sorted(counts.items()):
        if count > 1:
            issues.append(
                GitHubCrawlQualityIssue(
                    code=code,
                    severity="error",
                    message="Crawl manifest contains duplicate paths.",
                    path=path,
                )
            )


def _check_fetched_files_were_selected(manifest: GitHubCrawlManifest, issues: list[GitHubCrawlQualityIssue]) -> None:
    selected_paths = {file.path for file in manifest.selected_files}
    for file in manifest.fetched_files:
        if file.path not in selected_paths:
            issues.append(
                GitHubCrawlQualityIssue(
                    code="fetched_file_not_selected",
                    severity="error",
                    message="Fetched file was not present in selected file list.",
                    path=file.path,
                )
            )


def _check_fetched_file_metadata(manifest: GitHubCrawlManifest, issues: list[GitHubCrawlQualityIssue]) -> None:
    for file in manifest.fetched_files:
        if not _is_hex_hash(file.content_hash):
            issues.append(
                GitHubCrawlQualityIssue(
                    code="invalid_content_hash",
                    severity="error",
                    message="Fetched file content hash is not a SHA-256 hex digest.",
                    path=file.path,
                )
            )
        _check_raw_url_matches_manifest(file.path, file.raw_url, manifest, issues)


def _check_raw_url_matches_manifest(
    path: str,
    raw_url: str,
    manifest: GitHubCrawlManifest,
    issues: list[GitHubCrawlQualityIssue],
) -> None:
    parsed = urlparse(raw_url)
    expected_prefix = [
        manifest.owner,
        manifest.repo_name,
        manifest.ref,
    ]
    actual_parts = [unquote(part) for part in parsed.path.strip("/").split("/") if part]
    expected_parts = [*expected_prefix, *path.split("/")]
    if parsed.scheme != "https" or parsed.hostname != _RAW_GITHUB_HOST or actual_parts != expected_parts:
        issues.append(
            GitHubCrawlQualityIssue(
                code="raw_url_mismatch",
                severity="error",
                message="Fetched file raw URL does not match the manifest source, ref, and path.",
                path=path,
            )
        )


def _check_fetch_volume(
    manifest: GitHubCrawlManifest,
    *,
    min_fetched_files: int,
    issues: list[GitHubCrawlQualityIssue],
) -> None:
    if len(manifest.fetched_files) < min_fetched_files:
        issues.append(
            GitHubCrawlQualityIssue(
                code="insufficient_fetched_files",
                severity="error",
                message="Crawl fetched fewer files than the minimum quality threshold.",
            )
        )


def _check_fetch_skip_ratio(
    manifest: GitHubCrawlManifest,
    *,
    max_fetch_skip_ratio: float,
    issues: list[GitHubCrawlQualityIssue],
) -> None:
    fetch_skip_count = sum(1 for path in manifest.skipped_paths if path.stage == "fetch")
    total_fetch_attempts = len(manifest.fetched_files) + fetch_skip_count
    if total_fetch_attempts == 0:
        return
    if fetch_skip_count / total_fetch_attempts > max_fetch_skip_ratio:
        issues.append(
            GitHubCrawlQualityIssue(
                code="high_fetch_skip_ratio",
                severity="warning",
                message="More fetched candidates failed than the crawl quality threshold allows.",
            )
        )


def _check_readme_fetched(manifest: GitHubCrawlManifest, issues: list[GitHubCrawlQualityIssue]) -> None:
    selected_readme_paths = {file.path for file in manifest.selected_files if file.artifact_type == "readme"}
    if not selected_readme_paths:
        issues.append(
            GitHubCrawlQualityIssue(
                code="readme_not_selected",
                severity="warning",
                message="Crawl did not select a README artifact.",
            )
        )
        return

    fetched_paths = {file.path for file in manifest.fetched_files}
    if selected_readme_paths.isdisjoint(fetched_paths):
        issues.append(
            GitHubCrawlQualityIssue(
                code="readme_not_fetched",
                severity="warning",
                message="Crawl selected a README artifact but did not fetch it.",
            )
        )


def _is_hex_hash(value: str) -> bool:
    return len(value) == _HASH_HEX_LENGTH and all(character in "0123456789abcdef" for character in value)


def _hash_manifest(manifest: GitHubCrawlManifest) -> str:
    payload = manifest.model_dump(mode="json", exclude={"manifest_hash"})
    serialized = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return sha256(serialized.encode("utf-8")).hexdigest()
