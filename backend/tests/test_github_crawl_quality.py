from datetime import datetime, timezone
from hashlib import sha256

from app.github_crawl_manifest import GitHubCrawlManifest, build_github_crawl_manifest
from app.github_crawl_quality import assess_github_crawl_quality
from app.github_file_discovery import GitHubFileDiscoveryResult, RelevantGitHubFile, SkippedGitHubPath
from app.github_file_fetcher import FetchedGitHubTextFile, GitHubFileFetchResult, SkippedGitHubFetch
from app.github_url import canonicalize_github_repo_url


_GENERATED_AT = datetime(2026, 6, 16, 12, 0, tzinfo=timezone.utc)


def _repo():
    return canonicalize_github_repo_url("https://github.com/AgentSupplyShield/Safe_Tool")


def _selected(path: str, artifact_type: str = "readme", priority: int = 0) -> RelevantGitHubFile:
    return RelevantGitHubFile(
        path=path,
        artifact_type=artifact_type,
        selection_reason=artifact_type,
        priority=priority,
        size_bytes=100,
    )


def _fetched(path: str, artifact_type: str = "readme", text: str = "ok\n") -> FetchedGitHubTextFile:
    content = text.encode("utf-8")
    return FetchedGitHubTextFile(
        path=path,
        raw_url=f"https://raw.githubusercontent.com/agentsupplyshield/safe_tool/main/{path}",
        artifact_type=artifact_type,
        selection_reason=artifact_type,
        size_bytes=len(content),
        content_hash=sha256(content).hexdigest(),
        text=text,
        content_type="text/plain; charset=utf-8",
    )


def _manifest(
    *,
    selected_files: list[RelevantGitHubFile],
    fetched_files: list[FetchedGitHubTextFile],
    skipped_paths: list[SkippedGitHubPath] | None = None,
    skipped_fetches: list[SkippedGitHubFetch] | None = None,
) -> GitHubCrawlManifest:
    return build_github_crawl_manifest(
        _repo(),
        ref="main",
        discovery_result=GitHubFileDiscoveryResult(
            selected_files=selected_files,
            skipped_paths=skipped_paths or [],
        ),
        fetch_result=GitHubFileFetchResult(
            fetched_files=fetched_files,
            skipped_files=skipped_fetches or [],
        ),
        generated_at=_GENERATED_AT,
    )


def _codes(report):
    return {issue.code for issue in report.issues}


def test_quality_passes_for_consistent_manifest() -> None:
    manifest = _manifest(
        selected_files=[_selected("README.md"), _selected("docs/usage.md", "documentation", 30)],
        fetched_files=[_fetched("README.md")],
        skipped_paths=[SkippedGitHubPath(path="src/app.py", reason="unsupported_file")],
    )

    report = assess_github_crawl_quality(manifest)

    assert report.status == "pass"
    assert report.error_count == 0
    assert report.warning_count == 0
    assert report.issues == []


def test_quality_fails_on_manifest_hash_or_summary_mismatch() -> None:
    manifest = _manifest(selected_files=[_selected("README.md")], fetched_files=[_fetched("README.md")])
    tampered = manifest.model_copy(
        update={
            "manifest_hash": "0" * 64,
            "summary": manifest.summary.model_copy(update={"fetched_file_count": 99}),
        }
    )

    report = assess_github_crawl_quality(tampered)

    assert report.status == "fail"
    assert {"manifest_hash_mismatch", "summary_mismatch"}.issubset(_codes(report))


def test_quality_fails_for_duplicate_or_unselected_fetched_paths() -> None:
    manifest = _manifest(
        selected_files=[_selected("README.md"), _selected("README.md")],
        fetched_files=[_fetched("README.md"), _fetched("docs/unselected.md", "documentation")],
    )

    report = assess_github_crawl_quality(manifest)

    assert report.status == "fail"
    assert {"duplicate_selected_path", "fetched_file_not_selected"}.issubset(_codes(report))


def test_quality_fails_for_bad_hash_or_raw_url_mismatch() -> None:
    bad_hash_file = _fetched("README.md").model_copy(update={"content_hash": "not-a-sha"})
    bad_url_file = _fetched("docs/usage.md", "documentation").model_copy(
        update={"raw_url": "https://example.com/agentsupplyshield/safe_tool/main/docs/usage.md"}
    )
    manifest = _manifest(
        selected_files=[_selected("README.md"), _selected("docs/usage.md", "documentation", 30)],
        fetched_files=[bad_hash_file, bad_url_file],
    )

    report = assess_github_crawl_quality(manifest)

    assert report.status == "fail"
    assert {"invalid_content_hash", "raw_url_mismatch"}.issubset(_codes(report))


def test_quality_warns_for_missing_readme_or_high_fetch_skip_ratio() -> None:
    manifest = _manifest(
        selected_files=[
            _selected("README.md"),
            _selected("docs/usage.md", "documentation", 30),
            _selected("docs/config.md", "documentation", 30),
        ],
        fetched_files=[_fetched("docs/usage.md", "documentation")],
        skipped_fetches=[
            SkippedGitHubFetch(path="README.md", reason="HTTP 404"),
            SkippedGitHubFetch(path="docs/config.md", reason="HTTP 404"),
        ],
    )

    report = assess_github_crawl_quality(manifest)

    assert report.status == "warn"
    assert report.error_count == 0
    assert {"readme_not_fetched", "high_fetch_skip_ratio"}.issubset(_codes(report))


def test_quality_can_allow_zero_fetches_for_dry_manifest_checks() -> None:
    manifest = _manifest(selected_files=[], fetched_files=[])

    report = assess_github_crawl_quality(manifest, min_fetched_files=0, require_readme=False)

    assert report.status == "pass"
