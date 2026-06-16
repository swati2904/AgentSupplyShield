import json
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path

from app.github_crawl_manifest import (
    GITHUB_CRAWL_MANIFEST_VERSION,
    build_github_crawl_manifest,
    crawl_manifest_to_json,
    write_github_crawl_manifest,
)
from app.github_file_discovery import GitHubFileDiscoveryResult, RelevantGitHubFile, SkippedGitHubPath
from app.github_file_fetcher import FetchedGitHubTextFile, GitHubFileFetchResult, SkippedGitHubFetch
from app.github_url import canonicalize_github_repo_url


_GENERATED_AT = datetime(2026, 6, 16, 12, 0, tzinfo=timezone.utc)


def _repo():
    return canonicalize_github_repo_url("https://github.com/AgentSupplyShield/Safe_Tool")


def _selected(path: str, artifact_type: str, priority: int) -> RelevantGitHubFile:
    return RelevantGitHubFile(
        path=path,
        artifact_type=artifact_type,
        selection_reason=artifact_type,
        priority=priority,
        size_bytes=100,
    )


def _fetched(path: str, artifact_type: str, text: str) -> FetchedGitHubTextFile:
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


def test_builds_crawl_manifest_with_source_summary_and_skips() -> None:
    discovery_result = GitHubFileDiscoveryResult(
        selected_files=[
            _selected("README.md", "readme", 0),
            _selected("docs/usage.md", "documentation", 30),
        ],
        skipped_paths=[SkippedGitHubPath(path="src/app.py", reason="unsupported_file")],
    )
    fetch_result = GitHubFileFetchResult(
        fetched_files=[_fetched("README.md", "readme", "# Safe tool\n")],
        skipped_files=[SkippedGitHubFetch(path="docs/usage.md", reason="GitHub raw file fetch returned HTTP 404.")],
    )

    manifest = build_github_crawl_manifest(
        _repo(),
        ref="main",
        discovery_result=discovery_result,
        fetch_result=fetch_result,
        generated_at=_GENERATED_AT,
    )

    assert manifest.manifest_version == GITHUB_CRAWL_MANIFEST_VERSION
    assert manifest.source_type == "github_repo"
    assert manifest.source_url == "https://github.com/AgentSupplyShield/Safe_Tool"
    assert manifest.canonical_url == "https://github.com/agentsupplyshield/safe_tool"
    assert manifest.ref == "main"
    assert manifest.summary.selected_file_count == 2
    assert manifest.summary.fetched_file_count == 1
    assert manifest.summary.skipped_path_count == 2
    assert manifest.summary.total_fetched_bytes == len("# Safe tool\n".encode("utf-8"))
    assert manifest.summary.fetched_artifact_type_counts == {"readme": 1}
    assert [(skip.stage, skip.path) for skip in manifest.skipped_paths] == [
        ("discovery", "src/app.py"),
        ("fetch", "docs/usage.md"),
    ]
    assert len(manifest.manifest_hash) == 64


def test_manifest_hash_is_stable_for_same_crawl_inputs() -> None:
    discovery_result = GitHubFileDiscoveryResult(selected_files=[_selected("README.md", "readme", 0)])
    fetch_result = GitHubFileFetchResult(fetched_files=[_fetched("README.md", "readme", "same\n")])

    first = build_github_crawl_manifest(
        _repo(),
        ref="main",
        discovery_result=discovery_result,
        fetch_result=fetch_result,
        generated_at=_GENERATED_AT,
    )
    second = build_github_crawl_manifest(
        _repo(),
        ref="main",
        discovery_result=discovery_result,
        fetch_result=fetch_result,
        generated_at=_GENERATED_AT,
    )
    changed = build_github_crawl_manifest(
        _repo(),
        ref="main",
        discovery_result=discovery_result,
        fetch_result=GitHubFileFetchResult(fetched_files=[_fetched("README.md", "readme", "changed\n")]),
        generated_at=_GENERATED_AT,
    )

    assert first.manifest_hash == second.manifest_hash
    assert first.manifest_hash != changed.manifest_hash


def test_manifest_json_excludes_raw_fetched_text() -> None:
    manifest = build_github_crawl_manifest(
        _repo(),
        ref="main",
        discovery_result=GitHubFileDiscoveryResult(selected_files=[_selected("README.md", "readme", 0)]),
        fetch_result=GitHubFileFetchResult(fetched_files=[_fetched("README.md", "readme", "raw external text\n")]),
        generated_at=_GENERATED_AT,
    )

    payload = crawl_manifest_to_json(manifest)
    parsed = json.loads(payload)

    assert "raw external text" not in payload
    assert parsed["fetched_files"][0]["path"] == "README.md"
    assert parsed["fetched_files"][0]["content_hash"] == sha256(b"raw external text\n").hexdigest()
    assert parsed["manifest_hash"] == manifest.manifest_hash


def test_writes_manifest_json_to_disk(tmp_path: Path) -> None:
    manifest = build_github_crawl_manifest(
        _repo(),
        ref="main",
        discovery_result=GitHubFileDiscoveryResult(selected_files=[_selected("README.md", "readme", 0)]),
        fetch_result=GitHubFileFetchResult(fetched_files=[_fetched("README.md", "readme", "ok\n")]),
        generated_at=_GENERATED_AT,
    )

    output_path = write_github_crawl_manifest(manifest, tmp_path / "nested" / "crawl_manifest.json")

    assert output_path.exists()
    assert json.loads(output_path.read_text(encoding="utf-8"))["manifest_hash"] == manifest.manifest_hash
