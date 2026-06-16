from hashlib import sha256

import httpx
import pytest

from app.github_file_discovery import RelevantGitHubFile
from app.github_file_fetcher import (
    GitHubFileFetchError,
    build_github_raw_file_url,
    fetch_github_text_file,
    fetch_github_text_files,
)
from app.github_url import canonicalize_github_repo_url


def _repo():
    return canonicalize_github_repo_url("https://github.com/AgentSupplyShield/Safe_Tool")


def _file(path: str = "README.md", artifact_type: str = "readme") -> RelevantGitHubFile:
    return RelevantGitHubFile(
        path=path,
        artifact_type=artifact_type,
        selection_reason=artifact_type,
        priority=0,
        size_bytes=42,
    )


def test_builds_raw_github_file_url_with_encoded_path_segments() -> None:
    raw_url = build_github_raw_file_url(_repo(), ref="main", path="docs/my guide.md")

    assert raw_url == "https://raw.githubusercontent.com/agentsupplyshield/safe_tool/main/docs/my%20guide.md"


def test_fetches_utf8_text_file_with_hash_and_metadata() -> None:
    content = b"# Safe tool\nNo hidden behavior.\n"

    def handler(request: httpx.Request) -> httpx.Response:
        assert str(request.url) == "https://raw.githubusercontent.com/agentsupplyshield/safe_tool/main/README.md"
        assert request.headers["user-agent"] == "AgentSupplyShield/0.1 text-crawler"
        return httpx.Response(
            200,
            headers={"content-type": "text/plain; charset=utf-8", "content-length": str(len(content))},
            content=content,
        )

    with httpx.Client(transport=httpx.MockTransport(handler), follow_redirects=False) as client:
        fetched = fetch_github_text_file(_repo(), _file(), client=client)

    assert fetched.path == "README.md"
    assert fetched.artifact_type == "readme"
    assert fetched.selection_reason == "readme"
    assert fetched.size_bytes == len(content)
    assert fetched.content_hash == sha256(content).hexdigest()
    assert fetched.text == "# Safe tool\nNo hidden behavior.\n"


def test_rejects_binary_or_unsupported_content_type() -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, headers={"content-type": "application/octet-stream"}, content=b"\x89PNG\r\n")

    with httpx.Client(transport=httpx.MockTransport(handler), follow_redirects=False) as client:
        with pytest.raises(GitHubFileFetchError, match="text content type"):
            fetch_github_text_file(_repo(), _file(), client=client)


def test_rejects_declared_or_actual_oversized_file() -> None:
    def declared_large(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, headers={"content-length": "100"}, content=b"small")

    with httpx.Client(transport=httpx.MockTransport(declared_large), follow_redirects=False) as client:
        with pytest.raises(GitHubFileFetchError, match="maximum allowed size"):
            fetch_github_text_file(_repo(), _file(), client=client, max_file_size_bytes=10)

    def actual_large(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, headers={"content-type": "text/plain"}, content=b"x" * 11)

    with httpx.Client(transport=httpx.MockTransport(actual_large), follow_redirects=False) as client:
        with pytest.raises(GitHubFileFetchError, match="maximum allowed size"):
            fetch_github_text_file(_repo(), _file(), client=client, max_file_size_bytes=10)


@pytest.mark.parametrize(
    ("ref", "path"),
    [
        ("feature/docs", "README.md"),
        ("main", "../README.md"),
        ("main", "/README.md"),
        ("main", "docs\\README.md"),
        ("main", "docs/%2e%2e/README.md"),
    ],
)
def test_rejects_unsafe_refs_and_paths_before_fetching(ref: str, path: str) -> None:
    called = False

    def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal called
        called = True
        return httpx.Response(200, content=b"should not fetch")

    with httpx.Client(transport=httpx.MockTransport(handler), follow_redirects=False) as client:
        with pytest.raises(GitHubFileFetchError):
            fetch_github_text_file(_repo(), _file(path), ref=ref, client=client)

    assert called is False


def test_fetches_multiple_files_and_records_skips() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if str(request.url).endswith("/README.md"):
            return httpx.Response(200, headers={"content-type": "text/plain"}, content=b"ok\n")
        return httpx.Response(404, headers={"content-type": "text/plain"}, content=b"missing")

    with httpx.Client(transport=httpx.MockTransport(handler), follow_redirects=False) as client:
        result = fetch_github_text_files(
            _repo(),
            [_file("README.md"), _file("docs/missing.md", artifact_type="documentation")],
            client=client,
        )

    assert [file.path for file in result.fetched_files] == ["README.md"]
    assert result.fetched_files[0].text == "ok\n"
    assert len(result.skipped_files) == 1
    assert result.skipped_files[0].path == "docs/missing.md"
    assert "HTTP 404" in result.skipped_files[0].reason
