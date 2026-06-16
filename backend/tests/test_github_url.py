import pytest

from app.github_url import GitHubURLValidationError, canonicalize_github_repo_url


@pytest.mark.parametrize(
    "raw_url",
    [
        "https://github.com/Owner/Repo",
        "http://github.com/Owner/Repo/",
        "https://www.github.com/Owner/Repo.git",
        "  https://github.com/OWNER/.github  ",
    ],
)
def test_canonicalizes_github_repository_root_urls(raw_url: str) -> None:
    result = canonicalize_github_repo_url(raw_url)

    assert result.canonical_url.startswith("https://github.com/")
    assert result.owner == "owner"


def test_canonicalizes_owner_and_repo_name() -> None:
    result = canonicalize_github_repo_url("https://GitHub.com/AgentSupplyShield/Safe_Tool.git")

    assert result.canonical_url == "https://github.com/agentsupplyshield/safe_tool"
    assert result.owner == "agentsupplyshield"
    assert result.repo_name == "safe_tool"


@pytest.mark.parametrize(
    "raw_url",
    [
        "https://github.com.evil.example/owner/repo",
        "https://raw.githubusercontent.com/owner/repo/main/README.md",
        "https://evil.example/owner/repo",
        "https://github.com@evil.example/owner/repo",
    ],
)
def test_rejects_non_github_hosts(raw_url: str) -> None:
    with pytest.raises(GitHubURLValidationError):
        canonicalize_github_repo_url(raw_url)


@pytest.mark.parametrize(
    "raw_url",
    [
        "ftp://github.com/owner/repo",
        "https://github.com:443/owner/repo",
        "https://user:pass@github.com/owner/repo",
        "https://github.com/owner/repo?tab=readme-ov-file",
        "https://github.com/owner/repo#readme",
    ],
)
def test_rejects_ambiguous_or_unsafe_url_parts(raw_url: str) -> None:
    with pytest.raises(GitHubURLValidationError):
        canonicalize_github_repo_url(raw_url)


@pytest.mark.parametrize(
    "raw_url",
    [
        "https://github.com/owner",
        "https://github.com/owner/repo/tree/main",
        "https://github.com/owner/repo/issues/1",
        "https://github.com/-owner/repo",
        "https://github.com/owner-/repo",
        "https://github.com/owner/repo%2Fsecret",
        "https://github.com/owner/..",
        "https://github.com/owner/repo name",
    ],
)
def test_rejects_non_repository_or_invalid_paths(raw_url: str) -> None:
    with pytest.raises(GitHubURLValidationError):
        canonicalize_github_repo_url(raw_url)
