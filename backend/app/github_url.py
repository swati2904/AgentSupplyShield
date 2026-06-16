import re
from urllib.parse import urlparse

from pydantic import BaseModel


_ALLOWED_HOSTS = {"github.com", "www.github.com"}
_OWNER_PATTERN = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,37}[a-z0-9])?$")
_REPO_PATTERN = re.compile(r"^[a-z0-9._-]{1,100}$")


class GitHubURLValidationError(ValueError):
    pass


class GitHubRepositoryURL(BaseModel):
    raw_url: str
    canonical_url: str
    owner: str
    repo_name: str


def canonicalize_github_repo_url(raw_url: str) -> GitHubRepositoryURL:
    if not isinstance(raw_url, str):
        raise GitHubURLValidationError("GitHub repository URL must be a string.")

    candidate = raw_url.strip()
    if not candidate:
        raise GitHubURLValidationError("GitHub repository URL is required.")

    parsed = urlparse(candidate)
    scheme = parsed.scheme.lower()
    if scheme not in {"http", "https"}:
        raise GitHubURLValidationError("GitHub repository URL must use http or https.")

    host = parsed.hostname.lower() if parsed.hostname else ""
    if host not in _ALLOWED_HOSTS:
        raise GitHubURLValidationError("GitHub repository URL must use github.com.")

    if parsed.username or parsed.password:
        raise GitHubURLValidationError("GitHub repository URL must not include credentials.")

    try:
        port = parsed.port
    except ValueError as exc:
        raise GitHubURLValidationError("GitHub repository URL has an invalid port.") from exc
    if port is not None:
        raise GitHubURLValidationError("GitHub repository URL must not include a port.")

    if parsed.query or parsed.fragment:
        raise GitHubURLValidationError("GitHub repository URL must not include query strings or fragments.")

    path_segments = [segment for segment in parsed.path.strip("/").split("/") if segment]
    if len(path_segments) != 2:
        raise GitHubURLValidationError("GitHub repository URL must point to a repository root.")

    owner = _normalize_owner(path_segments[0])
    repo_name = _normalize_repo_name(path_segments[1])
    return GitHubRepositoryURL(
        raw_url=candidate,
        canonical_url=f"https://github.com/{owner}/{repo_name}",
        owner=owner,
        repo_name=repo_name,
    )


def _normalize_owner(owner: str) -> str:
    normalized = _normalize_path_segment(owner, "owner")
    if not _OWNER_PATTERN.fullmatch(normalized):
        raise GitHubURLValidationError("GitHub repository owner is invalid.")
    return normalized


def _normalize_repo_name(repo_name: str) -> str:
    normalized = _normalize_path_segment(repo_name, "repository name")
    if normalized.lower().endswith(".git"):
        normalized = normalized[:-4]
    if normalized in {"", ".", ".."} or not _REPO_PATTERN.fullmatch(normalized):
        raise GitHubURLValidationError("GitHub repository name is invalid.")
    return normalized


def _normalize_path_segment(segment: str, label: str) -> str:
    if "%" in segment or "\\" in segment:
        raise GitHubURLValidationError(f"GitHub repository {label} contains unsafe characters.")
    normalized = segment.strip().lower()
    if normalized in {"", ".", ".."}:
        raise GitHubURLValidationError(f"GitHub repository {label} is invalid.")
    return normalized
