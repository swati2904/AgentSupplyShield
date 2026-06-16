import re
from collections.abc import Iterable
from hashlib import sha256
from typing import Any
from urllib.parse import quote, urlparse

import httpx
from pydantic import BaseModel, Field

from app.github_file_discovery import DEFAULT_MAX_GITHUB_FILE_SIZE_BYTES, RelevantGitHubFile
from app.github_url import GitHubRepositoryURL


DEFAULT_GITHUB_RAW_TIMEOUT_SECONDS = 10.0
_RAW_GITHUB_HOST = "raw.githubusercontent.com"
_REF_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_TEXT_CONTENT_TYPES = {
    "application/json",
    "application/toml",
    "application/xml",
    "application/yaml",
    "application/x-yaml",
}


class GitHubFileFetchError(RuntimeError):
    pass


class FetchedGitHubTextFile(BaseModel):
    path: str
    raw_url: str
    artifact_type: str
    selection_reason: str
    size_bytes: int = Field(ge=0)
    content_hash: str
    text: str
    content_type: str | None = None
    encoding: str = "utf-8"


class SkippedGitHubFetch(BaseModel):
    path: str
    reason: str


class GitHubFileFetchResult(BaseModel):
    fetched_files: list[FetchedGitHubTextFile] = Field(default_factory=list)
    skipped_files: list[SkippedGitHubFetch] = Field(default_factory=list)


def build_github_raw_file_url(repo: GitHubRepositoryURL, *, ref: str, path: str) -> str:
    normalized_ref = _normalize_ref(ref)
    normalized_path = _normalize_fetch_path(path)
    encoded_path = "/".join(quote(part, safe="") for part in normalized_path.split("/"))
    return (
        f"https://{_RAW_GITHUB_HOST}/"
        f"{quote(repo.owner, safe='')}/"
        f"{quote(repo.repo_name, safe='')}/"
        f"{quote(normalized_ref, safe='')}/"
        f"{encoded_path}"
    )


def fetch_github_text_file(
    repo: GitHubRepositoryURL,
    file: RelevantGitHubFile | dict[str, Any],
    *,
    ref: str = "main",
    client: httpx.Client | None = None,
    max_file_size_bytes: int = DEFAULT_MAX_GITHUB_FILE_SIZE_BYTES,
) -> FetchedGitHubTextFile:
    relevant_file = file if isinstance(file, RelevantGitHubFile) else RelevantGitHubFile.model_validate(file)
    raw_url = build_github_raw_file_url(repo, ref=ref, path=relevant_file.path)
    _validate_raw_github_url(raw_url)

    response = _get_raw_response(raw_url, client=client)
    _raise_for_fetch_status(response)
    _raise_if_declared_too_large(response, max_file_size_bytes)

    content = response.content
    if len(content) > max_file_size_bytes:
        raise GitHubFileFetchError("Fetched GitHub file exceeds the maximum allowed size.")

    content_type = response.headers.get("content-type")
    if content_type and not _is_text_content_type(content_type):
        raise GitHubFileFetchError("Fetched GitHub file is not a supported text content type.")

    text = _decode_text_content(content)
    return FetchedGitHubTextFile(
        path=relevant_file.path,
        raw_url=raw_url,
        artifact_type=relevant_file.artifact_type,
        selection_reason=relevant_file.selection_reason,
        size_bytes=len(content),
        content_hash=sha256(content).hexdigest(),
        text=text,
        content_type=content_type,
    )


def fetch_github_text_files(
    repo: GitHubRepositoryURL,
    files: Iterable[RelevantGitHubFile | dict[str, Any]],
    *,
    ref: str = "main",
    client: httpx.Client | None = None,
    max_file_size_bytes: int = DEFAULT_MAX_GITHUB_FILE_SIZE_BYTES,
) -> GitHubFileFetchResult:
    fetched_files: list[FetchedGitHubTextFile] = []
    skipped_files: list[SkippedGitHubFetch] = []

    for raw_file in files:
        try:
            file = raw_file if isinstance(raw_file, RelevantGitHubFile) else RelevantGitHubFile.model_validate(raw_file)
            fetched_files.append(
                fetch_github_text_file(
                    repo,
                    file,
                    ref=ref,
                    client=client,
                    max_file_size_bytes=max_file_size_bytes,
                )
            )
        except (GitHubFileFetchError, ValueError) as exc:
            path = raw_file.path if isinstance(raw_file, RelevantGitHubFile) else str(raw_file.get("path", ""))
            skipped_files.append(SkippedGitHubFetch(path=path, reason=str(exc)))

    return GitHubFileFetchResult(fetched_files=fetched_files, skipped_files=skipped_files)


def _get_raw_response(raw_url: str, *, client: httpx.Client | None) -> httpx.Response:
    headers = {
        "accept": "text/plain, application/json, application/yaml, application/x-yaml, */*;q=0.1",
        "user-agent": "AgentSupplyShield/0.1 text-crawler",
    }
    if client is not None:
        try:
            return client.get(raw_url, headers=headers)
        except httpx.HTTPError as exc:
            raise GitHubFileFetchError("GitHub raw file fetch failed.") from exc

    try:
        with httpx.Client(follow_redirects=False, timeout=DEFAULT_GITHUB_RAW_TIMEOUT_SECONDS) as default_client:
            return default_client.get(raw_url, headers=headers)
    except httpx.HTTPError as exc:
        raise GitHubFileFetchError("GitHub raw file fetch failed.") from exc


def _normalize_ref(ref: str) -> str:
    normalized = ref.strip()
    if not _REF_PATTERN.fullmatch(normalized) or normalized in {".", ".."}:
        raise GitHubFileFetchError("GitHub ref must be a simple branch, tag, or commit identifier.")
    return normalized


def _normalize_fetch_path(path: str) -> str:
    candidate = path.strip()
    if not candidate or candidate.startswith("/") or "\\" in candidate or "\x00" in candidate or "%" in candidate:
        raise GitHubFileFetchError("GitHub file path is unsafe.")
    parts = candidate.split("/")
    if any(part in {"", ".", ".."} for part in parts):
        raise GitHubFileFetchError("GitHub file path is unsafe.")
    return "/".join(parts)


def _validate_raw_github_url(raw_url: str) -> None:
    parsed = urlparse(raw_url)
    if parsed.scheme != "https" or parsed.hostname != _RAW_GITHUB_HOST:
        raise GitHubFileFetchError("GitHub raw file URL must use the allowed raw GitHub host.")
    if parsed.username or parsed.password or parsed.port is not None or parsed.query or parsed.fragment:
        raise GitHubFileFetchError("GitHub raw file URL contains unsupported URL parts.")


def _raise_for_fetch_status(response: httpx.Response) -> None:
    if response.status_code != 200:
        raise GitHubFileFetchError(f"GitHub raw file fetch returned HTTP {response.status_code}.")


def _raise_if_declared_too_large(response: httpx.Response, max_file_size_bytes: int) -> None:
    content_length = response.headers.get("content-length")
    if content_length is None:
        return
    try:
        declared_size = int(content_length)
    except ValueError as exc:
        raise GitHubFileFetchError("GitHub raw file response has an invalid Content-Length.") from exc
    if declared_size > max_file_size_bytes:
        raise GitHubFileFetchError("GitHub raw file exceeds the maximum allowed size.")


def _is_text_content_type(content_type: str) -> bool:
    media_type = content_type.split(";", 1)[0].strip().lower()
    return media_type.startswith("text/") or media_type in _TEXT_CONTENT_TYPES


def _decode_text_content(content: bytes) -> str:
    if b"\x00" in content:
        raise GitHubFileFetchError("Fetched GitHub file contains binary data.")
    try:
        return content.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise GitHubFileFetchError("Fetched GitHub file is not valid UTF-8 text.") from exc
