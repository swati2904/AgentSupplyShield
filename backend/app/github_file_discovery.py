from collections.abc import Iterable
from pathlib import PurePosixPath
from typing import Any, Literal

from pydantic import BaseModel, Field


DEFAULT_MAX_GITHUB_FILE_SIZE_BYTES = 1_000_000
DEFAULT_MAX_SELECTED_FILES = 100

_IGNORED_PATH_PARTS = {
    ".git",
    ".hg",
    ".svn",
    ".venv",
    "venv",
    "env",
    "__pycache__",
    "node_modules",
    "dist",
    "build",
    "coverage",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    "raw_artifacts",
    "parsed_artifacts",
    "evidence_spans",
}
_SECRET_FILENAMES = {".env", ".env.local", ".env.production", ".npmrc", ".pypirc"}
_LOCKFILE_NAMES = {"package-lock.json", "pnpm-lock.yaml", "yarn.lock", "poetry.lock"}
_README_EXTENSIONS = {".md", ".markdown", ".txt"}
_DOCUMENTATION_EXTENSIONS = {".md", ".markdown", ".txt"}
_SCHEMA_EXTENSIONS = {".json", ".yaml", ".yml"}
_SCHEMA_NAMES = {
    "ai-plugin.json",
    "mcp.json",
    "mcp.yaml",
    "mcp.yml",
    "mcp-server.json",
    "mcp-server.yaml",
    "mcp-server.yml",
    "openapi.json",
    "openapi.yaml",
    "openapi.yml",
    "schema.json",
    "schema.yaml",
    "schema.yml",
    "swagger.json",
    "tool.json",
    "tool.yaml",
    "tool.yml",
    "tools.json",
    "tools.yaml",
    "tools.yml",
}
_PACKAGE_MANIFEST_NAMES = {
    "cargo.toml",
    "go.mod",
    "package.json",
    "pyproject.toml",
    "requirements-dev.txt",
    "requirements.txt",
}


class GitHubTreeItem(BaseModel):
    path: str
    type: Literal["blob", "tree"]
    size: int | None = Field(default=None, ge=0)


class RelevantGitHubFile(BaseModel):
    path: str
    artifact_type: str
    selection_reason: str
    priority: int = Field(ge=0)
    size_bytes: int | None = Field(default=None, ge=0)


class SkippedGitHubPath(BaseModel):
    path: str
    reason: str


class GitHubFileDiscoveryResult(BaseModel):
    selected_files: list[RelevantGitHubFile] = Field(default_factory=list)
    skipped_paths: list[SkippedGitHubPath] = Field(default_factory=list)


def discover_relevant_github_files(
    tree_items: Iterable[GitHubTreeItem | dict[str, Any]],
    *,
    max_file_size_bytes: int = DEFAULT_MAX_GITHUB_FILE_SIZE_BYTES,
    max_selected_files: int = DEFAULT_MAX_SELECTED_FILES,
) -> GitHubFileDiscoveryResult:
    candidates: list[RelevantGitHubFile] = []
    skipped: list[SkippedGitHubPath] = []

    for raw_item in tree_items:
        item = raw_item if isinstance(raw_item, GitHubTreeItem) else GitHubTreeItem.model_validate(raw_item)
        normalized_path = _normalize_tree_path(item.path)
        if normalized_path is None:
            skipped.append(SkippedGitHubPath(path=item.path, reason="unsafe_path"))
            continue
        if item.type != "blob":
            skipped.append(SkippedGitHubPath(path=normalized_path, reason="not_a_file"))
            continue
        if _has_ignored_path_part(normalized_path):
            skipped.append(SkippedGitHubPath(path=normalized_path, reason="ignored_path"))
            continue
        if item.size is not None and item.size > max_file_size_bytes:
            skipped.append(SkippedGitHubPath(path=normalized_path, reason="file_too_large"))
            continue

        classification = _classify_relevant_file(normalized_path)
        if classification is None:
            skipped.append(SkippedGitHubPath(path=normalized_path, reason="unsupported_file"))
            continue

        artifact_type, priority, selection_reason = classification
        candidates.append(
            RelevantGitHubFile(
                path=normalized_path,
                artifact_type=artifact_type,
                selection_reason=selection_reason,
                priority=priority,
                size_bytes=item.size,
            )
        )

    selected = sorted(candidates, key=lambda file: (file.priority, file.path.lower()))
    if max_selected_files < len(selected):
        for file in selected[max_selected_files:]:
            skipped.append(SkippedGitHubPath(path=file.path, reason="selection_limit"))
        selected = selected[:max_selected_files]

    return GitHubFileDiscoveryResult(selected_files=selected, skipped_paths=skipped)


def _normalize_tree_path(path: str) -> str | None:
    candidate = path.strip()
    if not candidate or candidate.startswith("/") or "\\" in candidate or "\x00" in candidate:
        return None
    parts = candidate.split("/")
    if any(part in {"", ".", ".."} for part in parts):
        return None
    return "/".join(parts)


def _has_ignored_path_part(path: str) -> bool:
    parts = [part.lower() for part in path.split("/")]
    name = parts[-1]
    return (
        any(part in _IGNORED_PATH_PARTS for part in parts)
        or name in _SECRET_FILENAMES
        or name in _LOCKFILE_NAMES
        or name.startswith(".env.")
    )


def _classify_relevant_file(path: str) -> tuple[str, int, str] | None:
    posix_path = PurePosixPath(path)
    name = posix_path.name.lower()
    suffix = posix_path.suffix.lower()
    parts = [part.lower() for part in posix_path.parts]

    if name.startswith("readme") and suffix in _README_EXTENSIONS:
        return ("readme", 0, "readme")
    if name in _SCHEMA_NAMES or (name.endswith(".schema.json") and suffix in _SCHEMA_EXTENSIONS):
        return ("tool_schema", 10, "tool_schema")
    if name in _PACKAGE_MANIFEST_NAMES:
        return ("package_manifest", 20, "package_manifest")
    if suffix in _DOCUMENTATION_EXTENSIONS and _is_documentation_path(parts):
        return ("documentation", 30, "documentation")
    if suffix in _SCHEMA_EXTENSIONS and _is_documentation_path(parts):
        return ("documentation_metadata", 40, "documentation_metadata")
    return None


def _is_documentation_path(parts: list[str]) -> bool:
    return any(part in {"docs", "doc", "documentation", "examples", "example"} for part in parts[:-1])
