from hashlib import sha256
from pathlib import Path
from typing import Iterable

from pydantic import BaseModel, Field


DEFAULT_ALLOWED_EXTENSIONS = frozenset(
    {
        ".md",
        ".markdown",
        ".json",
        ".yaml",
        ".yml",
        ".txt",
        ".toml",
    }
)
DEFAULT_IGNORED_NAMES = frozenset(
    {
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
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        "raw_artifacts",
        "parsed_artifacts",
        "evidence_spans",
    }
)
DEFAULT_MAX_FILE_SIZE_BYTES = 1_000_000


class LocalFileArtifact(BaseModel):
    relative_path: str
    absolute_path: str
    extension: str
    size_bytes: int
    content_hash: str


class SkippedPath(BaseModel):
    relative_path: str
    reason: str


class LocalIngestionResult(BaseModel):
    root_path: str
    files: list[LocalFileArtifact] = Field(default_factory=list)
    skipped: list[SkippedPath] = Field(default_factory=list)


def ingest_local_folder(
    root_path: str | Path,
    *,
    allowed_extensions: Iterable[str] = DEFAULT_ALLOWED_EXTENSIONS,
    ignored_names: Iterable[str] = DEFAULT_IGNORED_NAMES,
    max_file_size_bytes: int = DEFAULT_MAX_FILE_SIZE_BYTES,
) -> LocalIngestionResult:
    root_text = str(root_path)
    if "://" in root_text:
        raise ValueError("Only local folder paths are supported.")

    root = Path(root_path).expanduser().resolve()
    if not root.is_dir():
        raise ValueError(f"Local source path is not a directory: {root}")

    allowed = {extension.lower() for extension in allowed_extensions}
    ignored = set(ignored_names)
    result = LocalIngestionResult(root_path=str(root))

    for path in sorted(root.rglob("*")):
        relative_path = path.relative_to(root).as_posix()
        if _has_ignored_part(path.relative_to(root).parts, ignored):
            if path.is_dir():
                result.skipped.append(SkippedPath(relative_path=relative_path, reason="ignored_path"))
            continue
        if not path.is_file():
            continue

        extension = path.suffix.lower()
        if extension not in allowed:
            result.skipped.append(SkippedPath(relative_path=relative_path, reason="unsupported_extension"))
            continue

        size_bytes = path.stat().st_size
        if size_bytes > max_file_size_bytes:
            result.skipped.append(SkippedPath(relative_path=relative_path, reason="file_too_large"))
            continue

        result.files.append(
            LocalFileArtifact(
                relative_path=relative_path,
                absolute_path=str(path),
                extension=extension,
                size_bytes=size_bytes,
                content_hash=_hash_file(path),
            )
        )

    return result


def _has_ignored_part(parts: tuple[str, ...], ignored_names: set[str]) -> bool:
    return any(part in ignored_names for part in parts)


def _hash_file(path: Path) -> str:
    digest = sha256()
    with path.open("rb") as file:
        for chunk in iter(lambda: file.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()
