from pathlib import Path
from typing import Any
import json
import re

from pydantic import BaseModel, Field

from app.ingestion import LocalFileArtifact


SAFE_NAME_PATTERN = re.compile(r"[^A-Za-z0-9_.-]+")


class StoredArtifact(BaseModel):
    artifact_id: str
    source_id: str
    relative_path: str
    artifact_type: str
    content_hash: str
    size_bytes: int = Field(ge=0)
    raw_path: str
    parsed_path: str


class ParsedArtifactRecord(BaseModel):
    artifact_id: str
    source_id: str
    relative_path: str
    artifact_type: str
    content_hash: str
    parser_name: str
    parsed_payload: dict[str, Any] = Field(default_factory=dict)


class LocalArtifactStore:
    def __init__(self, root_path: str | Path) -> None:
        self.root_path = Path(root_path).expanduser().resolve()
        self.raw_dir = self.root_path / "raw_artifacts"
        self.parsed_dir = self.root_path / "parsed_artifacts"
        self.raw_dir.mkdir(parents=True, exist_ok=True)
        self.parsed_dir.mkdir(parents=True, exist_ok=True)

    def persist_artifact(
        self,
        *,
        source_id: str,
        artifact_id: str,
        file_artifact: LocalFileArtifact,
        raw_text: str,
        artifact_type: str,
        parser_name: str,
        parsed_payload: dict[str, Any],
    ) -> StoredArtifact:
        safe_artifact_id = _safe_name(artifact_id)
        raw_extension = _safe_extension(file_artifact.extension)
        raw_path = self.raw_dir / f"{safe_artifact_id}{raw_extension}"
        parsed_path = self.parsed_dir / f"{safe_artifact_id}.json"

        raw_path.write_text(raw_text, encoding="utf-8")
        parsed_record = ParsedArtifactRecord(
            artifact_id=artifact_id,
            source_id=source_id,
            relative_path=file_artifact.relative_path,
            artifact_type=artifact_type,
            content_hash=file_artifact.content_hash,
            parser_name=parser_name,
            parsed_payload=parsed_payload,
        )
        parsed_path.write_text(_json_dump(parsed_record.model_dump(mode="json")), encoding="utf-8")

        return StoredArtifact(
            artifact_id=artifact_id,
            source_id=source_id,
            relative_path=file_artifact.relative_path,
            artifact_type=artifact_type,
            content_hash=file_artifact.content_hash,
            size_bytes=file_artifact.size_bytes,
            raw_path=str(raw_path),
            parsed_path=str(parsed_path),
        )


def _safe_name(value: str) -> str:
    safe = SAFE_NAME_PATTERN.sub("_", value).strip("._")
    if not safe:
        raise ValueError("Artifact ID cannot be empty.")
    return safe


def _safe_extension(extension: str) -> str:
    if not extension.startswith("."):
        return ".txt"
    safe = SAFE_NAME_PATTERN.sub("", extension.lower())
    return safe if safe else ".txt"


def _json_dump(payload: dict[str, Any]) -> str:
    return json.dumps(payload, indent=2, sort_keys=True)
