import json
import re
from collections.abc import Iterable
from hashlib import sha256

from pydantic import BaseModel, Field

from app.chunking import TextChunk


WORD_PATTERN = re.compile(r"\w+(?:[-']\w+)*")


class ChunkMetadata(BaseModel):
    chunk_id: str
    artifact_id: str
    path: str | None = None
    chunk_index: int = Field(ge=0)
    start_line: int = Field(ge=1)
    end_line: int = Field(ge=1)
    line_count: int = Field(ge=1)
    chunk_type: str
    heading_path: list[str] = Field(default_factory=list)
    heading_depth: int = Field(ge=0)
    has_heading_context: bool
    char_count: int = Field(ge=0)
    word_count: int = Field(ge=0)
    content_hash: str
    metadata_hash: str


def build_chunk_metadata(chunk: TextChunk) -> ChunkMetadata:
    if chunk.end_line < chunk.start_line:
        raise ValueError("chunk end_line must be greater than or equal to start_line.")

    metadata = ChunkMetadata(
        chunk_id=chunk.chunk_id,
        artifact_id=chunk.artifact_id,
        path=chunk.path,
        chunk_index=chunk.chunk_index,
        start_line=chunk.start_line,
        end_line=chunk.end_line,
        line_count=chunk.end_line - chunk.start_line + 1,
        chunk_type=chunk.chunk_type,
        heading_path=list(chunk.heading_path),
        heading_depth=len(chunk.heading_path),
        has_heading_context=bool(chunk.heading_path),
        char_count=len(chunk.text),
        word_count=len(WORD_PATTERN.findall(chunk.text)),
        content_hash=chunk.content_hash,
        metadata_hash="",
    )
    return metadata.model_copy(update={"metadata_hash": _hash_chunk_metadata(metadata)})


def build_chunk_metadata_records(chunks: Iterable[TextChunk]) -> list[ChunkMetadata]:
    return [build_chunk_metadata(chunk) for chunk in chunks]


def _hash_chunk_metadata(metadata: ChunkMetadata) -> str:
    payload = metadata.model_dump(mode="json", exclude={"metadata_hash"})
    serialized = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return sha256(serialized.encode("utf-8")).hexdigest()
