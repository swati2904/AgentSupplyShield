import json
import math
import re
from collections.abc import Iterable
from hashlib import sha256
from typing import Protocol, runtime_checkable

from pydantic import BaseModel, Field

from app.chunk_metadata import build_chunk_metadata
from app.chunking import TextChunk


EMBEDDING_STRATEGY_VERSION = "chunk-embedding-strategy/v0.1"
DEFAULT_EMBEDDING_DIMENSIONS = 64
TOKEN_PATTERN = re.compile(r"[a-z0-9]+")


class EmbeddingStrategyConfig(BaseModel):
    provider: str = "deterministic_hash"
    model_name: str = "local-hash-embedding-v1"
    dimensions: int = Field(default=DEFAULT_EMBEDDING_DIMENSIONS, ge=1)
    normalize: bool = True
    include_heading_context: bool = True
    strategy_version: str = EMBEDDING_STRATEGY_VERSION


class ChunkEmbeddingRecord(BaseModel):
    chunk_id: str
    artifact_id: str
    path: str | None = None
    chunk_index: int = Field(ge=0)
    start_line: int = Field(ge=1)
    end_line: int = Field(ge=1)
    heading_path: list[str] = Field(default_factory=list)
    provider: str
    model_name: str
    dimensions: int = Field(ge=1)
    normalize: bool
    strategy_version: str
    vector: list[float] = Field(min_length=1)
    content_hash: str
    metadata_hash: str
    embedding_hash: str


class QueryEmbeddingRecord(BaseModel):
    query_hash: str
    provider: str
    model_name: str
    dimensions: int = Field(ge=1)
    normalize: bool
    strategy_version: str
    vector: list[float] = Field(min_length=1)
    embedding_hash: str


@runtime_checkable
class EmbeddingProvider(Protocol):
    config: EmbeddingStrategyConfig

    def embed_text(self, text: str) -> list[float]:
        ...


class DeterministicHashEmbeddingProvider:
    def __init__(self, config: EmbeddingStrategyConfig | None = None) -> None:
        self.config = config or EmbeddingStrategyConfig()

    def embed_text(self, text: str) -> list[float]:
        tokens = _tokenize(text) or ["empty"]
        vector = [0.0] * self.config.dimensions
        for token in tokens:
            digest = sha256(f"{self.config.model_name}:{token}".encode("utf-8")).digest()
            bucket = int.from_bytes(digest[:4], "big") % self.config.dimensions
            sign = 1.0 if digest[4] % 2 == 0 else -1.0
            weight = 1.0 + (digest[5] / 255.0)
            vector[bucket] += sign * weight

        if self.config.normalize:
            vector = _normalize_vector(vector)
        return [round(value, 6) for value in vector]


def build_chunk_embedding_record(
    chunk: TextChunk,
    provider: EmbeddingProvider | None = None,
) -> ChunkEmbeddingRecord:
    embedding_provider = provider or DeterministicHashEmbeddingProvider()
    metadata = build_chunk_metadata(chunk)
    vector = embedding_provider.embed_text(_embedding_input_text(chunk, embedding_provider.config))
    _validate_vector_dimensions(vector, embedding_provider.config.dimensions)

    record = ChunkEmbeddingRecord(
        chunk_id=metadata.chunk_id,
        artifact_id=metadata.artifact_id,
        path=metadata.path,
        chunk_index=metadata.chunk_index,
        start_line=metadata.start_line,
        end_line=metadata.end_line,
        heading_path=metadata.heading_path,
        provider=embedding_provider.config.provider,
        model_name=embedding_provider.config.model_name,
        dimensions=embedding_provider.config.dimensions,
        normalize=embedding_provider.config.normalize,
        strategy_version=embedding_provider.config.strategy_version,
        vector=vector,
        content_hash=metadata.content_hash,
        metadata_hash=metadata.metadata_hash,
        embedding_hash="",
    )
    return record.model_copy(update={"embedding_hash": _hash_embedding_record(record)})


def build_chunk_embedding_records(
    chunks: Iterable[TextChunk],
    provider: EmbeddingProvider | None = None,
) -> list[ChunkEmbeddingRecord]:
    embedding_provider = provider or DeterministicHashEmbeddingProvider()
    return [build_chunk_embedding_record(chunk, embedding_provider) for chunk in chunks]


def build_query_embedding_record(
    query: str,
    provider: EmbeddingProvider | None = None,
) -> QueryEmbeddingRecord:
    embedding_provider = provider or DeterministicHashEmbeddingProvider()
    vector = embedding_provider.embed_text(query)
    _validate_vector_dimensions(vector, embedding_provider.config.dimensions)
    record = QueryEmbeddingRecord(
        query_hash=sha256(query.encode("utf-8")).hexdigest(),
        provider=embedding_provider.config.provider,
        model_name=embedding_provider.config.model_name,
        dimensions=embedding_provider.config.dimensions,
        normalize=embedding_provider.config.normalize,
        strategy_version=embedding_provider.config.strategy_version,
        vector=vector,
        embedding_hash="",
    )
    return record.model_copy(update={"embedding_hash": _hash_embedding_record(record)})


def _embedding_input_text(chunk: TextChunk, config: EmbeddingStrategyConfig) -> str:
    if not config.include_heading_context:
        return chunk.text
    context_parts = [chunk.path or "", " > ".join(chunk.heading_path)]
    context = "\n".join(part for part in context_parts if part)
    return f"{context}\n{chunk.text}" if context else chunk.text


def _validate_vector_dimensions(vector: list[float], dimensions: int) -> None:
    if len(vector) != dimensions:
        raise ValueError("embedding vector length must match configured dimensions.")


def _hash_embedding_record(record: ChunkEmbeddingRecord | QueryEmbeddingRecord) -> str:
    payload = record.model_dump(mode="json", exclude={"embedding_hash"})
    serialized = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return sha256(serialized.encode("utf-8")).hexdigest()


def _normalize_vector(vector: list[float]) -> list[float]:
    magnitude = math.sqrt(sum(value * value for value in vector))
    if magnitude == 0:
        return vector
    return [value / magnitude for value in vector]


def _tokenize(text: str) -> list[str]:
    normalized = text.lower().replace("_", " ").replace("-", " ")
    return TOKEN_PATTERN.findall(normalized)
