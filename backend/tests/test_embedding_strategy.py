import json
import math
from hashlib import sha256

import pytest
from pydantic import ValidationError

from app.chunking import TextChunk, chunk_text_artifact
from app.embedding_strategy import (
    DEFAULT_EMBEDDING_DIMENSIONS,
    DeterministicHashEmbeddingProvider,
    EmbeddingStrategyConfig,
    build_chunk_embedding_record,
    build_chunk_embedding_records,
    build_query_embedding_record,
)


def test_builds_chunk_embedding_record_without_raw_text() -> None:
    result = chunk_text_artifact(
        "# Permissions\n\nRequires SAFE_API_KEY for local test fixtures.\n",
        artifact_id="artifact_readme",
        path="README.md",
    )
    chunk = result.chunks[0]

    record = build_chunk_embedding_record(chunk)
    payload = record.model_dump()
    serialized = json.dumps(payload, sort_keys=True)

    assert record.chunk_id == chunk.chunk_id
    assert record.artifact_id == "artifact_readme"
    assert record.path == "README.md"
    assert record.start_line == chunk.start_line
    assert record.end_line == chunk.end_line
    assert record.heading_path == ["Permissions"]
    assert record.provider == "deterministic_hash"
    assert record.model_name == "local-hash-embedding-v1"
    assert record.dimensions == DEFAULT_EMBEDDING_DIMENSIONS
    assert len(record.vector) == DEFAULT_EMBEDDING_DIMENSIONS
    assert _magnitude(record.vector) == pytest.approx(1.0, abs=0.00001)
    assert record.content_hash == chunk.content_hash
    assert len(record.metadata_hash) == 64
    assert len(record.embedding_hash) == 64
    assert "text" not in payload
    assert "SAFE_API_KEY" not in serialized


def test_embedding_records_are_stable_and_change_with_content() -> None:
    first_chunk = _chunk(0, "Network access requires review.")
    same_chunk = _chunk(0, "Network access requires review.")
    changed_chunk = _chunk(0, "Filesystem write access requires review.")

    first = build_chunk_embedding_record(first_chunk)
    same = build_chunk_embedding_record(same_chunk)
    changed = build_chunk_embedding_record(changed_chunk)

    assert first.vector == same.vector
    assert first.embedding_hash == same.embedding_hash
    assert first.vector != changed.vector
    assert first.embedding_hash != changed.embedding_hash


def test_batch_embedding_preserves_chunk_order_and_provider_config() -> None:
    provider = DeterministicHashEmbeddingProvider(
        EmbeddingStrategyConfig(model_name="local-test-provider", dimensions=16)
    )
    chunks = [
        _chunk(0, "Credential handling guidance."),
        _chunk(1, "Prompt injection evidence."),
    ]

    records = build_chunk_embedding_records(reversed(chunks), provider)

    assert [record.chunk_id for record in records] == ["chunk_1", "chunk_0"]
    assert [record.dimensions for record in records] == [16, 16]
    assert all(record.model_name == "local-test-provider" for record in records)
    assert all(len(record.vector) == 16 for record in records)


def test_query_embedding_record_hashes_query_without_storing_raw_query() -> None:
    query = "find prompt injection evidence"

    record = build_query_embedding_record(query)
    payload = record.model_dump()
    serialized = json.dumps(payload, sort_keys=True)

    assert record.query_hash == sha256(query.encode("utf-8")).hexdigest()
    assert len(record.vector) == DEFAULT_EMBEDDING_DIMENSIONS
    assert len(record.embedding_hash) == 64
    assert "query" not in payload
    assert query not in serialized


def test_invalid_config_and_bad_provider_vectors_fail() -> None:
    with pytest.raises(ValidationError):
        EmbeddingStrategyConfig(dimensions=0)

    class BadProvider:
        config = EmbeddingStrategyConfig(dimensions=4)

        def embed_text(self, text: str) -> list[float]:
            return [0.1, 0.2]

    with pytest.raises(ValueError, match="vector length"):
        build_chunk_embedding_record(_chunk(0, "short text"), BadProvider())


def _chunk(index: int, text: str) -> TextChunk:
    return TextChunk(
        chunk_id=f"chunk_{index}",
        artifact_id="artifact_manual",
        path="README.md",
        chunk_index=index,
        start_line=index + 1,
        end_line=index + 1,
        chunk_type="text_window",
        heading_path=[],
        text=text,
        content_hash=sha256(text.encode("utf-8")).hexdigest(),
    )


def _magnitude(vector: list[float]) -> float:
    return math.sqrt(sum(value * value for value in vector))
