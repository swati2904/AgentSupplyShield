import json
from hashlib import sha256

import pytest

from app.chunk_metadata import build_chunk_metadata, build_chunk_metadata_records
from app.chunking import TextChunk, chunk_text_artifact


def test_builds_chunk_metadata_without_raw_chunk_text() -> None:
    result = chunk_text_artifact(
        "# Safe Tool\n\nUse SAFE_TOKEN for local tests.\n",
        artifact_id="artifact_readme",
        path="README.md",
    )
    chunk = result.chunks[0]

    metadata = build_chunk_metadata(chunk)
    payload = metadata.model_dump()
    serialized = json.dumps(payload, sort_keys=True)

    assert metadata.chunk_id == chunk.chunk_id
    assert metadata.artifact_id == "artifact_readme"
    assert metadata.path == "README.md"
    assert metadata.chunk_index == 0
    assert metadata.start_line == 1
    assert metadata.end_line == 3
    assert metadata.line_count == 3
    assert metadata.chunk_type == "markdown_section"
    assert metadata.heading_path == ["Safe Tool"]
    assert metadata.heading_depth == 1
    assert metadata.has_heading_context is True
    assert metadata.char_count == len(chunk.text)
    assert metadata.word_count == 7
    assert metadata.content_hash == chunk.content_hash
    assert len(metadata.metadata_hash) == 64
    assert "text" not in payload
    assert "Use SAFE_TOKEN for local tests." not in serialized


def test_builds_metadata_records_in_chunk_order() -> None:
    result = chunk_text_artifact("First paragraph.\n\nSecond paragraph.\n", artifact_id="artifact_notes")

    metadata_records = build_chunk_metadata_records(result.chunks)

    assert [metadata.chunk_id for metadata in metadata_records] == [chunk.chunk_id for chunk in result.chunks]
    assert [metadata.chunk_index for metadata in metadata_records] == [0, 1]
    assert all(metadata.heading_depth == 0 for metadata in metadata_records)
    assert all(metadata.has_heading_context is False for metadata in metadata_records)


def test_metadata_hash_is_stable_and_changes_when_metadata_changes() -> None:
    chunk = chunk_text_artifact("# Stable\n\nSame body.\n", artifact_id="artifact_stable").chunks[0]

    first = build_chunk_metadata(chunk)
    second = build_chunk_metadata(chunk)
    changed_line_range = build_chunk_metadata(chunk.model_copy(update={"end_line": chunk.end_line + 1}))
    changed_content_hash = build_chunk_metadata(
        chunk.model_copy(update={"content_hash": sha256(b"changed").hexdigest()})
    )

    assert first.metadata_hash == second.metadata_hash
    assert first.metadata_hash != changed_line_range.metadata_hash
    assert first.metadata_hash != changed_content_hash.metadata_hash


def test_rejects_invalid_chunk_line_ranges() -> None:
    chunk = TextChunk(
        chunk_id="chunk_bad_range",
        artifact_id="artifact_bad",
        chunk_index=0,
        start_line=5,
        end_line=4,
        chunk_type="text_window",
        text="bad range",
        content_hash=sha256(b"bad range").hexdigest(),
    )

    with pytest.raises(ValueError, match="end_line"):
        build_chunk_metadata(chunk)
