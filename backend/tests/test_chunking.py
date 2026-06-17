import pytest

from app.chunking import chunk_text_artifact


def test_chunks_markdown_by_heading_structure() -> None:
    raw_text = """# Safe Tool

Overview paragraph.

## Usage

Run the safe command.

### Configuration

Set SAFE_TOKEN to a test value.
"""

    result = chunk_text_artifact(raw_text, artifact_id="artifact_readme", path="README.md")

    assert [(chunk.start_line, chunk.end_line, chunk.heading_path) for chunk in result.chunks] == [
        (1, 4, ["Safe Tool"]),
        (5, 8, ["Safe Tool", "Usage"]),
        (9, 11, ["Safe Tool", "Usage", "Configuration"]),
    ]
    assert all(chunk.chunk_type == "markdown_section" for chunk in result.chunks)
    assert result.chunks[0].text == "# Safe Tool\n\nOverview paragraph."
    assert result.chunks[0].path == "README.md"


def test_chunks_plain_text_by_paragraphs_when_no_headings_exist() -> None:
    raw_text = "First paragraph line one.\nStill first paragraph.\n\nSecond paragraph.\n"

    result = chunk_text_artifact(raw_text, artifact_id="artifact_text")

    assert [(chunk.chunk_type, chunk.start_line, chunk.end_line, chunk.text) for chunk in result.chunks] == [
        ("paragraph", 1, 2, "First paragraph line one.\nStill first paragraph."),
        ("paragraph", 4, 4, "Second paragraph."),
    ]
    assert all(chunk.heading_path == [] for chunk in result.chunks)


def test_splits_large_structural_sections_without_losing_line_ranges() -> None:
    raw_text = "# Large Section\nline one\nline two\nline three\nline four\n"

    result = chunk_text_artifact(
        raw_text,
        artifact_id="artifact_large",
        max_chunk_lines=2,
        max_chunk_chars=1_000,
    )

    assert [(chunk.start_line, chunk.end_line, chunk.heading_path) for chunk in result.chunks] == [
        (1, 2, ["Large Section"]),
        (3, 4, ["Large Section"]),
        (5, 5, ["Large Section"]),
    ]
    assert [chunk.chunk_index for chunk in result.chunks] == [0, 1, 2]


def test_chunk_ids_and_hashes_are_stable_for_same_input() -> None:
    raw_text = "# Stable\n\nThe same content.\n"

    first = chunk_text_artifact(raw_text, artifact_id="artifact_stable")
    second = chunk_text_artifact(raw_text, artifact_id="artifact_stable")

    assert [chunk.chunk_id for chunk in first.chunks] == [chunk.chunk_id for chunk in second.chunks]
    assert [chunk.content_hash for chunk in first.chunks] == [chunk.content_hash for chunk in second.chunks]


def test_handles_preamble_before_first_markdown_heading() -> None:
    raw_text = "Intro before title.\n\n# Title\n\nBody.\n"

    result = chunk_text_artifact(raw_text, artifact_id="artifact_preamble")

    assert [(chunk.chunk_type, chunk.start_line, chunk.end_line, chunk.heading_path) for chunk in result.chunks] == [
        ("text_window", 1, 2, []),
        ("markdown_section", 3, 5, ["Title"]),
    ]


def test_empty_text_returns_no_chunks_and_invalid_limits_fail() -> None:
    assert chunk_text_artifact("\n\n", artifact_id="artifact_empty").chunks == []

    with pytest.raises(ValueError, match="max_chunk_chars"):
        chunk_text_artifact("text", artifact_id="artifact_bad", max_chunk_chars=0)

    with pytest.raises(ValueError, match="max_chunk_lines"):
        chunk_text_artifact("text", artifact_id="artifact_bad", max_chunk_lines=0)
