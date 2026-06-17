import re
from hashlib import sha256
from typing import Literal

from pydantic import BaseModel, Field


DEFAULT_MAX_CHUNK_CHARS = 1_200
DEFAULT_MAX_CHUNK_LINES = 80
HEADING_PATTERN = re.compile(r"^(#{1,6})\s+(.+?)\s*$")

ChunkType = Literal["markdown_section", "paragraph", "text_window"]


class TextChunk(BaseModel):
    chunk_id: str
    artifact_id: str
    path: str | None = None
    chunk_index: int = Field(ge=0)
    start_line: int = Field(ge=1)
    end_line: int = Field(ge=1)
    chunk_type: ChunkType
    heading_path: list[str] = Field(default_factory=list)
    text: str
    content_hash: str


class ChunkingResult(BaseModel):
    artifact_id: str
    path: str | None = None
    chunks: list[TextChunk] = Field(default_factory=list)


def chunk_text_artifact(
    raw_text: str,
    *,
    artifact_id: str,
    path: str | None = None,
    max_chunk_chars: int = DEFAULT_MAX_CHUNK_CHARS,
    max_chunk_lines: int = DEFAULT_MAX_CHUNK_LINES,
) -> ChunkingResult:
    if max_chunk_chars < 1:
        raise ValueError("max_chunk_chars must be at least 1.")
    if max_chunk_lines < 1:
        raise ValueError("max_chunk_lines must be at least 1.")

    lines = raw_text.splitlines()
    if not any(line.strip() for line in lines):
        return ChunkingResult(artifact_id=artifact_id, path=path)

    candidates = _markdown_section_candidates(lines)
    if not candidates:
        candidates = _paragraph_candidates(lines)

    chunks: list[TextChunk] = []
    for start_line, end_line, chunk_type, heading_path in candidates:
        for split_start, split_end in _split_range(
            lines,
            start_line,
            end_line,
            max_chunk_chars=max_chunk_chars,
            max_chunk_lines=max_chunk_lines,
        ):
            text = _extract_lines(lines, split_start, split_end)
            chunks.append(
                _build_chunk(
                    artifact_id=artifact_id,
                    path=path,
                    chunk_index=len(chunks),
                    start_line=split_start,
                    end_line=split_end,
                    chunk_type=chunk_type,
                    heading_path=heading_path,
                    text=text,
                )
            )

    return ChunkingResult(artifact_id=artifact_id, path=path, chunks=chunks)


def _markdown_section_candidates(lines: list[str]) -> list[tuple[int, int, ChunkType, list[str]]]:
    candidates: list[tuple[int, int, ChunkType, list[str]]] = []
    heading_stack: list[tuple[int, str]] = []
    current_start_line: int | None = None
    current_heading_path: list[str] = []
    found_heading = False

    for line_number, line in enumerate(lines, start=1):
        heading_match = HEADING_PATTERN.match(line)
        if not heading_match:
            continue

        if current_start_line is not None and line_number > current_start_line:
            candidates.append((current_start_line, line_number - 1, "markdown_section", current_heading_path))
        elif not found_heading and line_number > 1:
            preamble_end = line_number - 1
            if any(line.strip() for line in lines[:preamble_end]):
                candidates.append((1, preamble_end, "text_window", []))

        found_heading = True
        level = len(heading_match.group(1))
        text = heading_match.group(2).strip()
        while heading_stack and heading_stack[-1][0] >= level:
            heading_stack.pop()
        heading_stack.append((level, text))
        current_start_line = line_number
        current_heading_path = [heading_text for _, heading_text in heading_stack]

    if current_start_line is not None:
        candidates.append((current_start_line, len(lines), "markdown_section", current_heading_path))

    return [
        (start, end, chunk_type, heading_path)
        for start, end, chunk_type, heading_path in candidates
        if start <= end and any(line.strip() for line in lines[start - 1 : end])
    ]


def _paragraph_candidates(lines: list[str]) -> list[tuple[int, int, ChunkType, list[str]]]:
    candidates: list[tuple[int, int, ChunkType, list[str]]] = []
    start_line: int | None = None
    for line_number, line in enumerate(lines, start=1):
        if line.strip():
            if start_line is None:
                start_line = line_number
            continue
        if start_line is not None:
            candidates.append((start_line, line_number - 1, "paragraph", []))
            start_line = None

    if start_line is not None:
        candidates.append((start_line, len(lines), "paragraph", []))
    return candidates


def _split_range(
    lines: list[str],
    start_line: int,
    end_line: int,
    *,
    max_chunk_chars: int,
    max_chunk_lines: int,
) -> list[tuple[int, int]]:
    ranges: list[tuple[int, int]] = []
    current_start = start_line
    current_chars = 0
    current_lines = 0

    for line_number in range(start_line, end_line + 1):
        line_text = lines[line_number - 1]
        line_chars = len(line_text) + (1 if current_lines else 0)
        would_exceed_lines = current_lines >= max_chunk_lines
        would_exceed_chars = current_lines > 0 and current_chars + line_chars > max_chunk_chars

        if would_exceed_lines or would_exceed_chars:
            ranges.append((current_start, line_number - 1))
            current_start = line_number
            current_chars = 0
            current_lines = 0

        current_chars += len(line_text) + (1 if current_lines else 0)
        current_lines += 1

    if current_lines:
        ranges.append((current_start, end_line))
    return ranges


def _build_chunk(
    *,
    artifact_id: str,
    path: str | None,
    chunk_index: int,
    start_line: int,
    end_line: int,
    chunk_type: ChunkType,
    heading_path: list[str],
    text: str,
) -> TextChunk:
    content_hash = sha256(text.encode("utf-8")).hexdigest()
    stable_key = f"{artifact_id}:{chunk_index}:{start_line}:{end_line}:{content_hash}"
    return TextChunk(
        chunk_id=f"chunk_{sha256(stable_key.encode('utf-8')).hexdigest()[:16]}",
        artifact_id=artifact_id,
        path=path,
        chunk_index=chunk_index,
        start_line=start_line,
        end_line=end_line,
        chunk_type=chunk_type,
        heading_path=heading_path,
        text=text,
        content_hash=content_hash,
    )


def _extract_lines(lines: list[str], start_line: int, end_line: int) -> str:
    return "\n".join(lines[start_line - 1 : end_line]).strip()
