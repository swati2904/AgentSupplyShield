from hashlib import sha256
from typing import Iterable

from pydantic import BaseModel, Field

from app.models import EvidenceSpan


DEFAULT_PREVIEW_MAX_CHARS = 160


class EvidenceSpanRequest(BaseModel):
    start_line: int = Field(ge=1)
    end_line: int = Field(ge=1)
    span_type: str


def create_evidence_span(
    *,
    artifact_id: str,
    raw_text: str,
    start_line: int,
    end_line: int,
    span_type: str,
    preview_max_chars: int = DEFAULT_PREVIEW_MAX_CHARS,
) -> EvidenceSpan:
    if end_line < start_line:
        raise ValueError("Evidence span end_line must be greater than or equal to start_line.")

    selected_text = _extract_line_range(raw_text, start_line, end_line)
    content_hash = _hash_text(selected_text)
    return EvidenceSpan(
        span_id=_span_id(artifact_id, span_type, start_line, end_line, content_hash),
        artifact_id=artifact_id,
        start_line=start_line,
        end_line=end_line,
        preview=_preview_text(selected_text, preview_max_chars),
        span_type=span_type,
        content_hash=content_hash,
    )


def create_evidence_spans(
    *,
    artifact_id: str,
    raw_text: str,
    span_requests: Iterable[EvidenceSpanRequest],
    preview_max_chars: int = DEFAULT_PREVIEW_MAX_CHARS,
) -> list[EvidenceSpan]:
    return [
        create_evidence_span(
            artifact_id=artifact_id,
            raw_text=raw_text,
            start_line=request.start_line,
            end_line=request.end_line,
            span_type=request.span_type,
            preview_max_chars=preview_max_chars,
        )
        for request in span_requests
    ]


def _extract_line_range(raw_text: str, start_line: int, end_line: int) -> str:
    lines = raw_text.splitlines()
    if start_line > len(lines):
        raise ValueError("Evidence span start_line is outside the artifact text.")
    return "\n".join(lines[start_line - 1 : end_line])


def _hash_text(text: str) -> str:
    return sha256(text.encode("utf-8")).hexdigest()


def _span_id(artifact_id: str, span_type: str, start_line: int, end_line: int, content_hash: str) -> str:
    stable_key = f"{artifact_id}:{span_type}:{start_line}:{end_line}:{content_hash}"
    return f"span_{sha256(stable_key.encode('utf-8')).hexdigest()[:16]}"


def _preview_text(text: str, preview_max_chars: int) -> str:
    normalized = " ".join(text.split())
    if preview_max_chars < 1:
        raise ValueError("preview_max_chars must be at least 1.")
    if len(normalized) <= preview_max_chars:
        return normalized
    clipped = normalized[:preview_max_chars].rstrip()
    last_space = clipped.rfind(" ")
    if last_space > 0:
        return clipped[:last_space]
    return clipped
