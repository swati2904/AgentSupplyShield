import pytest

from app.evidence import EvidenceSpanRequest, create_evidence_span, create_evidence_spans


def test_create_evidence_span_preserves_line_range_and_stable_hash() -> None:
    raw_text = "first line\nsecond line has evidence\nthird line has evidence\nfourth line"

    first = create_evidence_span(
        artifact_id="artifact_readme",
        raw_text=raw_text,
        start_line=2,
        end_line=3,
        span_type="paragraph",
    )
    second = create_evidence_span(
        artifact_id="artifact_readme",
        raw_text=raw_text,
        start_line=2,
        end_line=3,
        span_type="paragraph",
    )

    assert first.start_line == 2
    assert first.end_line == 3
    assert first.preview == "second line has evidence third line has evidence"
    assert first.content_hash == second.content_hash
    assert first.span_id == second.span_id


def test_create_evidence_span_keeps_only_bounded_preview() -> None:
    raw_text = "line one\n" + "sensitive-looking but fake content " * 20

    span = create_evidence_span(
        artifact_id="artifact_readme",
        raw_text=raw_text,
        start_line=2,
        end_line=2,
        span_type="long_line",
        preview_max_chars=40,
    )

    dumped = span.model_dump()
    assert "text" not in dumped
    assert dumped["preview"] == "sensitive-looking but fake content"
    assert len(dumped["preview"]) <= 40


def test_create_evidence_spans_from_requests() -> None:
    raw_text = "# Heading\n\nA paragraph with evidence.\nAnother paragraph."
    requests = [
        EvidenceSpanRequest(start_line=1, end_line=1, span_type="heading"),
        EvidenceSpanRequest(start_line=3, end_line=4, span_type="paragraph"),
    ]

    spans = create_evidence_spans(artifact_id="artifact_markdown", raw_text=raw_text, span_requests=requests)

    assert [(span.span_type, span.start_line, span.end_line) for span in spans] == [
        ("heading", 1, 1),
        ("paragraph", 3, 4),
    ]
    assert spans[0].preview == "# Heading"
    assert spans[1].preview == "A paragraph with evidence. Another paragraph."


def test_create_evidence_span_rejects_invalid_ranges() -> None:
    with pytest.raises(ValueError, match="end_line"):
        create_evidence_span(
            artifact_id="artifact_readme",
            raw_text="one\ntwo",
            start_line=2,
            end_line=1,
            span_type="invalid",
        )

    with pytest.raises(ValueError, match="outside"):
        create_evidence_span(
            artifact_id="artifact_readme",
            raw_text="one\ntwo",
            start_line=3,
            end_line=3,
            span_type="invalid",
        )
