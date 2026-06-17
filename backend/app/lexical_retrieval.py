import math
import re
from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass

from pydantic import BaseModel, Field

from app.chunk_metadata import ChunkMetadata, build_chunk_metadata
from app.chunking import TextChunk


DEFAULT_MAX_RESULTS = 5
DEFAULT_SNIPPET_CHARS = 240
TOKEN_PATTERN = re.compile(r"[a-z0-9]+")
WHITESPACE_PATTERN = re.compile(r"\s+")


class LexicalRetrievalHit(BaseModel):
    chunk_id: str
    artifact_id: str
    path: str | None = None
    chunk_index: int = Field(ge=0)
    start_line: int = Field(ge=1)
    end_line: int = Field(ge=1)
    heading_path: list[str] = Field(default_factory=list)
    score: float = Field(gt=0)
    matched_terms: list[str] = Field(default_factory=list)
    snippet: str
    content_hash: str
    metadata_hash: str


class LexicalRetrievalResult(BaseModel):
    query: str
    query_terms: list[str] = Field(default_factory=list)
    result_count: int = Field(ge=0)
    hits: list[LexicalRetrievalHit] = Field(default_factory=list)


@dataclass(frozen=True)
class _LexicalDocument:
    chunk: TextChunk
    metadata: ChunkMetadata
    text_tokens: list[str]
    text_counts: Counter[str]
    context_counts: Counter[str]
    normalized_text: str
    normalized_context: str


def retrieve_chunks_lexically(
    query: str,
    chunks: Iterable[TextChunk],
    *,
    max_results: int = DEFAULT_MAX_RESULTS,
    snippet_chars: int = DEFAULT_SNIPPET_CHARS,
) -> LexicalRetrievalResult:
    if max_results < 1:
        raise ValueError("max_results must be at least 1.")
    if snippet_chars < 1:
        raise ValueError("snippet_chars must be at least 1.")

    query_terms = _unique_preserving_order(_tokenize(query))
    if not query_terms:
        return LexicalRetrievalResult(query=query, query_terms=[], result_count=0, hits=[])

    documents = [_build_lexical_document(chunk) for chunk in chunks]
    if not documents:
        return LexicalRetrievalResult(query=query, query_terms=query_terms, result_count=0, hits=[])

    document_frequency = _document_frequency(documents, query_terms)
    average_length = max(sum(len(document.text_tokens) for document in documents) / len(documents), 1.0)
    scored_hits: list[tuple[float, LexicalRetrievalHit]] = []

    for document in documents:
        score = _score_document(document, query_terms, document_frequency, len(documents), average_length)
        if score <= 0:
            continue

        matched_terms = [
            term for term in query_terms if document.text_counts[term] > 0 or document.context_counts[term] > 0
        ]
        scored_hits.append((score, _build_hit(document, score, matched_terms, snippet_chars)))

    hits = [
        hit
        for _, hit in sorted(
            scored_hits,
            key=lambda scored_hit: (
                -scored_hit[0],
                scored_hit[1].chunk_index,
                scored_hit[1].chunk_id,
            ),
        )[:max_results]
    ]
    return LexicalRetrievalResult(query=query, query_terms=query_terms, result_count=len(hits), hits=hits)


def _build_lexical_document(chunk: TextChunk) -> _LexicalDocument:
    metadata = build_chunk_metadata(chunk)
    context = " ".join([chunk.path or "", *chunk.heading_path])
    text_tokens = _tokenize(chunk.text)
    context_tokens = _tokenize(context)
    return _LexicalDocument(
        chunk=chunk,
        metadata=metadata,
        text_tokens=text_tokens,
        text_counts=Counter(text_tokens),
        context_counts=Counter(context_tokens),
        normalized_text=" ".join(text_tokens),
        normalized_context=" ".join(context_tokens),
    )


def _score_document(
    document: _LexicalDocument,
    query_terms: list[str],
    document_frequency: Counter[str],
    document_count: int,
    average_length: float,
) -> float:
    score = 0.0
    document_length = max(len(document.text_tokens), 1)
    normalized_query = " ".join(query_terms)

    for term in query_terms:
        text_count = document.text_counts[term]
        context_count = document.context_counts[term]
        if text_count == 0 and context_count == 0:
            continue

        inverse_document_frequency = math.log(
            1 + (document_count - document_frequency[term] + 0.5) / (document_frequency[term] + 0.5)
        )
        score += _bm25_term_score(text_count, document_length, average_length, inverse_document_frequency)
        score += context_count * inverse_document_frequency * 0.35

    if normalized_query and normalized_query in document.normalized_text:
        score += 1.0
    if normalized_query and normalized_query in document.normalized_context:
        score += 0.4

    return score


def _bm25_term_score(term_count: int, document_length: int, average_length: float, idf: float) -> float:
    if term_count <= 0:
        return 0.0
    k1 = 1.2
    b = 0.75
    denominator = term_count + k1 * (1 - b + b * document_length / average_length)
    return idf * ((term_count * (k1 + 1)) / denominator)


def _build_hit(
    document: _LexicalDocument,
    score: float,
    matched_terms: list[str],
    snippet_chars: int,
) -> LexicalRetrievalHit:
    metadata = document.metadata
    return LexicalRetrievalHit(
        chunk_id=metadata.chunk_id,
        artifact_id=metadata.artifact_id,
        path=metadata.path,
        chunk_index=metadata.chunk_index,
        start_line=metadata.start_line,
        end_line=metadata.end_line,
        heading_path=metadata.heading_path,
        score=round(score, 6),
        matched_terms=matched_terms,
        snippet=_snippet(document.chunk.text, matched_terms, snippet_chars),
        content_hash=metadata.content_hash,
        metadata_hash=metadata.metadata_hash,
    )


def _document_frequency(documents: list[_LexicalDocument], query_terms: list[str]) -> Counter[str]:
    frequencies: Counter[str] = Counter()
    for document in documents:
        document_terms = set(document.text_counts) | set(document.context_counts)
        for term in query_terms:
            if term in document_terms:
                frequencies[term] += 1
    return frequencies


def _snippet(text: str, terms: list[str], snippet_chars: int) -> str:
    compact_text = WHITESPACE_PATTERN.sub(" ", text).strip()
    if len(compact_text) <= snippet_chars:
        return compact_text

    lower_text = compact_text.lower()
    positions = [position for term in terms if (position := lower_text.find(term)) >= 0]
    anchor = min(positions) if positions else 0
    start = max(anchor - snippet_chars // 3, 0)
    end = min(start + snippet_chars, len(compact_text))
    start = max(end - snippet_chars, 0)
    snippet = compact_text[start:end].strip()
    if start > 0:
        snippet = f"...{snippet}"
    if end < len(compact_text):
        snippet = f"{snippet}..."
    return snippet


def _tokenize(text: str) -> list[str]:
    normalized = text.lower().replace("_", " ").replace("-", " ")
    return [_normalize_token(token) for token in TOKEN_PATTERN.findall(normalized)]


def _normalize_token(token: str) -> str:
    if len(token) > 4 and token.endswith("ies"):
        return f"{token[:-3]}y"
    if len(token) > 3 and token.endswith("s") and not token.endswith(("ss", "us", "is")):
        return token[:-1]
    return token


def _unique_preserving_order(values: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    unique_values: list[str] = []
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        unique_values.append(value)
    return unique_values
