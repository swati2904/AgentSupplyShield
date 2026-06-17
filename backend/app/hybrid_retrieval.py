import json
import math
import re
from collections.abc import Iterable
from hashlib import sha256

from pydantic import BaseModel, Field

from app.chunking import TextChunk
from app.embedding_strategy import (
    ChunkEmbeddingRecord,
    DeterministicHashEmbeddingProvider,
    EmbeddingProvider,
    QueryEmbeddingRecord,
    build_chunk_embedding_records,
    build_query_embedding_record,
)
from app.lexical_retrieval import LexicalRetrievalHit, retrieve_chunks_lexically


HYBRID_RETRIEVAL_VERSION = "hybrid-retrieval/v0.1"
DEFAULT_HYBRID_MAX_RESULTS = 5
DEFAULT_HYBRID_SNIPPET_CHARS = 240
WHITESPACE_PATTERN = re.compile(r"\s+")


class HybridRetrievalHit(BaseModel):
    chunk_id: str
    artifact_id: str
    path: str | None = None
    chunk_index: int = Field(ge=0)
    start_line: int = Field(ge=1)
    end_line: int = Field(ge=1)
    heading_path: list[str] = Field(default_factory=list)
    hybrid_score: float = Field(gt=0)
    lexical_score: float = Field(ge=0)
    normalized_lexical_score: float = Field(ge=0)
    embedding_score: float = Field(ge=0)
    matched_terms: list[str] = Field(default_factory=list)
    snippet: str
    content_hash: str
    metadata_hash: str
    embedding_hash: str


class HybridRetrievalResult(BaseModel):
    query_hash: str
    query_terms: list[str] = Field(default_factory=list)
    result_count: int = Field(ge=0)
    lexical_weight: float = Field(ge=0)
    embedding_weight: float = Field(ge=0)
    embedding_provider: str
    embedding_model_name: str
    retrieval_version: str = HYBRID_RETRIEVAL_VERSION
    hits: list[HybridRetrievalHit] = Field(default_factory=list)


def retrieve_chunks_hybrid(
    query: str,
    chunks: Iterable[TextChunk],
    *,
    provider: EmbeddingProvider | None = None,
    max_results: int = DEFAULT_HYBRID_MAX_RESULTS,
    lexical_weight: float = 0.6,
    embedding_weight: float = 0.4,
    snippet_chars: int = DEFAULT_HYBRID_SNIPPET_CHARS,
) -> HybridRetrievalResult:
    _validate_retrieval_inputs(max_results, lexical_weight, embedding_weight, snippet_chars)
    embedding_provider = provider or DeterministicHashEmbeddingProvider()
    query_hash = sha256(query.encode("utf-8")).hexdigest()
    chunks_list = list(chunks)

    lexical_result = retrieve_chunks_lexically(
        query,
        chunks_list,
        max_results=max(len(chunks_list), 1),
        snippet_chars=snippet_chars,
    )
    if not lexical_result.query_terms:
        return HybridRetrievalResult(
            query_hash=query_hash,
            query_terms=[],
            result_count=0,
            lexical_weight=lexical_weight,
            embedding_weight=embedding_weight,
            embedding_provider=embedding_provider.config.provider,
            embedding_model_name=embedding_provider.config.model_name,
            hits=[],
        )

    lexical_hits_by_chunk_id = {hit.chunk_id: hit for hit in lexical_result.hits}
    max_lexical_score = max((hit.score for hit in lexical_result.hits), default=0.0)
    query_embedding = build_query_embedding_record(query, embedding_provider)
    chunk_embeddings = build_chunk_embedding_records(chunks_list, embedding_provider)
    embeddings_by_chunk_id = {record.chunk_id: record for record in chunk_embeddings}
    scored_hits: list[tuple[float, HybridRetrievalHit]] = []

    for chunk in chunks_list:
        embedding_record = embeddings_by_chunk_id[chunk.chunk_id]
        lexical_hit = lexical_hits_by_chunk_id.get(chunk.chunk_id)
        hit = _build_hybrid_hit(
            chunk=chunk,
            lexical_hit=lexical_hit,
            embedding_record=embedding_record,
            query_embedding=query_embedding,
            max_lexical_score=max_lexical_score,
            lexical_weight=lexical_weight,
            embedding_weight=embedding_weight,
            snippet_chars=snippet_chars,
        )
        if hit is not None:
            scored_hits.append((hit.hybrid_score, hit))

    hits = [
        hit
        for _, hit in sorted(
            scored_hits,
            key=lambda scored_hit: (
                -scored_hit[1].hybrid_score,
                -scored_hit[1].normalized_lexical_score,
                -scored_hit[1].embedding_score,
                scored_hit[1].chunk_index,
                scored_hit[1].chunk_id,
            ),
        )[:max_results]
    ]
    return HybridRetrievalResult(
        query_hash=query_hash,
        query_terms=lexical_result.query_terms,
        result_count=len(hits),
        lexical_weight=lexical_weight,
        embedding_weight=embedding_weight,
        embedding_provider=embedding_provider.config.provider,
        embedding_model_name=embedding_provider.config.model_name,
        hits=hits,
    )


def _build_hybrid_hit(
    *,
    chunk: TextChunk,
    lexical_hit: LexicalRetrievalHit | None,
    embedding_record: ChunkEmbeddingRecord,
    query_embedding: QueryEmbeddingRecord,
    max_lexical_score: float,
    lexical_weight: float,
    embedding_weight: float,
    snippet_chars: int,
) -> HybridRetrievalHit | None:
    lexical_score = lexical_hit.score if lexical_hit else 0.0
    normalized_lexical_score = lexical_score / max_lexical_score if max_lexical_score > 0 else 0.0
    embedding_score = max(0.0, _cosine_similarity(query_embedding.vector, embedding_record.vector))
    hybrid_score = lexical_weight * normalized_lexical_score + embedding_weight * embedding_score
    if hybrid_score <= 0:
        return None

    return HybridRetrievalHit(
        chunk_id=embedding_record.chunk_id,
        artifact_id=embedding_record.artifact_id,
        path=embedding_record.path,
        chunk_index=embedding_record.chunk_index,
        start_line=embedding_record.start_line,
        end_line=embedding_record.end_line,
        heading_path=embedding_record.heading_path,
        hybrid_score=round(hybrid_score, 6),
        lexical_score=round(lexical_score, 6),
        normalized_lexical_score=round(normalized_lexical_score, 6),
        embedding_score=round(embedding_score, 6),
        matched_terms=lexical_hit.matched_terms if lexical_hit else [],
        snippet=lexical_hit.snippet if lexical_hit else _snippet(chunk.text, snippet_chars),
        content_hash=embedding_record.content_hash,
        metadata_hash=embedding_record.metadata_hash,
        embedding_hash=embedding_record.embedding_hash,
    )


def hybrid_retrieval_to_json(result: HybridRetrievalResult) -> str:
    return json.dumps(result.model_dump(mode="json"), indent=2, sort_keys=True) + "\n"


def _cosine_similarity(first: list[float], second: list[float]) -> float:
    if len(first) != len(second):
        raise ValueError("embedding vectors must have the same dimensions.")
    first_magnitude = math.sqrt(sum(value * value for value in first))
    second_magnitude = math.sqrt(sum(value * value for value in second))
    if first_magnitude == 0 or second_magnitude == 0:
        return 0.0
    return sum(left * right for left, right in zip(first, second, strict=True)) / (
        first_magnitude * second_magnitude
    )


def _snippet(text: str, snippet_chars: int) -> str:
    compact_text = WHITESPACE_PATTERN.sub(" ", text).strip()
    if len(compact_text) <= snippet_chars:
        return compact_text
    return f"{compact_text[:snippet_chars].strip()}..."


def _validate_retrieval_inputs(
    max_results: int,
    lexical_weight: float,
    embedding_weight: float,
    snippet_chars: int,
) -> None:
    if max_results < 1:
        raise ValueError("max_results must be at least 1.")
    if lexical_weight < 0:
        raise ValueError("lexical_weight must be greater than or equal to 0.")
    if embedding_weight < 0:
        raise ValueError("embedding_weight must be greater than or equal to 0.")
    if lexical_weight + embedding_weight <= 0:
        raise ValueError("at least one retrieval weight must be greater than 0.")
    if snippet_chars < 1:
        raise ValueError("snippet_chars must be at least 1.")
