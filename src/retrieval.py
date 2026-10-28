import hashlib
import json
import math
import re
from datetime import datetime, timezone
from pathlib import Path


class RetrievalError(ValueError):
    pass


REQUIRED_CHUNK_FIELDS = (
    "chunk_id", "document_id", "source_id", "section_path", "text", "cwe_ids",
    "programming_languages", "content_sha256", "raw_source_sha256",
)


def filter_eligible_chunks(
    chunks: list[dict[str, object]],
    cwe_id: int,
    programming_language: str,
) -> list[dict[str, object]]:
    """Return chunks matching the mandatory CWE and language metadata gate."""
    eligible = []
    for chunk in chunks:
        _validate_chunk(chunk)
        if cwe_id in chunk["cwe_ids"] and programming_language in chunk["programming_languages"]:
            eligible.append(chunk)
    return eligible


def canonical_ranking_text(chunk: dict[str, object]) -> str:
    """Build the frozen sparse/dense ranking text for one admitted chunk."""
    _validate_chunk(chunk)
    return f"{' > '.join(chunk['section_path'])}\n{chunk['text']}"


def rank_bm25(query: str, chunks: list[dict[str, object]]) -> list[dict[str, object]]:
    """Rank chunks with a deterministic, dependency-free BM25 implementation."""
    if not isinstance(query, str) or not query.strip():
        raise RetrievalError("query must be a non-empty string")
    if not chunks:
        return []
    texts = [canonical_ranking_text(chunk) for chunk in chunks]
    tokenized = [_tokens(text) for text in texts]
    query_tokens = _tokens(query)
    document_frequency = {
        token: sum(token in set(tokens) for tokens in tokenized)
        for token in set(query_tokens)
    }
    average_length = sum(len(tokens) for tokens in tokenized) / len(tokenized)
    ranked = []
    for chunk, tokens in zip(chunks, tokenized):
        score = _bm25_score(tokens, query_tokens, document_frequency, len(tokenized), average_length)
        ranked.append({"chunk_id": chunk["chunk_id"], "sparse_score": score})
    ranked.sort(key=lambda item: (-item["sparse_score"], item["chunk_id"]))
    for rank, item in enumerate(ranked, start=1):
        item["sparse_rank"] = rank
    return ranked


def fuse_rankings(
    sparse: list[dict[str, object]],
    dense: list[dict[str, object]],
    rrf_k: int,
    top_k: int,
) -> list[dict[str, object]]:
    """Fuse sparse and dense rankings with RRF and deterministic tie-breaking."""
    if rrf_k < 1 or top_k < 1:
        raise RetrievalError("rrf_k and top_k must be positive integers")
    merged: dict[str, dict[str, object]] = {}
    _merge_ranking(merged, sparse, "sparse")
    _merge_ranking(merged, dense, "dense")
    for item in merged.values():
        score = 0.0
        for name in ("sparse_rank", "dense_rank"):
            rank = item.get(name)
            if rank is not None:
                score += 1 / (rrf_k + rank)
        item["rrf_score"] = score
    fused = sorted(merged.values(), key=lambda item: (-item["rrf_score"], item["chunk_id"]))[:top_k]
    for rank, item in enumerate(fused, start=1):
        item["final_rank"] = rank
    return fused


def build_retrieval_record(
    corpus_id: str,
    retrieval_config: dict[str, object],
    embedding_model_name: str,
    embedding_model_digest: str,
    query: str,
    metadata_filter: dict[str, object],
    results: list[dict[str, object]],
) -> dict[str, object]:
    """Build one attributable retrieval record without changing any verdict."""
    if not all(isinstance(value, str) and value.strip() for value in (
        corpus_id, embedding_model_name, embedding_model_digest, query,
    )):
        raise RetrievalError("corpus, model, digest, and query must be non-empty strings")
    if not isinstance(retrieval_config, dict) or not isinstance(metadata_filter, dict):
        raise RetrievalError("retrieval_config and metadata_filter must be objects")
    output_results = [_result_provenance(result) for result in results]
    return {
        "retrieval_schema_version": 1,
        "status": "passed" if output_results else "empty",
        "corpus_id": corpus_id,
        "retrieval_config_sha256": _canonical_hash(retrieval_config),
        "embedding_model_name": embedding_model_name,
        "embedding_model_digest": embedding_model_digest,
        "query_sha256": _hash(query.encode("utf-8")),
        "query": query,
        "retrieval_timestamp_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "metadata_filter": metadata_filter,
        "rrf_k": retrieval_config.get("rrf_k"),
        "top_k": retrieval_config.get("top_k"),
        "results": output_results,
    }


def write_retrieval_records(path: Path, records: list[dict[str, object]]) -> None:
    """Write immutable JSONL evidence and refuse to overwrite an existing run."""
    if path.exists():
        raise RetrievalError(f"retrieval output already exists: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "".join(json.dumps(record, sort_keys=True) + "\n" for record in records),
        encoding="utf-8",
    )


def _validate_chunk(chunk: dict[str, object]) -> None:
    if not isinstance(chunk, dict):
        raise RetrievalError("chunk must be an object")
    for field in REQUIRED_CHUNK_FIELDS:
        if chunk.get(field) in (None, "", []):
            raise RetrievalError(f"chunk field is required: {field}")
    if not isinstance(chunk["chunk_id"], str):
        raise RetrievalError("chunk_id must be a string")
    if not isinstance(chunk["section_path"], list) or not all(isinstance(item, str) for item in chunk["section_path"]):
        raise RetrievalError("section_path must be a list of strings")
    if not isinstance(chunk["cwe_ids"], list) or not all(isinstance(item, int) for item in chunk["cwe_ids"]):
        raise RetrievalError("cwe_ids must be a list of integers")
    if not isinstance(chunk["programming_languages"], list) or not all(
        isinstance(item, str) for item in chunk["programming_languages"]
    ):
        raise RetrievalError("programming_languages must be a list of strings")


def _tokens(text: str) -> list[str]:
    return re.findall(r"[a-z0-9]+", text.casefold())


def _bm25_score(
    document: list[str],
    query: list[str],
    document_frequency: dict[str, int],
    document_count: int,
    average_length: float,
) -> float:
    score = 0.0
    frequencies = {token: document.count(token) for token in set(query)}
    for token in set(query):
        frequency = frequencies[token]
        if frequency == 0:
            continue
        inverse_frequency = math.log(1 + (document_count - document_frequency[token] + 0.5) / (document_frequency[token] + 0.5))
        denominator = frequency + 1.5 * (1 - 0.75 + 0.75 * len(document) / average_length)
        score += inverse_frequency * frequency * 2.5 / denominator
    return score


def _merge_ranking(
    merged: dict[str, dict[str, object]],
    ranking: list[dict[str, object]],
    prefix: str,
) -> None:
    for item in ranking:
        chunk_id = item.get("chunk_id")
        rank = item.get(f"{prefix}_rank")
        score = item.get(f"{prefix}_score")
        if not isinstance(chunk_id, str) or not isinstance(rank, int) or rank < 1:
            raise RetrievalError(f"invalid {prefix} ranking entry")
        if not isinstance(score, (int, float)):
            raise RetrievalError(f"invalid {prefix} score")
        merged.setdefault(chunk_id, {"chunk_id": chunk_id}).update({
            f"{prefix}_rank": rank,
            f"{prefix}_score": score,
        })


def _result_provenance(result: dict[str, object]) -> dict[str, object]:
    _validate_chunk(result)
    required = ("final_rank", "sparse_rank", "sparse_score", "dense_rank", "dense_score", "rrf_score")
    for field in required:
        if field not in result:
            raise RetrievalError(f"result field is required: {field}")
    return {field: result[field] for field in (
        "final_rank", "chunk_id", "document_id", "source_id", "section_path",
        "content_sha256", "raw_source_sha256", "sparse_rank", "sparse_score",
        "dense_rank", "dense_score", "rrf_score",
    )}


def _hash(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _canonical_hash(value: object) -> str:
    return _hash(json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8"))
