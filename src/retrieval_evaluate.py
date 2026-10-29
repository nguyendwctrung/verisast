import hashlib
import json
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from ollama_client import embed, metadata
from retrieval import build_retrieval_record, rank_hybrid, write_retrieval_records


class EvaluationError(ValueError):
    pass


MetadataReader = Callable[[str, str, int], dict[str, object]]
EmbeddingFunction = Callable[[str, str, list[str], int, str], list[list[object]]]


def load_projected_chunks(chunks_path: Path, documents_path: Path) -> list[dict[str, object]]:
    """Join immutable chunks to admitted document metadata in memory."""
    chunks = _read_jsonl(chunks_path)
    documents = _read_jsonl(documents_path)
    by_document = {document.get("document_id"): document for document in documents}
    if len(by_document) != len(documents):
        raise EvaluationError("documents must have unique document_id values")
    chunk_ids = {chunk.get("chunk_id") for chunk in chunks}
    if len(chunk_ids) != len(chunks) or None in chunk_ids:
        raise EvaluationError("chunks must have unique chunk_id values")
    projected = []
    for chunk in chunks:
        document_id = chunk.get("document_id")
        document = by_document.get(document_id)
        if not isinstance(document_id, str) or not isinstance(document, dict):
            raise EvaluationError(f"chunk does not join to one document: {document_id}")
        for field in ("document_version_id", "content_sha256", "raw_source_sha256", "source_id"):
            if chunk.get(field) != document.get(field):
                raise EvaluationError(f"chunk/document mismatch for {field}: {document_id}")
        metadata_fields = ("cwe_ids", "programming_languages")
        if not all(isinstance(document.get(field), list) and document[field] for field in metadata_fields):
            raise EvaluationError(f"document lacks retrieval metadata: {document_id}")
        projected.append({
            **chunk,
            "cwe_ids": document["cwe_ids"],
            "programming_languages": document["programming_languages"],
        })
    return projected


def compute_metrics(
    judgments: list[dict[str, object]],
    returned_chunk_ids: dict[str, list[str]],
    k_values: list[int],
) -> tuple[dict[str, float], list[dict[str, object]]]:
    """Calculate macro-averaged binary-relevance Hit@k and Recall@k."""
    if not judgments or not k_values or any(not isinstance(value, int) or value < 1 for value in k_values):
        raise EvaluationError("judgments and positive k values are required")
    rows = []
    totals = {f"{metric}@{value}": 0.0 for metric in ("Hit", "Recall") for value in k_values}
    for judgment in judgments:
        query_id = judgment.get("query_id")
        relevant = judgment.get("relevant_chunk_ids")
        if not isinstance(query_id, str) or not isinstance(relevant, list) or not relevant or not all(isinstance(item, str) for item in relevant):
            raise EvaluationError("invalid relevance judgment")
        if query_id not in returned_chunk_ids:
            raise EvaluationError(f"missing retrieval result for query: {query_id}")
        returned = returned_chunk_ids[query_id]
        row: dict[str, object] = {"query_id": query_id, "relevant_chunk_ids": relevant, "returned_chunk_ids": returned}
        relevant_set = set(relevant)
        for value in k_values:
            selected = set(returned[:value])
            hit = float(bool(relevant_set & selected))
            recall = len(relevant_set & selected) / len(relevant_set)
            row[f"Hit@{value}"] = hit
            row[f"Recall@{value}"] = recall
            totals[f"Hit@{value}"] += hit
            totals[f"Recall@{value}"] += recall
        rows.append(row)
    return {name: total / len(judgments) for name, total in totals.items()}, rows


def run(
    protocol_path: Path,
    output: Path,
    metadata_reader: MetadataReader = metadata,
    embedding_function: EmbeddingFunction = embed,
) -> dict[str, object]:
    """Execute one immutable development retrieval evaluation run."""
    if output.exists():
        raise EvaluationError(f"retrieval evaluation output already exists: {output}")
    protocol = _read_object(protocol_path)
    if protocol.get("status") != "preregistered_not_executed":
        raise EvaluationError("protocol must be preregistered_not_executed")
    corpus = _required_object(protocol, "corpus")
    embedding = _required_object(protocol, "embedding")
    metadata_filter = _required_object(protocol, "metadata_filter")
    ranking = _required_object(protocol, "ranking")
    inputs = _required_object(protocol, "inputs")
    manifest_path = _required_path(corpus, "manifest_path")
    chunks_path = _required_path(corpus, "chunks_path")
    documents_path = _required_path(corpus, "documents_path")
    _validate_corpus(manifest_path, chunks_path, documents_path, corpus)
    chunks = load_projected_chunks(chunks_path, documents_path)
    queries_path = _required_path(inputs, "queries_path")
    judgments_path = _required_path(inputs, "relevance_judgments_path")
    queries, judgments = _load_queries_and_judgments(queries_path, judgments_path, chunks, metadata_filter)
    endpoint, model, digest, dimension, timeout, keep_alive = _embedding_settings(embedding)
    observed = metadata_reader(endpoint, model, timeout)
    if observed.get("model_digest") != digest:
        raise EvaluationError("observed embedding model digest does not match protocol")

    output.mkdir(parents=True)
    _snapshot(protocol_path, output / "protocol-snapshot.json")
    _snapshot(queries_path, output / "queries-snapshot.jsonl")
    _snapshot(judgments_path, output / "relevance-judgments-snapshot.jsonl")
    try:
        results_by_query: dict[str, list[str]] = {}
        records = []
        retrieval_config = {"embedding": embedding, "metadata_filter": metadata_filter, "ranking": ranking}
        for query in queries:
            query_text = query["query_text"]
            ranked = rank_hybrid(
                query_text, chunks, int(metadata_filter["cwe_id"]), str(metadata_filter["programming_language"]),
                lambda values: _embed_with_dimension(
                    embedding_function, endpoint, model, values, timeout, keep_alive, dimension
                ),
                int(ranking["rrf_k"]), int(ranking["top_k"]),
            )
            query_id = str(query["query_id"])
            results_by_query[query_id] = [str(item["chunk_id"]) for item in ranked]
            records.append(build_retrieval_record(
                str(corpus["corpus_id"]), retrieval_config, model, digest, query_text,
                metadata_filter, ranked,
            ) | {"query_id": query_id})
        write_retrieval_records(output / "retrieval-records.jsonl", records)
        k_values = _metric_k_values(_required_object(protocol, "metrics"))
        metrics, rows = compute_metrics(judgments, results_by_query, k_values)
        _write_jsonl(output / "per-query-metrics.jsonl", rows)
        (output / "metrics.json").write_text(json.dumps(metrics, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        manifest = {"schema_version": 1, "status": "passed", "created_at": _timestamp(), "query_count": len(queries), "corpus_id": corpus["corpus_id"], "embedding_model_name": model, "embedding_model_digest": digest, "metrics": metrics}
        (output / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        return {"status": "passed", "output": str(output), "query_count": len(queries), "metrics": metrics}
    except Exception as error:
        _write_jsonl(output / "errors.jsonl", [{"status": "error", "error": str(error)}])
        (output / "manifest.json").write_text(json.dumps({"schema_version": 1, "status": "failed", "created_at": _timestamp(), "error": str(error)}, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        raise EvaluationError(str(error)) from error


def _validate_corpus(manifest_path: Path, chunks_path: Path, documents_path: Path, corpus: dict[str, object]) -> None:
    manifest = _read_object(manifest_path)
    if manifest.get("status") != "passed" or manifest.get("corpus_id") != corpus.get("corpus_id"):
        raise EvaluationError("corpus manifest is not the preregistered admitted corpus")
    for field, path in (("chunks_sha256", chunks_path), ("documents_sha256", documents_path)):
        if corpus.get(field) != _hash(path.read_bytes()) or manifest.get(field) != corpus.get(field):
            raise EvaluationError(f"corpus hash mismatch: {field}")


def _load_queries_and_judgments(
    queries_path: Path,
    judgments_path: Path,
    chunks: list[dict[str, object]],
    metadata_filter: dict[str, object],
) -> tuple[list[dict[str, object]], list[dict[str, object]]]:
    queries = _read_jsonl(queries_path)
    judgments = _read_jsonl(judgments_path)
    query_ids = {item.get("query_id") for item in queries}
    judgment_ids = {item.get("query_id") for item in judgments}
    required_cwe = metadata_filter.get("cwe_id")
    required_language = metadata_filter.get("programming_language")
    if len(query_ids) != len(queries) or query_ids != judgment_ids or not all(
        isinstance(item.get("query_id"), str)
        and isinstance(item.get("query_text"), str)
        and item["query_text"].strip()
        and item.get("cwe_id") == required_cwe
        and item.get("programming_language") == required_language
        for item in queries
    ):
        raise EvaluationError("queries and judgments must have matching unique IDs")
    chunk_ids = {item["chunk_id"] for item in chunks}
    for judgment in judgments:
        relevant = judgment.get("relevant_chunk_ids")
        if not isinstance(relevant, list) or not relevant or not all(item in chunk_ids for item in relevant):
            raise EvaluationError("judgment references an unadmitted chunk")
    return queries, judgments


def _embedding_settings(embedding: dict[str, object]) -> tuple[str, str, str, int, int, str]:
    values = (embedding.get("endpoint"), embedding.get("model_name"), embedding.get("model_digest"), embedding.get("dimension"), embedding.get("timeout_seconds"), embedding.get("keep_alive"))
    if not isinstance(values[0], str) or not isinstance(values[1], str) or not isinstance(values[2], str) or not isinstance(values[3], int) or values[3] < 1 or not isinstance(values[4], int) or not isinstance(values[5], str):
        raise EvaluationError("invalid embedding configuration")
    return values


def _embed_with_dimension(
    embedding_function: EmbeddingFunction,
    endpoint: str,
    model: str,
    inputs: list[str],
    timeout: int,
    keep_alive: str,
    dimension: int,
) -> list[list[object]]:
    vectors = embedding_function(endpoint, model, inputs, timeout, keep_alive)
    if not all(isinstance(vector, list) and len(vector) == dimension for vector in vectors):
        raise EvaluationError("embedding dimension does not match protocol")
    return vectors


def _metric_k_values(metrics: dict[str, object]) -> list[int]:
    primary = metrics.get("primary")
    if not isinstance(primary, list):
        raise EvaluationError("metrics.primary must be a list")
    values = sorted({int(name.split("@", 1)[1]) for name in primary if isinstance(name, str) and "@" in name})
    if not values:
        raise EvaluationError("metrics.primary must contain k values")
    return values


def _read_jsonl(path: Path) -> list[dict[str, object]]:
    try:
        rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    except (OSError, json.JSONDecodeError) as error:
        raise EvaluationError(str(error)) from error
    if not all(isinstance(row, dict) for row in rows):
        raise EvaluationError(f"JSONL records must be objects: {path}")
    return rows


def _read_object(path: Path) -> dict[str, object]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise EvaluationError(str(error)) from error
    if not isinstance(value, dict):
        raise EvaluationError(f"JSON object required: {path}")
    return value


def _required_object(parent: dict[str, object], name: str) -> dict[str, object]:
    value = parent.get(name)
    if not isinstance(value, dict):
        raise EvaluationError(f"object is required: {name}")
    return value


def _required_path(parent: dict[str, object], name: str) -> Path:
    value = parent.get(name)
    if not isinstance(value, str) or not value:
        raise EvaluationError(f"path is required: {name}")
    return Path(value)


def _snapshot(source: Path, destination: Path) -> None:
    shutil.copyfile(source, destination)


def _write_jsonl(path: Path, rows: list[dict[str, object]]) -> None:
    path.write_text("".join(json.dumps(row, sort_keys=True) + "\n" for row in rows), encoding="utf-8")


def _hash(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _timestamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
