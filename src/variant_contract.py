import copy
import hashlib
import json
import math
import re


class VariantContractError(ValueError):
    pass


_FORBIDDEN_KNOWLEDGE = re.compile(
    r"\b(?:advisory|patch|vulnerable|fixed|cve-\d{4}-\d+)\b",
    re.IGNORECASE,
)
_RESULT_IDENTIFIERS = (
    "chunk_id",
    "document_id",
    "source_id",
    "section_path",
    "content_sha256",
    "raw_source_sha256",
)
_SCORE_FIELDS = ("sparse_score", "dense_score", "rrf_score")


def build_variant_c_request(
    base_request: dict[str, object],
    retrieval_bundle: dict[str, object],
) -> dict[str, object]:
    """Copy a B request and replace only its validated knowledge bundle."""
    if not isinstance(base_request, dict):
        raise VariantContractError("base request must be an object")
    knowledge_items = retrieval_bundle.get("knowledge_items")
    if not isinstance(knowledge_items, list) or not knowledge_items:
        raise VariantContractError("retrieval bundle must contain knowledge items")
    request = copy.deepcopy(base_request)
    request["retrieved_knowledge"] = copy.deepcopy(knowledge_items)
    return request


def validate_retrieval_bundle(
    contract: dict[str, object],
    candidate: dict[str, object],
    context: dict[str, object],
    retrieval_record: dict[str, object],
    chunks: list[dict[str, object]],
) -> dict[str, object]:
    """Validate one attributable C knowledge bundle against its frozen contract."""
    _require_object(contract, "contract")
    _require_object(candidate, "candidate")
    _require_object(context, "context")
    _require_object(retrieval_record, "retrieval record")
    candidate_id = _require_string(candidate.get("id"), "candidate id")
    if context.get("candidate_id") != candidate_id:
        raise VariantContractError("context candidate_id must match candidate id")
    admitted = _object_field(contract, "admitted_retrieval", "contract")
    metadata_filter = _object_field(contract, "metadata_filter", "contract")
    ranking = _object_field(contract, "ranking", "contract")
    record_specification = _object_field(contract, "record_contract", "contract")
    _validate_record_fields(retrieval_record, record_specification)
    _validate_record_identity(retrieval_record, admitted, metadata_filter)
    results = retrieval_record["results"]
    if not isinstance(results, list) or not results:
        raise VariantContractError("retrieval record results must be a non-empty list")
    top_k = _positive_integer(ranking.get("top_k"), "top_k")
    if len(results) > top_k:
        raise VariantContractError("retrieval record result count exceeds top_k")
    chunk_index = _index_chunks(chunks)
    knowledge_items = []
    expected_rank = 1
    seen_chunk_ids: set[str] = set()
    for result in results:
        _require_object(result, "retrieval result")
        _validate_result_fields(result, record_specification)
        rank = result.get("final_rank")
        if rank != expected_rank:
            raise VariantContractError("retrieval result ranks must be ascending and contiguous")
        expected_rank += 1
        chunk_id = _require_string(result.get("chunk_id"), "retrieval result chunk_id")
        if chunk_id in seen_chunk_ids:
            raise VariantContractError("duplicate chunk_id in retrieval results")
        seen_chunk_ids.add(chunk_id)
        chunk = chunk_index.get(chunk_id)
        if chunk is None:
            raise VariantContractError("retrieval result chunk_id is not in the frozen corpus")
        _validate_result_chunk_match(result, chunk)
        text = _require_string(chunk.get("text"), "frozen chunk text")
        if _FORBIDDEN_KNOWLEDGE.search(text):
            raise VariantContractError("forbidden target-specific knowledge")
        knowledge_items.append(_knowledge_item(result, chunk, text))
    query = _require_string(retrieval_record.get("query"), "retrieval query")
    query_sha256 = _require_string(retrieval_record.get("query_sha256"), "retrieval query_sha256")
    config_sha256 = _require_string(
        retrieval_record.get("retrieval_config_sha256"), "retrieval config hash",
    )
    return {
        "candidate_id": candidate_id,
        "query": query,
        "query_sha256": query_sha256,
        "retrieval_record_sha256": _canonical_hash(retrieval_record),
        "retrieval_config_sha256": config_sha256,
        "corpus_id": retrieval_record["corpus_id"],
        "embedding_model_digest": retrieval_record["embedding_model_digest"],
        "knowledge_items": knowledge_items,
    }


def retrieval_failure_row(candidate_id: str, message: str) -> dict[str, object]:
    """Build the mandatory fail-open-to-UNCERTAIN record for C retrieval."""
    candidate_id = _require_string(candidate_id, "candidate id")
    message = _require_string(message, "retrieval failure message")
    return {
        "candidate_id": candidate_id,
        "effective_verdict": "UNCERTAIN",
        "error": f"retrieval:{message}",
        "retrieval_error": {"message": message},
    }


def _validate_record_fields(record: dict[str, object], specification: dict[str, object]) -> None:
    required = specification.get("required_record_fields")
    if not isinstance(required, list) or not all(isinstance(field, str) for field in required):
        raise VariantContractError("contract record fields must be a string list")
    if any(field not in record for field in required):
        raise VariantContractError("retrieval record is missing a required field")
    if record.get("status") != specification.get("status_requirement"):
        raise VariantContractError("retrieval record status must be passed")


def _validate_record_identity(
    record: dict[str, object],
    admitted: dict[str, object],
    metadata_filter: dict[str, object],
) -> None:
    for field in ("corpus_id", "embedding_model_name", "embedding_model_digest"):
        if record.get(field) != admitted.get(field):
            raise VariantContractError(f"retrieval record {field.replace('_', ' ')} does not match contract")
    if record.get("metadata_filter") != metadata_filter:
        raise VariantContractError("retrieval record metadata filter does not match contract")


def _validate_result_fields(result: dict[str, object], specification: dict[str, object]) -> None:
    required = specification.get("required_result_fields")
    if not isinstance(required, list) or not all(isinstance(field, str) for field in required):
        raise VariantContractError("contract result fields must be a string list")
    if any(field not in result for field in required):
        raise VariantContractError("retrieval result is missing a required field")
    _positive_integer(result.get("final_rank"), "retrieval result final_rank")
    for field in ("sparse_rank", "dense_rank"):
        _positive_integer(result.get(field), f"retrieval result {field}")
    for field in _SCORE_FIELDS:
        value = result.get(field)
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
            raise VariantContractError("retrieval result scores must be finite numbers")


def _index_chunks(chunks: list[dict[str, object]]) -> dict[str, dict[str, object]]:
    if not isinstance(chunks, list):
        raise VariantContractError("frozen chunks must be a list")
    index = {}
    for chunk in chunks:
        _require_object(chunk, "frozen chunk")
        chunk_id = _require_string(chunk.get("chunk_id"), "frozen chunk_id")
        if chunk_id in index:
            raise VariantContractError("duplicate chunk_id in frozen corpus")
        index[chunk_id] = chunk
    return index


def _validate_result_chunk_match(result: dict[str, object], chunk: dict[str, object]) -> None:
    for field in _RESULT_IDENTIFIERS:
        if result.get(field) != chunk.get(field):
            raise VariantContractError(f"retrieval result {field} does not match frozen chunk")


def _knowledge_item(
    result: dict[str, object],
    chunk: dict[str, object],
    text: str,
) -> dict[str, object]:
    section_path = chunk.get("section_path")
    if not isinstance(section_path, list) or not all(isinstance(item, str) for item in section_path):
        raise VariantContractError("frozen chunk section_path must be a string list")
    return {
        "knowledge_id": result["chunk_id"],
        "final_rank": result["final_rank"],
        "chunk_id": result["chunk_id"],
        "document_id": result["document_id"],
        "source_id": result["source_id"],
        "section_path": section_path,
        "content_sha256": result["content_sha256"],
        "raw_source_sha256": result["raw_source_sha256"],
        "canonical_text": f"{' > '.join(section_path)}\n{text}",
        "sparse_rank": result["sparse_rank"],
        "sparse_score": result["sparse_score"],
        "dense_rank": result["dense_rank"],
        "dense_score": result["dense_score"],
        "rrf_score": result["rrf_score"],
    }


def _require_object(value: object, name: str) -> dict[str, object]:
    if not isinstance(value, dict):
        raise VariantContractError(f"{name} must be an object")
    return value


def _object_field(value: dict[str, object], field: str, name: str) -> dict[str, object]:
    return _require_object(value.get(field), f"{name} {field}")


def _require_string(value: object, name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise VariantContractError(f"{name} must be a non-empty string")
    return value


def _positive_integer(value: object, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise VariantContractError(f"{name} must be a positive integer")
    return value


def _canonical_hash(value: object) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()
