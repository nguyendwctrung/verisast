import copy
import json
import math
from pathlib import Path

import pytest

from triage import _request
from variant_contract import (
    VariantContractError,
    build_variant_c_request,
    retrieval_failure_row,
    validate_retrieval_bundle,
)


ROOT = Path(__file__).parents[1]


@pytest.fixture
def bundle_contract() -> dict[str, object]:
    return json.loads((ROOT / "inventory" / "variant-contracts" / "variant-c-retrieval-bundle-v1.json").read_text(encoding="utf-8"))


@pytest.fixture
def candidate() -> dict[str, object]:
    return {"id": "candidate-1", "cwes": [22], "path": "src/Archive.java"}


@pytest.fixture
def context() -> dict[str, object]:
    return {
        "candidate_id": "candidate-1",
        "lines": [{"id": "F1:L1", "text": "entry.getName();"}],
        "guards": [],
    }


@pytest.fixture
def chunks() -> list[dict[str, object]]:
    return [{
        "chunk_id": "chunk-v1:one",
        "document_id": "document-v1:one",
        "source_id": "owasp-input-validation-20261028",
        "section_path": ["Input Validation", "Canonicalization"],
        "text": "Normalize the untrusted path before authorizing filesystem access.",
        "content_sha256": "content-one",
        "raw_source_sha256": "raw-one",
    }]


@pytest.fixture
def retrieval_record(bundle_contract: dict[str, object]) -> dict[str, object]:
    admitted = bundle_contract["admitted_retrieval"]
    return {
        "status": "passed",
        "corpus_id": admitted["corpus_id"],
        "embedding_model_name": admitted["embedding_model_name"],
        "embedding_model_digest": admitted["embedding_model_digest"],
        "metadata_filter": {"cwe_id": 22, "programming_language": "Java"},
        "query": "CWE-22 Java archive entry path validation",
        "query_sha256": "query-sha256",
        "retrieval_config_sha256": "config-sha256",
        "results": [{
            "final_rank": 1,
            "chunk_id": "chunk-v1:one",
            "document_id": "document-v1:one",
            "source_id": "owasp-input-validation-20261028",
            "section_path": ["Input Validation", "Canonicalization"],
            "content_sha256": "content-one",
            "raw_source_sha256": "raw-one",
            "sparse_rank": 1,
            "sparse_score": 3.0,
            "dense_rank": 1,
            "dense_score": 0.7,
            "rrf_score": 0.03,
        }],
    }


def _b_request() -> dict[str, object]:
    guards = {"G1": {
        "condition_lines": ["F1:L1"],
        "action_lines": ["F1:L2"],
        "action_blocks_sink": True,
    }}
    return _request(
        "frozen prompt template",
        {"type": "object"},
        guards,
        [{"guard_id": "G1", "kind": "PATH_PREFIX_CHECK"}],
        [],
        {"temperature": 0, "num_predict": 512, "num_ctx": 3072, "keep_alive": "10m"},
    )


def test_variant_c_request_changes_only_retrieved_knowledge(
    bundle_contract: dict[str, object],
    candidate: dict[str, object],
    context: dict[str, object],
    retrieval_record: dict[str, object],
    chunks: list[dict[str, object]],
) -> None:
    b_request = _b_request()
    bundle = validate_retrieval_bundle(
        bundle_contract, candidate, context, retrieval_record, chunks,
    )

    c_request = build_variant_c_request(b_request, bundle)

    assert b_request["retrieved_knowledge"] == []
    assert c_request["retrieved_knowledge"] == bundle["knowledge_items"]
    assert {
        key: value for key, value in c_request.items() if key != "retrieved_knowledge"
    } == {
        key: value for key, value in b_request.items() if key != "retrieved_knowledge"
    }
    assert b_request == _b_request()


def test_validated_bundle_preserves_attribution_and_canonical_text(
    bundle_contract: dict[str, object],
    candidate: dict[str, object],
    context: dict[str, object],
    retrieval_record: dict[str, object],
    chunks: list[dict[str, object]],
) -> None:
    bundle = validate_retrieval_bundle(
        bundle_contract, candidate, context, retrieval_record, chunks,
    )

    assert bundle["candidate_id"] == "candidate-1"
    assert bundle["query"] == retrieval_record["query"]
    assert bundle["embedding_model_digest"] == retrieval_record["embedding_model_digest"]
    assert bundle["knowledge_items"] == [{
        "knowledge_id": "chunk-v1:one",
        "final_rank": 1,
        "chunk_id": "chunk-v1:one",
        "document_id": "document-v1:one",
        "source_id": "owasp-input-validation-20261028",
        "section_path": ["Input Validation", "Canonicalization"],
        "content_sha256": "content-one",
        "raw_source_sha256": "raw-one",
        "canonical_text": "Input Validation > Canonicalization\nNormalize the untrusted path before authorizing filesystem access.",
        "sparse_rank": 1,
        "sparse_score": 3.0,
        "dense_rank": 1,
        "dense_score": 0.7,
        "rrf_score": 0.03,
    }]


def test_bundle_rejects_wrong_embedding_digest(
    bundle_contract: dict[str, object],
    candidate: dict[str, object],
    context: dict[str, object],
    retrieval_record: dict[str, object],
    chunks: list[dict[str, object]],
) -> None:
    record = copy.deepcopy(retrieval_record)
    record["embedding_model_digest"] = "wrong-digest"

    with pytest.raises(VariantContractError, match="embedding.*digest"):
        validate_retrieval_bundle(bundle_contract, candidate, context, record, chunks)


def test_bundle_rejects_nonfinite_scores(
    bundle_contract: dict[str, object],
    candidate: dict[str, object],
    context: dict[str, object],
    retrieval_record: dict[str, object],
    chunks: list[dict[str, object]],
) -> None:
    record = copy.deepcopy(retrieval_record)
    record["results"][0]["dense_score"] = math.nan

    with pytest.raises(VariantContractError, match="finite"):
        validate_retrieval_bundle(bundle_contract, candidate, context, record, chunks)


def test_bundle_rejects_duplicate_knowledge_ids(
    bundle_contract: dict[str, object],
    candidate: dict[str, object],
    context: dict[str, object],
    retrieval_record: dict[str, object],
    chunks: list[dict[str, object]],
) -> None:
    record = copy.deepcopy(retrieval_record)
    duplicate = copy.deepcopy(record["results"][0])
    duplicate["final_rank"] = 2
    duplicate["sparse_rank"] = 2
    duplicate["dense_rank"] = 2
    record["results"].append(duplicate)

    with pytest.raises(VariantContractError, match="duplicate"):
        validate_retrieval_bundle(bundle_contract, candidate, context, record, chunks)


def test_bundle_rejects_forbidden_target_specific_knowledge(
    bundle_contract: dict[str, object],
    candidate: dict[str, object],
    context: dict[str, object],
    retrieval_record: dict[str, object],
    chunks: list[dict[str, object]],
) -> None:
    frozen_chunks = copy.deepcopy(chunks)
    frozen_chunks[0]["text"] = "Known vulnerable patch for this target fixes CVE-2026-0001."

    with pytest.raises(VariantContractError, match="forbidden"):
        validate_retrieval_bundle(bundle_contract, candidate, context, retrieval_record, frozen_chunks)


def test_retrieval_failure_is_uncertain_with_preserved_error_evidence() -> None:
    row = retrieval_failure_row("candidate-1", "embedding endpoint unavailable")

    assert row == {
        "candidate_id": "candidate-1",
        "effective_verdict": "UNCERTAIN",
        "error": "retrieval:embedding endpoint unavailable",
        "retrieval_error": {"message": "embedding endpoint unavailable"},
    }
