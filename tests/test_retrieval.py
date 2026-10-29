import hashlib
import json
from pathlib import Path

import pytest

from retrieval import (
    RetrievalError,
    build_retrieval_record,
    canonical_ranking_text,
    filter_eligible_chunks,
    fuse_rankings,
    rank_bm25,
    rank_dense,
    rank_hybrid,
    write_retrieval_records,
)


CORPUS_ID = "corpus-v1-6fb146619be86ca1"


def chunk(
    chunk_id: str,
    section_path: list[str],
    text: str,
    cwe_ids: list[int] | None = None,
    languages: list[str] | None = None,
) -> dict[str, object]:
    return {
        "chunk_id": chunk_id,
        "document_id": f"document-{chunk_id}",
        "source_id": "owasp-example",
        "section_path": section_path,
        "text": text,
        "cwe_ids": [22] if cwe_ids is None else cwe_ids,
        "programming_languages": ["Java"] if languages is None else languages,
        "content_sha256": f"content-{chunk_id}",
        "raw_source_sha256": f"raw-{chunk_id}",
    }


def test_metadata_gate_accepts_only_cwe22_java_chunks() -> None:
    chunks = [
        chunk("chunk-match", ["File Upload", "Filename Safety"], "Validate a filename."),
        chunk("chunk-wrong-cwe", ["Other"], "Archive safety.", cwe_ids=[79]),
        chunk("chunk-wrong-language", ["Other"], "Archive safety.", languages=["Python"]),
    ]

    eligible = filter_eligible_chunks(chunks, cwe_id=22, programming_language="Java")

    assert [item["chunk_id"] for item in eligible] == ["chunk-match"]


def test_metadata_gate_returns_no_unfiltered_fallback() -> None:
    chunks = [chunk("chunk-wrong-cwe", ["Other"], "Archive safety.", cwe_ids=[79])]

    assert filter_eligible_chunks(chunks, cwe_id=22, programming_language="Java") == []


def test_malformed_chunk_is_a_retrieval_error() -> None:
    malformed = chunk("chunk-bad", ["Other"], "Archive safety.")
    malformed.pop("raw_source_sha256")

    with pytest.raises(RetrievalError, match="raw_source_sha256"):
        filter_eligible_chunks([malformed], cwe_id=22, programming_language="Java")


def test_canonical_ranking_text_joins_heading_path_and_text() -> None:
    value = canonical_ranking_text(
        chunk("chunk-path", ["File Upload Protection", "Filename Safety"], "Validate untrusted names.")
    )

    assert value == "File Upload Protection > Filename Safety\nValidate untrusted names."


def test_bm25_ranks_the_best_matching_eligible_chunk_first() -> None:
    archive = chunk("chunk-archive", ["Archive Handling"], "Validate archive entry names before extraction.")
    filename = chunk("chunk-filename", ["Filename Safety"], "Allowlist user-controlled filename characters.")

    ranked = rank_bm25("archive entry extraction", [filename, archive])

    assert [item["chunk_id"] for item in ranked] == ["chunk-archive", "chunk-filename"]
    assert [item["sparse_rank"] for item in ranked] == [1, 2]
    assert ranked[0]["sparse_score"] > ranked[1]["sparse_score"]


def test_dense_ranking_uses_canonical_text_and_cosine_similarity() -> None:
    archive = chunk("chunk-archive", ["Archive Handling"], "Validate archive entry names.")
    filename = chunk("chunk-filename", ["Filename Safety"], "Allowlist filename characters.")
    captured: list[list[str]] = []

    def embed(inputs: list[str]) -> list[list[float]]:
        captured.append(inputs)
        return [[1.0, 0.0], [0.0, 1.0], [1.0, 0.0]]

    ranked = rank_dense("archive extraction", [filename, archive], embed)

    assert captured == [[
        "archive extraction",
        "Filename Safety\nAllowlist filename characters.",
        "Archive Handling\nValidate archive entry names.",
    ]]
    assert [item["chunk_id"] for item in ranked] == ["chunk-archive", "chunk-filename"]
    assert [item["dense_rank"] for item in ranked] == [1, 2]
    assert ranked[0]["dense_score"] == 1.0
    assert ranked[1]["dense_score"] == 0.0


def test_dense_ranking_uses_chunk_id_for_equal_cosine_scores() -> None:
    first = chunk("chunk-b", ["B"], "Second canonical text.")
    second = chunk("chunk-a", ["A"], "First canonical text.")

    ranked = rank_dense(
        "query",
        [first, second],
        lambda inputs: [[1.0, 0.0], [1.0, 0.0], [1.0, 0.0]],
    )

    assert [item["chunk_id"] for item in ranked] == ["chunk-a", "chunk-b"]


def test_dense_ranking_rejects_malformed_embedding_vectors() -> None:
    with pytest.raises(RetrievalError, match="same dimension"):
        rank_dense(
            "query",
            [chunk("chunk-a", ["A"], "Text.")],
            lambda inputs: [[1.0, 0.0], [1.0]],
        )

    with pytest.raises(RetrievalError, match="finite numbers"):
        rank_dense(
            "query",
            [chunk("chunk-a", ["A"], "Text.")],
            lambda inputs: [[1.0, 0.0], [float("nan"), 1.0]],
        )


def test_hybrid_ranking_filters_before_embedding_and_preserves_chunk_provenance() -> None:
    eligible = chunk("chunk-eligible", ["Archive Handling"], "Validate archive entry names.")
    ineligible = chunk("chunk-ineligible", ["Other"], "Other text.", cwe_ids=[79])
    captured: list[list[str]] = []

    def embed(inputs: list[str]) -> list[list[float]]:
        captured.append(inputs)
        return [[1.0, 0.0], [1.0, 0.0]]

    ranked = rank_hybrid(
        "archive extraction",
        [ineligible, eligible],
        cwe_id=22,
        programming_language="Java",
        embed=embed,
        rrf_k=60,
        top_k=3,
    )

    assert captured == [[
        "archive extraction",
        "Archive Handling\nValidate archive entry names.",
    ]]
    assert ranked == [{
        **eligible,
        "sparse_score": ranked[0]["sparse_score"],
        "sparse_rank": 1,
        "dense_score": 1.0,
        "dense_rank": 1,
        "rrf_score": 2 / 61,
        "final_rank": 1,
    }]


def test_hybrid_ranking_does_not_embed_when_metadata_gate_is_empty() -> None:
    def unexpected_embedding_call(inputs: list[str]) -> list[list[float]]:
        raise AssertionError("embedding must not run without eligible chunks")

    assert rank_hybrid(
        "archive extraction",
        [chunk("chunk-ineligible", ["Other"], "Other text.", cwe_ids=[79])],
        cwe_id=22,
        programming_language="Java",
        embed=unexpected_embedding_call,
        rrf_k=60,
        top_k=3,
    ) == []


def test_rrf_uses_configured_k_and_chunk_id_tie_break() -> None:
    sparse = [
        {"chunk_id": "chunk-b", "sparse_rank": 1, "sparse_score": 0.9},
        {"chunk_id": "chunk-a", "sparse_rank": 2, "sparse_score": 0.8},
    ]
    dense = [
        {"chunk_id": "chunk-a", "dense_rank": 1, "dense_score": 0.9},
        {"chunk_id": "chunk-b", "dense_rank": 2, "dense_score": 0.8},
    ]

    fused = fuse_rankings(sparse, dense, rrf_k=60, top_k=3)

    assert [item["chunk_id"] for item in fused] == ["chunk-a", "chunk-b"]
    assert [item["final_rank"] for item in fused] == [1, 2]
    assert fused[0]["rrf_score"] == fused[1]["rrf_score"]


def test_retrieval_record_preserves_attributable_provenance(tmp_path: Path) -> None:
    selected = chunk("chunk-archive", ["Archive Handling"], "Validate archive entry names before extraction.")
    record = build_retrieval_record(
        corpus_id=CORPUS_ID,
        retrieval_config={"rrf_k": 60, "top_k": 3},
        embedding_model_name="bge-m3",
        embedding_model_digest="sha256:test",
        query="CWE-22 Java archive entry extraction",
        metadata_filter={"cwe_id": 22, "programming_language": "Java"},
        results=[{
            **selected,
            "sparse_rank": 1,
            "sparse_score": 1.0,
            "dense_rank": 1,
            "dense_score": 1.0,
            "rrf_score": 2 / 61,
            "final_rank": 1,
        }],
    )

    output = tmp_path / "retrieval.jsonl"
    write_retrieval_records(output, [record])
    written = json.loads(output.read_text(encoding="utf-8"))

    assert written["status"] == "passed"
    assert written["corpus_id"] == CORPUS_ID
    assert written["query_sha256"] == hashlib.sha256(
        b"CWE-22 Java archive entry extraction"
    ).hexdigest()
    assert written["retrieval_config_sha256"]
    assert written["rrf_k"] == 60
    assert written["top_k"] == 3
    assert written["results"] == [{
        "final_rank": 1,
        "chunk_id": "chunk-archive",
        "document_id": "document-chunk-archive",
        "source_id": "owasp-example",
        "section_path": ["Archive Handling"],
        "content_sha256": "content-chunk-archive",
        "raw_source_sha256": "raw-chunk-archive",
        "sparse_rank": 1,
        "sparse_score": 1.0,
        "dense_rank": 1,
        "dense_score": 1.0,
        "rrf_score": 2 / 61,
    }]
