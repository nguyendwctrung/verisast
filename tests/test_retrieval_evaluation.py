import hashlib
import json
from pathlib import Path

import pytest

from retrieval_evaluate import EvaluationError, compute_metrics, load_projected_chunks, run


def write_jsonl(path: Path, rows: list[dict[str, object]]) -> None:
    path.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")


def chunk() -> dict[str, object]:
    return {
        "chunk_id": "chunk-1", "document_id": "document-1", "document_version_id": "version-1",
        "source_id": "source-1", "section_path": ["Safety"], "text": "Validate paths.",
        "content_sha256": "content-1", "raw_source_sha256": "raw-1",
    }


def document() -> dict[str, object]:
    return {
        "document_id": "document-1", "document_version_id": "version-1", "source_id": "source-1",
        "section_path": ["Safety"], "text": "Validate paths.", "content_sha256": "content-1",
        "raw_source_sha256": "raw-1", "cwe_ids": [22], "programming_languages": ["Java"],
    }


def test_projection_inherits_document_metadata_after_integrity_validation(tmp_path: Path) -> None:
    chunks_path, documents_path = tmp_path / "chunks.jsonl", tmp_path / "documents.jsonl"
    write_jsonl(chunks_path, [chunk()])
    write_jsonl(documents_path, [document()])

    projected = load_projected_chunks(chunks_path, documents_path)

    assert projected == [{**chunk(), "cwe_ids": [22], "programming_languages": ["Java"]}]


def test_projection_rejects_mismatched_document_metadata(tmp_path: Path) -> None:
    chunks_path, documents_path = tmp_path / "chunks.jsonl", tmp_path / "documents.jsonl"
    write_jsonl(chunks_path, [chunk()])
    wrong = document()
    wrong["content_sha256"] = "other"
    write_jsonl(documents_path, [wrong])

    with pytest.raises(EvaluationError, match="content_sha256"):
        load_projected_chunks(chunks_path, documents_path)


def test_projection_rejects_missing_document_join(tmp_path: Path) -> None:
    chunks_path, documents_path = tmp_path / "chunks.jsonl", tmp_path / "documents.jsonl"
    write_jsonl(chunks_path, [chunk()])
    write_jsonl(documents_path, [])

    with pytest.raises(EvaluationError, match="does not join"):
        load_projected_chunks(chunks_path, documents_path)


def test_metrics_are_macro_averaged_at_preregistered_k_values() -> None:
    metrics, rows = compute_metrics(
        [{"query_id": "one", "relevant_chunk_ids": ["a"]}, {"query_id": "two", "relevant_chunk_ids": ["b", "c"]}],
        {"one": ["a", "x"], "two": ["c", "x"]},
        [1, 3],
    )

    assert metrics == {"Hit@1": 1.0, "Hit@3": 1.0, "Recall@1": 0.75, "Recall@3": 0.75}
    assert rows[1]["Recall@1"] == 0.5


def test_runner_snapshots_inputs_and_refuses_overwrite(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    corpus = tmp_path / "corpus"
    corpus.mkdir()
    chunks_path, documents_path = corpus / "chunks.jsonl", corpus / "documents.jsonl"
    write_jsonl(chunks_path, [chunk()])
    write_jsonl(documents_path, [document()])
    manifest = {
        "corpus_id": "corpus-test", "status": "passed",
        "chunks_sha256": hashlib.sha256(chunks_path.read_bytes()).hexdigest(),
        "documents_sha256": hashlib.sha256(documents_path.read_bytes()).hexdigest(),
    }
    (corpus / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    inventory = tmp_path / "inventory"
    inventory.mkdir()
    write_jsonl(inventory / "queries.jsonl", [{"query_id": "one", "query_text": "validate path", "cwe_id": 22, "programming_language": "Java"}])
    write_jsonl(inventory / "judgments.jsonl", [{"query_id": "one", "relevant_chunk_ids": ["chunk-1"]}])
    protocol = {
        "status": "preregistered_not_executed",
        "corpus": {"corpus_id": "corpus-test", "manifest_path": str(corpus / "manifest.json"), "chunks_path": str(chunks_path), "documents_path": str(documents_path), "chunks_sha256": manifest["chunks_sha256"], "documents_sha256": manifest["documents_sha256"]},
        "embedding": {"endpoint": "http://localhost", "model_name": "bge-m3:latest", "model_digest": "digest", "dimension": 2, "timeout_seconds": 12, "keep_alive": "0s"},
        "metadata_filter": {"cwe_id": 22, "programming_language": "Java"},
        "ranking": {"rrf_k": 60, "top_k": 3},
        "metrics": {"primary": ["Hit@1", "Hit@3", "Recall@1", "Recall@3"]},
        "inputs": {"queries_path": str(inventory / "queries.jsonl"), "relevance_judgments_path": str(inventory / "judgments.jsonl")},
    }
    protocol_path = inventory / "protocol.json"
    protocol_path.write_text(json.dumps(protocol), encoding="utf-8")

    result = run(
        protocol_path,
        tmp_path / "run",
        metadata_reader=lambda endpoint, model, timeout: {"model_digest": "digest"},
        embedding_function=lambda endpoint, model, inputs, timeout, keep_alive: [[1.0, 0.0], [1.0, 0.0]],
    )

    assert result["status"] == "passed"
    assert (tmp_path / "run" / "retrieval-records.jsonl").exists()
    assert json.loads((tmp_path / "run" / "metrics.json").read_text(encoding="utf-8"))["Hit@1"] == 1.0
    with pytest.raises(EvaluationError, match="already exists"):
        run(protocol_path, tmp_path / "run")
