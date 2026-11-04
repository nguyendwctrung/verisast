import hashlib
import json
from pathlib import Path
from typing import Callable

from ollama_client import embed, metadata
from retrieval import build_retrieval_record, filter_eligible_chunks, rank_hybrid
from retrieval_evaluate import load_projected_chunks
from variant_contract import validate_retrieval_bundle


class TriageRetrievalError(ValueError):
    pass


def build_provider(
    contract_path: Path,
    metadata_reader: Callable[[str, str, int], dict[str, object]] = metadata,
    embedding_function: Callable[[str, str, list[str], int, str], list[list[object]]] = embed,
) -> Callable[[dict[str, object], dict[str, object]], dict[str, object]]:
    contract = json.loads(contract_path.read_text(encoding="utf-8"))
    admitted = contract["admitted_retrieval"]
    for name in ("chunks_path", "documents_path"):
        path = Path(str(admitted[name]))
        if not path.is_file():
            raise TriageRetrievalError(f"missing frozen corpus input: {path}")
    observed = metadata_reader("http://127.0.0.1:11434", str(admitted["embedding_model_name"]), 120)
    if observed.get("model_digest") != admitted["embedding_model_digest"]:
        raise TriageRetrievalError("embedding model digest does not match contract")
    chunks = load_projected_chunks(admitted)
    eligible = filter_eligible_chunks(chunks, int(contract["metadata_filter"]["cwe_id"]), str(contract["metadata_filter"]["programming_language"]))

    def provider(finding: dict[str, object], context: dict[str, object]) -> dict[str, object]:
        query = deterministic_query(finding, context)
        ranking = contract["ranking"]
        results = rank_hybrid(
            query, eligible,
            lambda inputs: embedding_function("http://127.0.0.1:11434", str(admitted["embedding_model_name"]), inputs, 120, "0s"),
            int(ranking["rrf_k"]), int(ranking["top_k"]),
        )
        record = build_retrieval_record(
            str(admitted["corpus_id"]), str(admitted["embedding_model_name"]), str(admitted["embedding_model_digest"]),
            query, ranking, contract["metadata_filter"], results,
        )
        return validate_retrieval_bundle(contract, finding, context, record, chunks)
    return provider


def deterministic_query(finding: dict[str, object], context: dict[str, object]) -> str:
    if not isinstance(finding.get("id"), str) or context.get("candidate_id") != finding["id"]:
        raise TriageRetrievalError("finding and context identities must match")
    lines = context.get("lines")
    if not isinstance(lines, list):
        raise TriageRetrievalError("context lines are required")
    text = " ".join(str(line.get("text", "")) for line in lines if isinstance(line, dict))
    payload = {"cwes": finding.get("cwes", []), "rule_id": finding.get("rule_id", ""), "message": finding.get("message", ""), "path": finding.get("path", ""), "context": text}
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))
