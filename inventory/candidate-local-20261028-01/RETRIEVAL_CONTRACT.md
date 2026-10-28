# Retrieval Contract v1

## Status

Accepted design; implementation, model acquisition, and retrieval evaluation
are pending.

## Frozen corpus boundary

Retrieval v1 operates only on admitted corpus
`corpus-v1-6fb146619be86ca1`. It may retrieve only the four admitted chunks
from the separate freeze output. A corpus revision requires a new retrieval
configuration identity and new retrieval evidence.

## Eligibility gate

Before ranking, a chunk is eligible only when both conditions hold:

- `cwe_ids` contains `22`.
- `programming_languages` contains `Java`.

The gate is mandatory. If it yields no chunks, retrieval emits an attributable
empty or failed result and must not fall back to unfiltered corpus content.

## Query contract

The retrieval query is constructed only from frozen SAST/context fields:

```text
CWE + CodeQL rule title + normalized source API + normalized sink API
+ sanitizer candidates + short behavioral summary
```

It must not contain a target repository name, CVE, commit hash, patch, ground
truth, vulnerable/fixed label, or expected verdict.

## Ranking contract

Each eligible chunk has one canonical ranking text:

```text
section_path joined by " > " + newline + text
```

- Sparse ranking uses BM25 over canonical ranking text.
- Dense ranking uses BGE-M3 through Ollama over the same canonical ranking
  text.
- The exact Ollama model name and digest are mandatory runtime provenance, but
  are not frozen until the model is acquired and verified locally.
- Sparse and dense ranks are fused with Reciprocal Rank Fusion using
  `rrf_k = 60`.
- Results use `chunk_id` ascending as the deterministic tie-break.
- Return `top_k = 3` chunks, or all eligible chunks if fewer than three exist.

## Retrieval evidence contract

Each query emits one JSONL retrieval record containing at least:

```json
{
  "retrieval_schema_version": 1,
  "status": "passed",
  "corpus_id": "corpus-v1-6fb146619be86ca1",
  "retrieval_config_sha256": "...",
  "embedding_model_name": "...",
  "embedding_model_digest": "...",
  "query_sha256": "...",
  "metadata_filter": {"cwe_id": 22, "programming_language": "Java"},
  "rrf_k": 60,
  "top_k": 3,
  "results": [
    {
      "final_rank": 1,
      "chunk_id": "...",
      "document_id": "...",
      "source_id": "...",
      "section_path": ["..."],
      "content_sha256": "...",
      "raw_source_sha256": "...",
      "sparse_rank": 1,
      "sparse_score": 0.0,
      "dense_rank": 1,
      "dense_score": 0.0,
      "rrf_score": 0.0
    }
  ]
}
```

Records also retain run identity, retrieval timestamp, canonical query text or
an attributable query snapshot, and error detail when status is not `passed`.

## Failure and scope rules

- Missing corpus files, config/model identity, malformed chunks, embedding
  failure, or an empty eligibility gate are retrieval failures, not negative
  vulnerability predictions.
- A B/C verdict pipeline must treat failed or unavailable retrieval as an
  error or `UNCERTAIN` under the experiment policy.
- Retrieval may not create CodeQL candidates, alter source context, or add
  target-specific answer material.

## Implementation and evaluation gate

Implementation starts with deterministic retrieval tests for metadata gating,
BM25 inputs, RRF fusion, tie-breaking, and attributable JSONL records. Model
acquisition and its exact digest are recorded before dense retrieval runs.
Retrieval quality is evaluated separately on preregistered development
queries before any Variant C or held-out benchmark execution.
