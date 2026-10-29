# Retrieval Development Evaluation v1

This directory freezes development-only retrieval inputs before any retrieval
output is produced. It is not a Variant C input and it does not contain target
repository identifiers, CVEs, patches, vulnerable/fixed labels, or verdicts.

`protocol.json` fixes the corpus, runtime, ranking configuration, metrics, and
evidence layout. `queries.jsonl` contains SAST/context-shaped development
queries. `relevance-judgments.jsonl` contains manual knowledge-relevance
judgments over immutable admitted chunk IDs; it is not vulnerability ground
truth.

The evaluation runner must snapshot these three files, validate their hashes,
join each immutable chunk to its document metadata, and refuse to overwrite an
existing run directory. A missing chunk/document join, malformed judgment, or
retrieval failure is an evaluation error and cannot be reported as a negative
security prediction.

Readiness thresholds are intentionally unset. Development metrics may be
reported descriptively after execution, but cannot close OD-005 or authorize
Variant C until the user accepts explicit success criteria.
