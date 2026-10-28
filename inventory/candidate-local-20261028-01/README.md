# Candidate Local Inventory

**Status:** corpus v1 admitted on the basis of a successful separate freeze
run, automated audit, and completed manual review. This directory remains the
source inventory; the immutable freeze evidence remains local under
`artifacts/`.

This directory is a local scaffold for one bounded, official-source inventory.
It is not a corpus snapshot, retrieval corpus, or benchmark input.

## Registered inventory

Two official OWASP Markdown snapshots are registered in `sources.jsonl` with
four exact heading paths. Raw snapshots, hashes, acquisition provenance, and
the local license snapshot are preserved in this directory.

Candidate extraction and the separate freeze run both produced
`corpus-v1-6fb146619be86ca1` with status `passed`: 2 sources, 4 documents, 4
chunks, and zero excluded or quarantined records. The freeze output is
`artifacts/rag/freeze/corpus-v1-candidate-local-20261028-01/`.

## Admission boundary

The admitted corpus contains only the four section paths registered in
`sources.jsonl`. A future corpus revision requires a new inventory decision,
new freeze output, and separate review; do not modify this admission in place.

Do not use `sources.template.jsonl` as wrapper input. It contains intentionally
invalid placeholders and must not be interpreted as provenance evidence.

## Current boundary

Do not download sources, add target-specific answer material, implement
retrieval, run Variant C, or report benchmark results from this directory.
Corpus admission alone is not Variant C readiness or a benchmark result.
