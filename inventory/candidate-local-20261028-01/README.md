# Candidate Local Inventory

**Status:** official snapshots acquired; section registration, candidate
extraction, automated audit, and manual review completed. A separate freeze
run is pending; this directory is not an admitted corpus snapshot.

This directory is a local scaffold for one bounded, official-source inventory.
It is not a corpus snapshot, retrieval corpus, or benchmark input.

## Registered inventory

Two official OWASP Markdown snapshots are registered in `sources.jsonl` with
four exact heading paths. Raw snapshots, hashes, acquisition provenance, and
the local license snapshot are preserved in this directory.

Candidate extraction `corpus-v1-6fb146619be86ca1` completed with status
`passed`: 2 sources, 4 documents, 4 chunks, and zero excluded or quarantined
records. Its artifact remains local under `artifacts/` and is not a freeze.

## Next authorized operation

After the completed manual review, invoke `scripts/prepare_corpus_freeze.ps1`
with a new, non-existing output directory. Review the resulting manifest and
audit before recording any corpus-v1 admission decision.

Do not use `sources.template.jsonl` as wrapper input. It contains intentionally
invalid placeholders and must not be interpreted as provenance evidence.

## Current boundary

Do not download sources, add target-specific answer material, implement
retrieval, run Variant C, or report benchmark results from this directory.
Do not treat a freeze output as Variant C readiness or as a benchmark result.
