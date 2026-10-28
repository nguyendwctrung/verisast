# Candidate Local Inventory

**Status:** preparation only; no official source has been acquired or admitted.

This directory is a local scaffold for one bounded, official-source inventory.
It is not a corpus snapshot, retrieval corpus, or benchmark input.

## Populate before execution

1. Select an allowlisted official document and exact section before examining
   Variant C outcomes.
2. Place the unchanged UTF-8 source snapshot in `sources/`.
3. Place the applicable local license or copyright-notice snapshot in
   `licenses/`.
4. Complete `selection-rationale.md` and replace every placeholder in
   `sources.template.jsonl` to create `sources.jsonl`.
5. Verify the expected raw SHA-256 against the local source snapshot.
6. Review the audit scope and then invoke `scripts/prepare_corpus_freeze.ps1`
   with a new output directory.

Do not use `sources.template.jsonl` as wrapper input. It contains intentionally
invalid placeholders and must not be interpreted as provenance evidence.

## Current boundary

Do not download sources, add target-specific answer material, freeze corpus v1,
implement retrieval, run Variant C, or report benchmark results from this
directory.
