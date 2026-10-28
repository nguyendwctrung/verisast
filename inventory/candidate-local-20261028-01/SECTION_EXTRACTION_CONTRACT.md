# Markdown Section Extraction Contract

## Status

Accepted design; implementation and corpus admission are pending.

## Input

Each source record references one immutable UTF-8 Markdown snapshot and its
raw SHA-256. It declares `selected_sections`, an ordered non-empty list of
section specifications. A specification contains an exact non-empty
`section_path` array of Markdown heading texts plus the section's CWE, query,
language, and optional framework metadata.

The source record does not copy or rewrite section text. Raw snapshots and
license snapshots remain unchanged.

## Selection algorithm

The extractor parses ATX headings (`#` through `######`) in source order. A
section path matches only when its heading texts and heading levels form the
exact parent-to-child chain. Its extracted text starts at the matched heading
and ends immediately before the next heading at the same or a higher level.

Every requested path must resolve exactly once. A missing or ambiguous path
quarantines the source. The implementation must never fall back to a complete
source document.

## Output contract

Each admitted selected section produces one document and one chunk. Both carry
the exact `section_path`, `source_line_start`, `source_line_end`,
`raw_source_sha256`, `content_sha256`, and `extractor_version`.

Document and chunk identities include the source identity, source revision,
section path, extracted-content SHA-256, and extractor version. The corpus
retains each raw source once and preserves license provenance. The audit checks
both normalized raw text and every extracted section.

## Failure and evidence rules

Missing/ambiguous headings, invalid section metadata, extraction errors, hash
mismatches, or leakage matches produce quarantine or failed audit output. They
never admit a section or yield a safe verdict. Corpus v1 is not admitted until
the reviewed freeze output reports passed audit with zero excluded and
quarantined records.
