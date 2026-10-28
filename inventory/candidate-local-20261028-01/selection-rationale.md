# Selection Rationale

**Status:** snapshots acquired; four section-level admissions registered;
implementation is complete, while audit and corpus admission remain pending.

## Selected source identities

| Source ID | Publisher | Official source URL | Local source filename |
| --- | --- | --- | --- |
| `owasp-file-upload-20261028` | OWASP Foundation | `https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html` | `sources/owasp-file-upload-9d41c054686e.md` |
| `owasp-input-validation-20261028` | OWASP Foundation | `https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html` | `sources/owasp-input-validation-9d41c054686e.md` |

- Release, commit, or version: OWASP CheatSheetSeries commit
  `9d41c054686e35fb56070b4b6271ae2829edea6a`.
- Local license snapshot filename:
  `licenses/owasp-cheat-sheet-series-license-20261028.html`.
- Retrieval timestamp (UTC): `2026-10-28T08:09:18Z` for File Upload and
  `2026-10-28T08:09:19Z` for Input Validation and Secure Code Review.

## Selected content

| Source ID | Exact title | Stable section locator | CWE and query relevance |
| --- | --- | --- | --- |
| `owasp-file-upload-20261028` | `File Upload Cheat Sheet` | `File Upload Protection > Filename Safety` | General handling of untrusted filenames, including allowlisted characters and traversal-related restrictions. |
| `owasp-file-upload-20261028` | `File Upload Cheat Sheet` | `File Upload Protection > Upload and Download Limits` | General ZIP extraction-size and resource-limit guidance. |
| `owasp-input-validation-20261028` | `Input Validation Cheat Sheet` | `Input Validation Strategies > Allowlist vs Denylist` | General allowlist validation guidance for untrusted input. |
| `owasp-input-validation-20261028` | `Input Validation Cheat Sheet` | `Implementing Input Validation > Parse Safely, Then Validate` | General parsing, decoding, and validation-order guidance. |

- Each listed section path is a corpus-admission boundary. The raw snapshots
  remain unchanged and the source manifest must preserve their exact hashes.
- The registered manifest uses the accepted `selected_sections` contract and
  must not be expanded with a full-document fallback.
- All records are tagged for CWE-22, Java, and `java/zipslip`; this is a
  relevance mapping, not a vulnerability label or target answer.

## Pre-registration rationale

The two registered documents were selected before acquiring snapshots and
before examining any Variant C output. They are official OWASP guidance with
one consistent license and provide complementary general knowledge about
untrusted file names and paths: allowlist validation, parsing order, and
archive handling. The content is relevant to the registered CWE-22 and Java
Zip Slip query scope without describing any target repository, target version,
expected verdict, patch, or experiment outcome.

The Secure Code Review snapshot is retained as an acquired candidate with
provenance, but it is not registered for corpus v1: its relevant path-traversal
guidance is embedded in broader review sections, so it cannot be admitted at a
sufficiently narrow heading boundary.

## Leakage review

- Target identifiers checked: `plexus utils`, `cve-2022-4244`,
  `6176f91bb843eecddac857591ed20bda38e01470`, and
  `33a2853df8185b4519b1b8bfae284f03392618ef`.
- Advisory, patch, label, ground-truth, vulnerable/fixed marker, repository
  version, and target-answer material: prohibited. A source with a target
  match must be excluded rather than edited.
- General examples retained and rationale: only after lexical audit and manual
  review confirm they do not disclose a target-specific answer.
- Manual reviewer and review date: pending.
- Disposition: snapshots acquired; not admitted.

## License and redistribution review

- License identifier and official URL: `CC-BY-SA-4.0`;
  `https://creativecommons.org/licenses/by-sa/4.0/`.
- Snapshot location: `licenses/owasp-cheat-sheet-series-license-20261028.html`.
- Copyright or attribution notice: preserve the OWASP attribution and license
  statement exactly as captured from the official OWASP project page.
- Redistribution constraints: retain attribution and comply with CC BY-SA 4.0
  for any redistributed or adapted content.
