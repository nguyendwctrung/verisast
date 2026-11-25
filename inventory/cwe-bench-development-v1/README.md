# CWE-Bench-Java OD-002 development cohort

This inventory preregisters local pair discovery and later development-cohort
selection. It does not contain a selected cohort yet.

The discovery step records only source and build facts: local pair identity,
origin remote, immutable `buggy` and `fixed` commits, clean-worktree status,
and top-level build systems. It does not inspect CodeQL, LLM, RAG, benchmark
outcomes, or target labels to rank candidates.

## Discovery command

Run from the repository root with the project virtual environment active:

```powershell
$env:PYTHONPATH = "src"
python -m src.main cwe-bench inventory `
  --dataset-root datasets/raw/cwe-bench-java `
  --protocol inventory/cwe-bench-development-v1/selection-protocol.json `
  --output artifacts/cohort/cwe-bench-discovery-20261118-01
```

The output directory is no-overwrite. Use a new run ID instead of deleting or
reusing an existing directory.

## Evidence to return for review

```powershell
Get-Content artifacts/cohort/cwe-bench-discovery-20261118-01/manifest.json
Get-Content artifacts/cohort/cwe-bench-discovery-20261118-01/candidates.jsonl
```

Discovery does not resolve OD-002. The next review must add verified
ground-truth file/symbol metadata, assess diversity, and decide whether more
official CWE-Bench snapshots are required before feasibility scanning.

## Source materialization

The accepted acquisition shortlist is pinned in
`acquisition-shortlist.json`. It is not a selected or admitted cohort. After
cloning the official 120-CVE snapshot at its pinned detached revision, run:

```powershell
$env:PYTHONPATH = "src"
python -m src.main cwe-bench materialize `
  --snapshot datasets/raw/cwe-bench-java-120 `
  --shortlist inventory/cwe-bench-development-v1/acquisition-shortlist.json `
  --dataset-root datasets/raw/cwe-bench-java `
  --output artifacts/cohort/cwe-bench-materialization-20261118-01
```

The command validates the snapshot revision and metadata hashes before any
source acquisition. Each new target receives an incomplete marker before Git
work begins. The marker is removed only after both roles pass expected-origin,
detached-revision, and clean-worktree checks. A later no-overwrite run can
resume a matching incomplete target. An existing complete pair is accepted
only when both revision roles match exactly. The command does not apply
upstream build patches and does not run CodeQL, LLM, or RAG.

Return the following generated evidence for review:

```powershell
Get-Content artifacts/cohort/cwe-bench-materialization-20261118-01/manifest.json
Get-Content artifacts/cohort/cwe-bench-materialization-20261118-01/records.jsonl
```

If a Git command fails, the run manifest records `status: failed` and an
incomplete target retains its marker for diagnosis and safe resume. Do not
delete or reuse the run directory; review the failure and use a new run ID.
The separate promotion helper remains available only to recover staging output
created by the earlier Windows-incompatible implementation.
