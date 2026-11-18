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
