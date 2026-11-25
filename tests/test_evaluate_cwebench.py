import pytest

from evaluate import EvaluationError, score_cwe_bench


def test_reviewed_symbol_range_excludes_other_methods_in_same_file() -> None:
    units = [{"target_id": "project/buggy", "cve_id": "CVE-1", "revision_role": "buggy",
              "cwe": 22, "path_prefixes": ["src/Vulnerable.java"],
              "symbol_ranges": [{"path": "src/Vulnerable.java", "start": 20, "end": 30}]}]
    findings = [{"id": "outside", "target_id": "project/buggy", "cwes": [22],
                 "path": "src/Vulnerable.java", "start": 80, "flow": []}]
    result = score_cwe_bench(units, findings, require_pairs=False)
    assert result["overall"]["fn"] == 1
    findings[0]["flow"] = [{"path": "src/Vulnerable.java", "line": 25}]
    result = score_cwe_bench(units, findings, require_pairs=False)
    assert result["overall"]["tp"] == 1


def test_cwe_bench_scores_target_cve_units_separately_from_owasp() -> None:
    units = [
        {"target_id": "plexus:CVE-2022-4244:buggy", "cve_id": "CVE-2022-4244", "revision_role": "buggy", "cwe": 22, "path_prefixes": ["src/main/java/"]},
        {"target_id": "plexus:CVE-2022-4244:fixed", "cve_id": "CVE-2022-4244", "revision_role": "fixed", "cwe": 22, "path_prefixes": ["src/main/java/"]},
    ]
    findings = [
        {"id": "candidate-1", "target_id": "plexus:CVE-2022-4244:buggy", "cwes": [22], "path": "src/main/java/Archive.java"},
    ]

    result = score_cwe_bench(units, findings)

    assert result["matching_policy"] == "cwe-bench-target-cve-revision-cwe-path-v1"
    assert result["overall"]["tp"] == 1
    assert result["overall"]["tn"] == 1
    assert result["pair_accuracy"] == 1.0


def test_cwe_bench_ignores_findings_outside_target_path_scope() -> None:
    units = [{"target_id": "target:buggy", "cve_id": "CVE-1", "revision_role": "buggy", "cwe": 22, "path_prefixes": ["src/main/"]}]
    findings = [{"id": "candidate-1", "target_id": "target:buggy", "cwes": [22], "path": "tests/Fixture.java"}]

    result = score_cwe_bench(units, findings, require_pairs=False)

    assert result["overall"]["fn"] == 1


def test_cwe_bench_rejects_invalid_or_unpaired_units() -> None:
    with pytest.raises(EvaluationError, match="revision_role"):
        score_cwe_bench([{"target_id": "x", "cve_id": "CVE-1", "revision_role": "unknown", "cwe": 22, "path_prefixes": ["src/"]}], [])
    with pytest.raises(EvaluationError, match="vulnerable/fixed pair"):
        score_cwe_bench([{"target_id": "x", "cve_id": "CVE-1", "revision_role": "buggy", "cwe": 22, "path_prefixes": ["src/"]}], [], require_pairs=True)
