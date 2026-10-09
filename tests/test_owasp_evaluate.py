from owasp_evaluate import evaluate_findings


def test_evaluate_uses_any_matching_finding_per_unit() -> None:
    cohort = {
        "units": [
            {"test_id": "BenchmarkTest00001", "cwe": 78, "vulnerable": True, "category": "cmdi"},
            {"test_id": "BenchmarkTest00002", "cwe": 78, "vulnerable": False, "category": "cmdi"},
            {"test_id": "BenchmarkTest00003", "cwe": 78, "vulnerable": True, "category": "cmdi"},
        ]
    }
    findings = [
        {"candidate_id": "a", "test_id": "BenchmarkTest00001", "reviewed_cwes": [78]},
        {"candidate_id": "b", "test_id": "BenchmarkTest00001", "reviewed_cwes": [78]},
        {"candidate_id": "c", "test_id": "BenchmarkTest00002", "reviewed_cwes": [78]},
        {"candidate_id": "d", "test_id": None, "reviewed_cwes": [78]},
    ]
    matches, metrics = evaluate_findings(cohort, findings, raw_finding_count=5)
    assert len(matches) == 3
    assert metrics["overall"]["tp"] == 1
    assert metrics["overall"]["fp"] == 1
    assert metrics["overall"]["fn"] == 1
    assert metrics["overall"]["tn"] == 0
    assert metrics["predicted_unit_count"] == 2
    assert metrics["unmapped_candidate_count"] == 1


def test_evaluate_zero_denominator_returns_null_metric() -> None:
    cohort = {"units": [{"test_id": "BenchmarkTest00001", "cwe": 78, "vulnerable": True, "category": "cmdi"}]}
    _, metrics = evaluate_findings(cohort, [], raw_finding_count=0)
    assert metrics["overall"]["precision"] is None
    assert metrics["overall"]["fpr"] is None
