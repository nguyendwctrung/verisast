import json
from pathlib import Path

import pytest

from semgrep_normalize import NormalizeError, normalize_findings
from semgrep_rules import sha256_file


def test_normalize_deduplicates_and_preserves_raw_references(tmp_path: Path) -> None:
    dataset = tmp_path / "dataset"
    source = dataset / "src" / "main" / "java" / "org" / "owasp" / "benchmark" / "testcode"
    source.mkdir(parents=True)
    java = source / "BenchmarkTest00001.java"
    java.write_text("class X {}\n", encoding="utf-8")
    raw = tmp_path / "raw.json"
    result = {
        "check_id": "rule",
        "path": str(java),
        "start": {"line": 1, "col": 1, "offset": 0},
        "end": {"line": 1, "col": 6, "offset": 5},
        "extra": {
            "message": "message",
            "severity": "ERROR",
            "lines": "class",
            "metavars": {"$X": {"abstract_content": "X"}},
            "dataflow_trace": {"taint_source": ["source"]},
        },
    }
    raw.write_text(json.dumps({"version": "1.179.0", "results": [result, result], "errors": []}), encoding="utf-8")
    scans = [
        {
            "rule_identity": "java/rule.yaml::rule",
            "rule_id": "rule",
            "rule_path": "java/rule.yaml",
            "rule_sha256": "1" * 64,
            "reviewed_cwes": [78],
            "stdout_path": str(raw),
            "stdout_sha256": sha256_file(raw),
        }
    ]
    findings, raw_count = normalize_findings(dataset, "b" * 40, scans)
    assert raw_count == 2
    assert len(findings) == 1
    assert len(findings[0]["raw_references"]) == 2
    assert findings[0]["metavars"]["$X"]["abstract_content"] == "X"
    assert findings[0]["dataflow_trace"] == {"taint_source": ["source"]}


def test_normalize_rejects_path_outside_dataset(tmp_path: Path) -> None:
    raw = tmp_path / "raw.json"
    raw.write_text(
        json.dumps(
            {
                "version": "1.179.0",
                "errors": [],
                "results": [
                    {
                        "check_id": "rule",
                        "path": str(tmp_path / "outside.java"),
                        "start": {"line": 1, "col": 1},
                        "end": {"line": 1, "col": 2},
                        "extra": {},
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    scans = [{"rule_identity": "p::r", "rule_id": "r", "rule_path": "p", "rule_sha256": "1" * 64, "reviewed_cwes": [78], "stdout_path": str(raw), "stdout_sha256": sha256_file(raw)}]
    with pytest.raises(NormalizeError, match="outside dataset"):
        normalize_findings(tmp_path / "dataset", "b" * 40, scans)
