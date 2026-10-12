import json
from pathlib import Path

import pytest

from semgrep_rules import sha256_file
from source_context import ContextError, build_contexts, validate_contexts


def write_findings(path: Path, findings: list[dict[str, object]]) -> None:
    path.write_text(
        "".join(json.dumps(item) + "\n" for item in findings),
        encoding="utf-8",
    )


def finding(path: str, line: int = 3) -> dict[str, object]:
    return {
        "candidate_id": "a" * 64,
        "dataset_commit": "b" * 40,
        "rule_identity": "java/rule.yaml::rule",
        "rule_id": "rule",
        "rule_sha256": "c" * 64,
        "reviewed_cwes": [78],
        "path": path,
        "start": {"line": line, "col": 1, "offset": 0},
        "end": {"line": line, "col": 5, "offset": 4},
    }


def test_builds_numbered_bounded_context_with_provenance(tmp_path: Path) -> None:
    dataset = tmp_path / "dataset"
    source = dataset / "src" / "Example.java"
    source.parent.mkdir(parents=True)
    source.write_text("one\ntwo\nthree\nfour\nfive\n", encoding="utf-8")
    findings = tmp_path / "findings.jsonl"
    output = tmp_path / "contexts.jsonl"
    write_findings(findings, [finding("src/Example.java")])

    result = build_contexts(dataset, findings, output, before=1, after=1, max_lines=3)

    assert result.context_count == 1
    record = json.loads(output.read_text(encoding="utf-8"))
    assert record["candidate_id"] == "a" * 64
    assert record["dataset_commit"] == "b" * 40
    assert record["source_sha256"] == sha256_file(source)
    assert record["context_start_line"] == 2
    assert record["context_end_line"] == 4
    assert record["truncated_before"] is True
    assert record["truncated_after"] is True
    assert record["lines"] == [
        {"number": 2, "text": "two"},
        {"number": 3, "text": "three"},
        {"number": 4, "text": "four"},
    ]


def test_context_output_is_deterministic_and_not_overwritten(tmp_path: Path) -> None:
    dataset = tmp_path / "dataset"
    source = dataset / "Example.java"
    dataset.mkdir()
    source.write_text("one\ntwo\n", encoding="utf-8")
    findings = tmp_path / "findings.jsonl"
    first = tmp_path / "first.jsonl"
    second = tmp_path / "second.jsonl"
    write_findings(findings, [finding("Example.java", 1)])

    build_contexts(dataset, findings, first, before=2, after=2, max_lines=5)
    build_contexts(dataset, findings, second, before=2, after=2, max_lines=5)

    assert first.read_bytes() == second.read_bytes()
    validated = validate_contexts(dataset, findings, first, before=2, after=2, max_lines=5)
    assert validated.context_count == 1
    with pytest.raises(ContextError, match="already exists"):
        build_contexts(dataset, findings, first, before=2, after=2, max_lines=5)


def test_rejects_finding_path_outside_dataset(tmp_path: Path) -> None:
    dataset = tmp_path / "dataset"
    dataset.mkdir()
    findings = tmp_path / "findings.jsonl"
    write_findings(findings, [finding("../outside.java")])

    with pytest.raises(ContextError, match="outside dataset"):
        build_contexts(dataset, findings, tmp_path / "contexts.jsonl")
