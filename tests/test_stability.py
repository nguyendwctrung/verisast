import json
from pathlib import Path

import pytest

from stability import (
    StabilityError,
    aggregate_llm_repetitions,
    canonical_sha256,
    compare_baseline_repetitions,
    compare_deterministic_repetitions,
    write_stability_manifest,
)


def test_canonical_hash_excludes_only_declared_runtime_fields() -> None:
    first = {"candidate_id": "c1", "result": [1, 2], "created_at": "one", "duration_seconds": 1.2}
    second = {"duration_seconds": 9.9, "created_at": "two", "result": [1, 2], "candidate_id": "c1"}

    assert canonical_sha256(first) == canonical_sha256(second)
    assert canonical_sha256(first) != canonical_sha256({**second, "result": [2, 1]})


def test_deterministic_gate_requires_two_matching_repetitions() -> None:
    result = compare_deterministic_repetitions([{"rows": [1]}, {"rows": [1]}])

    assert result["status"] == "passed"
    assert result["repetition_count"] == 2
    assert len(result["canonical_sha256"]) == 64


def test_deterministic_gate_rejects_mismatch() -> None:
    with pytest.raises(StabilityError, match="canonical outputs differ"):
        compare_deterministic_repetitions([{"rows": [1]}, {"rows": [2]}])


def test_baseline_gate_compares_findings_contexts_and_matches(tmp_path: Path) -> None:
    repetitions = []
    for index in range(2):
        run = tmp_path / str(index)
        run.mkdir()
        (run / "findings.jsonl").write_text('{"id":"c1"}\n', encoding="utf-8")
        (run / "contexts.jsonl").write_text('{"candidate_id":"c1"}\n', encoding="utf-8")
        (run / "matches.json").write_text('{"matches":[]}', encoding="utf-8")
        repetitions.append({
            "findings": run / "findings.jsonl",
            "contexts": run / "contexts.jsonl",
            "matches": run / "matches.json",
        })

    result = compare_baseline_repetitions(repetitions)

    assert result["status"] == "passed"
    (tmp_path / "1" / "matches.json").write_text('{"matches":["changed"]}', encoding="utf-8")
    with pytest.raises(StabilityError, match="canonical outputs differ"):
        compare_baseline_repetitions(repetitions)


def _llm_row(verdict: str = "TRUE_POSITIVE", source: list[str] | None = None) -> dict[str, object]:
    return {
        "candidate_id": "c1",
        "effective_verdict": verdict,
        "error": None,
        "citations": {
            "source": ["F1:L1"] if source is None else source,
            "sink": ["F1:L2"],
            "dataflow": ["F1:L1", "F1:L2"],
        },
    }


def test_llm_gate_accepts_three_matching_canonical_results() -> None:
    result = aggregate_llm_repetitions([_llm_row(), _llm_row(), _llm_row()])

    assert result["effective_verdict"] == "TRUE_POSITIVE"
    assert result["error"] is None
    assert result["stability_gate"]["status"] == "passed"


def test_llm_gate_fails_open_when_citations_differ() -> None:
    result = aggregate_llm_repetitions([_llm_row(), _llm_row(), _llm_row(source=["F1:L3"])])

    assert result["effective_verdict"] == "UNCERTAIN"
    assert result["error"] == "non_reproducible_output"
    assert result["stability_gate"]["status"] == "failed"


def test_manifest_is_complete_and_no_overwrite(tmp_path: Path) -> None:
    output = tmp_path / "stability.json"
    manifest = {
        "schema_version": 1,
        "purpose": "development_only",
        "dataset": {"name": "OWASP Benchmark Java", "cohort_id": "dev", "split": "development"},
        "inputs": {"findings_sha256": "a" * 64},
        "configuration": {"model_digest": "b" * 64},
        "environment": {"platform": "Windows"},
        "repetitions": [{"index": 1, "raw_sha256": "c" * 64, "canonical_sha256": "d" * 64}],
        "timing": {"duration_seconds": 1.0},
        "resources": {"peak_ram_bytes": None, "peak_vram_bytes": None},
        "gate": {"status": "passed"},
    }

    write_stability_manifest(output, manifest)

    assert json.loads(output.read_text(encoding="utf-8"))["purpose"] == "development_only"
    with pytest.raises(StabilityError, match="already exists"):
        write_stability_manifest(output, manifest)


def test_manifest_rejects_missing_required_section(tmp_path: Path) -> None:
    with pytest.raises(StabilityError, match="missing required fields"):
        write_stability_manifest(tmp_path / "manifest.json", {"schema_version": 1})
