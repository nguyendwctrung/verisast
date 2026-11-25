import hashlib
import json
from pathlib import Path

from stability import StabilityError, aggregate_llm_repetitions


def aggregate_triage_runs(run_directories: list[Path], output: Path) -> dict[str, object]:
    """Aggregate exactly three immutable B or C run directories."""
    if len(run_directories) != 3:
        raise StabilityError("triage stability gate requires exactly three runs")
    if output.exists():
        raise StabilityError(f"triage stability output already exists: {output}")
    per_run = [_load_run(path) for path in run_directories]
    candidate_sets = [set(rows) for rows in per_run]
    if any(candidate_set != candidate_sets[0] for candidate_set in candidate_sets[1:]):
        raise StabilityError("triage runs do not contain the same candidate set")
    aggregate_rows = []
    for candidate_id in sorted(candidate_sets[0]):
        aggregate_rows.append(aggregate_llm_repetitions([
            rows[candidate_id] for rows in per_run
        ]))
    gate_status = "passed" if all(
        row["stability_gate"]["status"] == "passed" for row in aggregate_rows
    ) else "failed"
    output.mkdir(parents=True)
    (output / "verdicts.jsonl").write_text(
        "".join(json.dumps(row, sort_keys=True) + "\n" for row in aggregate_rows),
        encoding="utf-8",
    )
    manifest = {
        "schema_version": 1,
        "purpose": "development_only",
        "status": "completed",
        "required_repetitions": 3,
        "candidate_count": len(aggregate_rows),
        "repetitions": [
            {
                "index": index,
                "run_directory": str(path),
                "verdicts_sha256": hashlib.sha256((path / "verdicts.jsonl").read_bytes()).hexdigest(),
            }
            for index, path in enumerate(run_directories, start=1)
        ],
        "gate": {"status": gate_status, "mismatch_policy": "UNCERTAIN/non_reproducible_output"},
        "aggregate_verdicts": "verdicts.jsonl",
    }
    (output / "manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8",
    )
    return manifest


def _load_run(path: Path) -> dict[str, dict[str, object]]:
    verdicts_path = path / "verdicts.jsonl"
    if not verdicts_path.is_file():
        raise StabilityError(f"triage run lacks verdicts.jsonl: {path}")
    rows: dict[str, dict[str, object]] = {}
    for line in verdicts_path.read_text(encoding="utf-8").splitlines():
        if not line:
            continue
        row = json.loads(line)
        candidate_id = row.get("candidate_id")
        if not isinstance(candidate_id, str) or candidate_id in rows:
            raise StabilityError(f"triage run has invalid candidate IDs: {path}")
        rows[candidate_id] = {**row, "citations": _citations(path, candidate_id)}
    return rows


def _citations(run: Path, candidate_id: str) -> dict[str, list[str]]:
    raw_path = run / "raw" / f"{candidate_id}.json"
    if not raw_path.is_file():
        return {"source": [], "sink": [], "dataflow": []}
    try:
        envelope = json.loads(raw_path.read_text(encoding="utf-8"))
        response = envelope.get("response")
        decoded = json.loads(response) if isinstance(response, str) else {}
    except (OSError, json.JSONDecodeError):
        return {"source": [], "sink": [], "dataflow": []}
    return {
        "source": _evidence_lines(decoded, "source"),
        "sink": _evidence_lines(decoded, "sink"),
        "dataflow": _evidence_lines(decoded, "dataflow"),
    }


def _evidence_lines(decoded: dict[str, object], field: str) -> list[str]:
    evidence = decoded.get(field)
    if not isinstance(evidence, dict):
        return []
    lines = evidence.get("evidence_lines")
    if not isinstance(lines, list) or not all(isinstance(line, str) for line in lines):
        return []
    return lines
