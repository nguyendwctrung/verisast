import hashlib
import json
from pathlib import Path


class StabilityError(ValueError):
    pass


RUNTIME_ONLY_FIELDS = frozenset({
    "created_at",
    "started_at",
    "finished_at",
    "timestamp",
    "retrieval_timestamp_utc",
    "duration_seconds",
    "run_id",
    "output",
})

MANIFEST_REQUIRED_FIELDS = frozenset({
    "schema_version",
    "purpose",
    "dataset",
    "inputs",
    "configuration",
    "environment",
    "repetitions",
    "timing",
    "resources",
    "gate",
})


def canonical_sha256(value: object, excluded_fields: frozenset[str] = RUNTIME_ONLY_FIELDS) -> str:
    """Hash a JSON value after removing declared runtime-only object fields."""
    canonical = _canonical_value(value, excluded_fields)
    encoded = json.dumps(canonical, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def compare_deterministic_repetitions(repetitions: list[object]) -> dict[str, object]:
    """Require exactly two canonically identical deterministic repetitions."""
    if len(repetitions) != 2:
        raise StabilityError("deterministic gate requires exactly two repetitions")
    hashes = [canonical_sha256(repetition) for repetition in repetitions]
    if len(set(hashes)) != 1:
        raise StabilityError("deterministic repetition canonical outputs differ")
    return {
        "status": "passed",
        "repetition_count": 2,
        "canonical_sha256": hashes[0],
        "repetition_sha256": hashes,
    }


def compare_baseline_repetitions(repetitions: list[dict[str, Path]]) -> dict[str, object]:
    """Compare canonical findings, contexts, and matcher output for two A runs."""
    required = {"findings", "contexts", "matches"}
    loaded = []
    for repetition in repetitions:
        if set(repetition) != required:
            raise StabilityError("baseline repetition requires findings, contexts, and matches")
        loaded.append({
            "findings": _read_json_records(repetition["findings"]),
            "contexts": _read_json_records(repetition["contexts"]),
            "matches": _read_json_records(repetition["matches"]),
        })
    return compare_deterministic_repetitions(loaded)


def aggregate_llm_repetitions(repetitions: list[dict[str, object]]) -> dict[str, object]:
    """Aggregate three LLM results, failing open when verdict evidence differs."""
    if len(repetitions) != 3:
        raise StabilityError("LLM gate requires exactly three repetitions")
    candidate_ids = {row.get("candidate_id") for row in repetitions}
    if len(candidate_ids) != 1 or not all(isinstance(value, str) and value for value in candidate_ids):
        raise StabilityError("LLM repetitions must describe one candidate")
    projections = [_llm_projection(row) for row in repetitions]
    hashes = [canonical_sha256(projection, frozenset()) for projection in projections]
    gate = {
        "required_repetitions": 3,
        "observed_repetitions": 3,
        "canonical_sha256": hashes,
    }
    if len(set(hashes)) != 1:
        return {
            "candidate_id": next(iter(candidate_ids)),
            "effective_verdict": "UNCERTAIN",
            "error": "non_reproducible_output",
            "stability_gate": {**gate, "status": "failed"},
        }
    first = repetitions[0]
    return {
        "candidate_id": first["candidate_id"],
        "effective_verdict": first.get("effective_verdict"),
        "reported_verdict": first.get("reported_verdict"),
        "error": first.get("error"),
        "citations": first.get("citations", {}),
        "stability_gate": {**gate, "status": "passed", "result_sha256": hashes[0]},
    }


def write_stability_manifest(path: Path, manifest: dict[str, object]) -> None:
    """Validate and write one no-overwrite stability manifest."""
    if path.exists():
        raise StabilityError(f"stability manifest already exists: {path}")
    missing = sorted(MANIFEST_REQUIRED_FIELDS - manifest.keys())
    if missing:
        raise StabilityError(f"stability manifest missing required fields: {', '.join(missing)}")
    if manifest.get("purpose") != "development_only":
        raise StabilityError("stability manifest purpose must be development_only")
    repetitions = manifest.get("repetitions")
    gate = manifest.get("gate")
    if not isinstance(repetitions, list) or not repetitions:
        raise StabilityError("stability manifest repetitions must be a non-empty list")
    if not isinstance(gate, dict) or gate.get("status") not in {"passed", "failed", "blocked"}:
        raise StabilityError("stability manifest gate status is invalid")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _canonical_value(value: object, excluded_fields: frozenset[str]) -> object:
    if isinstance(value, dict):
        return {
            key: _canonical_value(item, excluded_fields)
            for key, item in sorted(value.items())
            if key not in excluded_fields
        }
    if isinstance(value, list):
        return [_canonical_value(item, excluded_fields) for item in value]
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    raise StabilityError(f"canonical value is not JSON-compatible: {type(value).__name__}")


def _llm_projection(row: dict[str, object]) -> dict[str, object]:
    citations = row.get("citations", {})
    if not isinstance(citations, dict):
        raise StabilityError("LLM citations must be an object")
    normalized_citations = {}
    for name in ("source", "sink", "dataflow"):
        values = citations.get(name, [])
        if not isinstance(values, list) or not all(isinstance(value, str) for value in values):
            raise StabilityError(f"LLM {name} citations must be a string list")
        normalized_citations[name] = values
    return {
        "effective_verdict": row.get("effective_verdict"),
        "error": row.get("error"),
        "citations": normalized_citations,
    }


def _read_json_records(path: Path) -> object:
    try:
        text = path.read_text(encoding="utf-8")
        if path.suffix == ".jsonl":
            return [json.loads(line) for line in text.splitlines() if line]
        return json.loads(text)
    except (OSError, json.JSONDecodeError) as error:
        raise StabilityError(f"cannot read canonical baseline input {path}: {error}") from error
