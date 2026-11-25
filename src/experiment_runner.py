"""Run identity and fixture-only orchestration checks for Phase 5."""

import hashlib
import json
import re
import secrets
from datetime import datetime, timezone
from pathlib import Path

from experiment_report import evaluate_variants, write_reports


class RunnerError(ValueError):
    pass


def allocate_run(output_dir: Path, result_name: str) -> Path:
    """Atomically reserve a unique no-overwrite directory for a named result."""
    validate_result_name(result_name)
    output_dir.mkdir(parents=True, exist_ok=True)
    for _ in range(8):
        suffix = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + secrets.token_hex(4)
        run = output_dir / f"{result_name}-{suffix}"
        try:
            run.mkdir()
            return run
        except FileExistsError:
            continue
    raise RunnerError("unable to allocate a unique run ID")


def validate_result_name(result_name: str) -> None:
    if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,79}", result_name) is None or result_name in {".", ".."}:
        raise RunnerError("result name must be a safe file-name stem")


def run_mock(output_dir: Path, result_name: str) -> dict[str, object]:
    """Exercise report plumbing with synthetic fixtures, never real datasets."""
    run = allocate_run(output_dir, result_name)
    candidate = {"id": "fixture-candidate", "path": "BenchmarkTest00001.java", "cwes": [22]}
    units = [{"test_id": "BenchmarkTest00001", "cwe": 22, "vulnerable": True}]
    verdict = {"fixture-candidate": {"effective_verdict": "UNCERTAIN", "error": "fixture_only"}}
    evaluated = evaluate_variants("owasp", units, [candidate], verdict, verdict)
    candidate_hash = hashlib.sha256(json.dumps([candidate], sort_keys=True).encode("utf-8")).hexdigest()
    manifest = {
        "schema_version": 1, "status": "mock_completed", "purpose": "fixture_only",
        "run_id": run.name, "candidate_sha256": {name: candidate_hash for name in ("A", "B", "C")},
        "variants": ["A", "B", "C"], "dataset": "synthetic_fixture",
    }
    (run / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    (run / "fixture-input.json").write_text(json.dumps({"units": units, "findings": [candidate],
                                                    "verdicts": verdict}, indent=2) + "\n", encoding="utf-8")
    reports = run / "reports"
    rows = [{"dataset": "synthetic_fixture", "mode": "mock", "variant": variant,
             "status": "mock_completed", **outcome["overall"]} for variant, outcome in evaluated.items()]
    finding_rows = [{"dataset": "synthetic_fixture", "mode": "mock", "variant": variant,
                     "candidate_id": candidate["id"], "effective_verdict": "UNCERTAIN" if variant != "A" else "CANDIDATE"}
                    for variant in ("A", "B", "C")]
    unit_rows = [{"dataset": "synthetic_fixture", "mode": "mock", "variant": variant,
                  "unit_id": units[0]["test_id"], "cwe": 22, "vulnerable": True,
                  "candidate_ids": candidate["id"], "outcome": evaluated[variant]["matches"][0]["outcome"]}
                 for variant in ("A", "B", "C")]
    write_reports(reports, run.name, "../manifest.json", rows, finding_rows, unit_rows)
    return {"status": "mock_completed", "run_directory": str(run)}
