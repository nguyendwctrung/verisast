import json
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path


class ScanError(RuntimeError):
    pass


def _raw_result_count(sarif_path: Path) -> int:
    try:
        payload = json.loads(sarif_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ScanError(f"cannot count CodeQL SARIF results: {error}") from error
    runs = payload.get("runs")
    if not isinstance(runs, list):
        raise ScanError("CodeQL SARIF lacks runs")
    count = 0
    for run in runs:
        if not isinstance(run, dict) or not isinstance(run.get("results", []), list):
            raise ScanError("CodeQL SARIF run lacks results")
        count += len(run["results"])
    return count


def run(source: Path, output: Path, codeql: str, suite: str) -> dict[str, object]:
    source = source.resolve()
    output = output.resolve()
    if not source.is_dir():
        raise ScanError(f"source directory not found: {source}")
    if output.exists():
        raise ScanError(f"run directory already exists: {output}")
    output.mkdir(parents=True)
    raw = output / "raw"
    raw.mkdir()
    database = output / "database"
    commands = [
        [codeql, "version"],
        [codeql, "database", "create", str(database), "--language=java-kotlin", "--build-mode=none", f"--source-root={source}"],
        [codeql, "database", "analyze", str(database), suite, "--format=sarif-latest", f"--output={raw / 'results.sarif'}", "--threads=0"],
    ]
    records = []
    status = "complete"
    started_at = datetime.now(timezone.utc).isoformat()
    started = time.monotonic()
    for command in commands:
        command_started_at = datetime.now(timezone.utc).isoformat()
        command_started = time.monotonic()
        result = subprocess.run(command, text=True, capture_output=True, check=False)
        record = {
            "command": command,
            "started_at": command_started_at,
            "finished_at": datetime.now(timezone.utc).isoformat(),
            "duration_seconds": round(time.monotonic() - command_started, 3),
            "exit_code": result.returncode,
            "stdout": result.stdout,
            "stderr": result.stderr,
        }
        records.append(record)
        if result.returncode:
            status = "failed"
            break
    (raw / "commands.json").write_text(json.dumps(records, indent=2), encoding="utf-8")
    if status != "complete":
        finished_at = datetime.now(timezone.utc).isoformat()
        manifest = {
            "schema_version": 1,
            "scanner": "codeql",
            "status": status,
            "created_at": finished_at,
            "started_at": started_at,
            "finished_at": finished_at,
            "duration_seconds": round(time.monotonic() - started, 3),
            "source": str(source),
            "suite": suite,
            "database": str(database),
            "sarif": str(raw / "results.sarif"),
            "commands": "raw/commands.json",
        }
        (output / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
        raise ScanError(f"CodeQL command failed; inspect {raw / 'commands.json'}")
    raw_result_count = _raw_result_count(raw / "results.sarif")
    finished_at = datetime.now(timezone.utc).isoformat()
    manifest = {
        "schema_version": 1,
        "scanner": "codeql",
        "status": status,
        "created_at": finished_at,
        "started_at": started_at,
        "finished_at": finished_at,
        "duration_seconds": round(time.monotonic() - started, 3),
        "source": str(source),
        "suite": suite,
        "database": str(database),
        "sarif": str(raw / "results.sarif"),
        "commands": "raw/commands.json",
        "raw_result_count": raw_result_count,
    }
    (output / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print(f"CODEQL_COMPLETE raw_results={raw_result_count} elapsed_s={manifest['duration_seconds']}")
    return manifest

