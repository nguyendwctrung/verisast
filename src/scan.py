import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path


class ScanError(RuntimeError):
    pass


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
    for command in commands:
        result = subprocess.run(command, text=True, capture_output=True, check=False)
        record = {"command": command, "exit_code": result.returncode, "stdout": result.stdout, "stderr": result.stderr}
        records.append(record)
        if result.returncode:
            status = "failed"
            break
    (raw / "commands.json").write_text(json.dumps(records, indent=2), encoding="utf-8")
    manifest = {
        "schema_version": 1,
        "scanner": "codeql",
        "status": status,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "source": str(source),
        "suite": suite,
        "database": str(database),
        "sarif": str(raw / "results.sarif"),
        "commands": "raw/commands.json",
    }
    (output / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    if status != "complete":
        raise ScanError(f"CodeQL command failed; inspect {raw / 'commands.json'}")
    return manifest

