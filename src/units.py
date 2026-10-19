import csv
import json
from pathlib import Path


class UnitError(ValueError):
    pass


def load(path: Path) -> list[dict[str, object]]:
    rows = []
    try:
        with path.open(encoding="utf-8", newline="") as stream:
            for row in csv.reader(line for line in stream if not line.startswith("#")):
                if len(row) != 4 or not row[0].startswith("BenchmarkTest") or row[2] not in {"true", "false"}:
                    raise UnitError("invalid OWASP expected-results row")
                rows.append({"test_id": row[0], "cwe": int(row[3]), "vulnerable": row[2] == "true"})
    except OSError as error:
        raise UnitError(str(error)) from error
    return rows


def write(path: Path, rows: list[dict[str, object]]) -> None:
    if path.exists():
        raise UnitError(f"output already exists: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(rows, indent=2), encoding="utf-8")

