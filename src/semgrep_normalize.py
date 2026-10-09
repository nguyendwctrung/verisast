import hashlib
import json
import re
from pathlib import Path
from typing import cast

from semgrep_rules import sha256_file

TEST_ID_PATTERN = re.compile(r"BenchmarkTest\d{5}")


class NormalizeError(ValueError):
    pass


def normalize_findings(
    dataset_dir: Path,
    dataset_commit: str,
    scans: list[dict[str, object]],
) -> tuple[list[dict[str, object]], int]:
    dataset_dir = dataset_dir.resolve()
    candidates: dict[str, dict[str, object]] = {}
    raw_count = 0
    for scan in scans:
        raw_path = Path(str(scan["stdout_path"])).resolve()
        if sha256_file(raw_path) != scan.get("stdout_sha256"):
            raise NormalizeError(f"raw output hash mismatch: {raw_path}")
        try:
            payload = json.loads(raw_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as error:
            raise NormalizeError(f"failed to read raw output: {error}") from error
        results = payload.get("results") if isinstance(payload, dict) else None
        if not isinstance(results, list):
            raise NormalizeError("raw results must be a list")
        for index, result in enumerate(results):
            raw_count += 1
            candidate = _normalize_result(dataset_dir, dataset_commit, scan, result)
            candidate_id = str(candidate["candidate_id"])
            reference = {
                "raw_path": str(raw_path),
                "raw_sha256": scan["stdout_sha256"],
                "result_index": index,
            }
            if candidate_id in candidates:
                references = cast(
                    list[dict[str, object]],
                    candidates[candidate_id]["raw_references"],
                )
                references.append(reference)
            else:
                candidate["raw_references"] = [reference]
                candidates[candidate_id] = candidate
    return sorted(candidates.values(), key=lambda item: str(item["candidate_id"])), raw_count


def _normalize_result(
    dataset_dir: Path,
    dataset_commit: str,
    scan: dict[str, object],
    value: object,
) -> dict[str, object]:
    if not isinstance(value, dict):
        raise NormalizeError("Semgrep result must be an object")
    path_value = value.get("path")
    if not isinstance(path_value, str) or not path_value:
        raise NormalizeError("Semgrep result has invalid path")
    path = Path(path_value)
    if not path.is_absolute():
        path = dataset_dir / path
    path = path.resolve()
    if not path.is_relative_to(dataset_dir):
        raise NormalizeError(f"finding path is outside dataset: {path}")
    start = _position(value.get("start"), "start")
    end = _position(value.get("end"), "end")
    if (end["line"], end["col"]) < (start["line"], start["col"]):
        raise NormalizeError("finding end precedes start")
    relative_path = path.relative_to(dataset_dir).as_posix()
    canonical = {
        "dataset_commit": dataset_commit,
        "rule_identity": scan["rule_identity"],
        "rule_sha256": scan["rule_sha256"],
        "path": relative_path,
        "start": start,
        "end": end,
    }
    candidate_id = hashlib.sha256(
        json.dumps(canonical, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    raw_extra = value.get("extra")
    extra: dict[str, object] = (
        cast(dict[str, object], raw_extra) if isinstance(raw_extra, dict) else {}
    )
    test_match = TEST_ID_PATTERN.search(path.stem)
    return {
        "candidate_id": candidate_id,
        "dataset_commit": dataset_commit,
        "rule_identity": scan["rule_identity"],
        "rule_id": scan["rule_id"],
        "rule_path": scan["rule_path"],
        "rule_sha256": scan["rule_sha256"],
        "reviewed_cwes": scan["reviewed_cwes"],
        "raw_check_id": value.get("check_id"),
        "path": relative_path,
        "test_id": test_match.group(0) if test_match else None,
        "start": start,
        "end": end,
        "message": extra.get("message"),
        "severity": extra.get("severity"),
        "lines": extra.get("lines"),
        "metavars": extra.get("metavars", {}),
        "dataflow_trace": extra.get("dataflow_trace"),
    }


def _position(value: object, label: str) -> dict[str, int | None]:
    if not isinstance(value, dict):
        raise NormalizeError(f"finding has invalid {label} position")
    line = value.get("line")
    col = value.get("col")
    offset = value.get("offset")
    if not isinstance(line, int) or line < 1 or not isinstance(col, int) or col < 1:
        raise NormalizeError(f"finding has invalid {label} position")
    if offset is not None and (not isinstance(offset, int) or offset < 0):
        raise NormalizeError(f"finding has invalid {label} offset")
    return {"line": line, "col": col, "offset": offset}
