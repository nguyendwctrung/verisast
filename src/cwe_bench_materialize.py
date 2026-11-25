import csv
import hashlib
import json
import os
import re
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable


class MaterializationError(ValueError):
    pass


CommandRunner = Callable[[list[str], Path | None], subprocess.CompletedProcess[str]]


def materialize(
    snapshot: Path,
    shortlist_path: Path,
    dataset_root: Path,
    output: Path,
    runner: CommandRunner | None = None,
) -> dict[str, object]:
    """Materialize preregistered CWE-Bench buggy/fixed pairs without overwrite."""
    if output.exists():
        raise MaterializationError(f"materialization output already exists: {output}")
    snapshot = snapshot.resolve()
    if not snapshot.is_dir():
        raise MaterializationError(f"snapshot directory not found: {snapshot}")
    shortlist = _read_json(shortlist_path)
    if shortlist.get("status") != "preregistered_acquisition_shortlist":
        raise MaterializationError("shortlist is not preregistered for acquisition")
    snapshot_contract = shortlist.get("snapshot")
    if not isinstance(snapshot_contract, dict):
        raise MaterializationError("shortlist snapshot contract is missing")
    slugs = shortlist.get("project_slugs")
    if not isinstance(slugs, list) or not slugs or not all(isinstance(slug, str) and slug for slug in slugs):
        raise MaterializationError("shortlist project_slugs must be a non-empty string array")
    if len(slugs) != len(set(slugs)):
        raise MaterializationError("shortlist project_slugs must be unique")
    if any(re.fullmatch(r"[A-Za-z0-9._-]+", slug) is None or slug in {".", ".."} for slug in slugs):
        raise MaterializationError("shortlist contains an unsafe project slug")

    data = snapshot / "data"
    metadata_names = ("project_info.csv", "fix_info.csv", "build_info.csv")
    expected_hashes = snapshot_contract.get("metadata_sha256")
    if not isinstance(expected_hashes, dict):
        raise MaterializationError("snapshot metadata hashes are missing")
    observed_hashes = {}
    for name in metadata_names:
        path = data / name
        if not path.is_file():
            raise MaterializationError(f"snapshot metadata not found: {path}")
        observed_hashes[name] = _hash(path.read_bytes())
        if observed_hashes[name] != str(expected_hashes.get(name, "")).lower():
            raise MaterializationError(f"metadata hash mismatch: {name}")

    projects = _read_csv(data / "project_info.csv")
    expected_count = snapshot_contract.get("project_count")
    if not isinstance(expected_count, int) or len(projects) != expected_count:
        raise MaterializationError("snapshot project count mismatch")
    by_slug = {row.get("project_slug", ""): row for row in projects}
    if len(by_slug) != len(projects):
        raise MaterializationError("snapshot project slugs are not unique")
    unknown = [slug for slug in slugs if slug not in by_slug]
    if unknown:
        raise MaterializationError(f"shortlist contains unknown project slug: {unknown[0]}")
    ground_truth_rows = _read_csv(data / "fix_info.csv")
    ground_truth = {
        slug: [row for row in ground_truth_rows if row.get("project_slug") == slug]
        for slug in slugs
    }
    if any(not rows for rows in ground_truth.values()):
        missing = next(slug for slug, rows in ground_truth.items() if not rows)
        raise MaterializationError(f"shortlist lacks ground truth: {missing}")

    output.mkdir(parents=True)
    commands_path = output / "commands.jsonl"
    command_records: list[dict[str, object]] = []
    runner = runner or _run_command

    def run(arguments: list[str], cwd: Path | None = None) -> str:
        result = runner(arguments, cwd)
        record = {
            "arguments": arguments,
            "cwd": str(cwd.resolve()) if cwd is not None else None,
            "returncode": result.returncode,
            "stdout": result.stdout,
            "stderr": result.stderr,
        }
        command_records.append(record)
        _write_jsonl(commands_path, command_records)
        if result.returncode:
            message = result.stderr.strip() or result.stdout.strip() or "unknown Git error"
            raise MaterializationError(f"command failed: {message}")
        return result.stdout.strip()

    records: list[dict[str, object]] = []
    try:
        revision = run(["git", "-C", str(snapshot), "rev-parse", "HEAD"])
        expected_revision = snapshot_contract.get("revision")
        if revision != expected_revision:
            raise MaterializationError("snapshot revision mismatch")
        if run(["git", "-C", str(snapshot), "status", "--porcelain"]):
            raise MaterializationError("snapshot worktree is not clean")
        dataset_root = dataset_root.resolve()
        dataset_root.mkdir(parents=True, exist_ok=True)
        for slug in slugs:
            project = by_slug[slug]
            record = _materialize_pair(
                slug, project, ground_truth[slug], dataset_root, output.name, run,
            )
            records.append(record)
            _write_jsonl(output / "records.jsonl", records)
    except (MaterializationError, OSError) as error:
        manifest = _manifest(
            "failed", snapshot, shortlist_path, dataset_root, revision if "revision" in locals() else None,
            observed_hashes, records, commands_path, error=str(error),
        )
        _write_json(output / "manifest.json", manifest)
        raise MaterializationError(str(error)) from error

    manifest = _manifest(
        "complete", snapshot, shortlist_path, dataset_root, revision,
        observed_hashes, records, commands_path,
    )
    _write_json(output / "manifest.json", manifest)
    return manifest


def _materialize_pair(
    slug: str,
    project: dict[str, str],
    ground_truth: list[dict[str, str]],
    dataset_root: Path,
    run_id: str,
    run: Callable[[list[str], Path | None], str],
) -> dict[str, object]:
    remote_url = project.get("github_url", "").strip()
    buggy_commit = project.get("buggy_commit_id", "").strip().lower()
    fix_commits = [value.strip().lower() for value in project.get("fix_commit_ids", "").split(";") if value.strip()]
    if not remote_url or not _is_revision(buggy_commit) or not fix_commits or not all(_is_revision(value) for value in fix_commits):
        raise MaterializationError(f"invalid source metadata: {slug}")
    commits = {"buggy": buggy_commit, "fixed": fix_commits[-1]}
    target = dataset_root / slug
    marker = target / ".verisast-materialization-incomplete.json"
    if target.exists() and not marker.is_file():
        status = "reused_verified"
        _verify_pair(target, remote_url, commits, run)
    else:
        status = "resumed_materialization" if target.exists() else "materialized"
        if target.exists():
            marker_payload = _read_json(marker)
            if marker_payload.get("project_slug") != slug or marker_payload.get("commits") != commits:
                raise MaterializationError(f"incomplete materialization marker mismatch: {target}")
        else:
            target.mkdir()
            _write_json(marker, {
                "schema_version": 1,
                "project_slug": slug,
                "remote_url": remote_url,
                "commits": commits,
                "run_id": run_id,
            })
        for role, commit in commits.items():
            source = target / role
            if source.exists():
                _verify_revision(source, remote_url, commit, run)
                continue
            run(["git", "init", str(source)])
            run(["git", "-C", str(source), "remote", "add", "origin", remote_url])
            run(["git", "-C", str(source), "-c", "maintenance.auto=false", "-c", "gc.auto=0", "fetch", "--depth", "1", "origin", commit])
            run(["git", "-C", str(source), "checkout", "--detach", commit])
        _verify_pair(target, remote_url, commits, run)
        marker.unlink()
    paths = sorted({row.get("file", "") for row in ground_truth if row.get("file")})
    return {
        "schema_version": 1,
        "project_slug": slug,
        "cve_id": project.get("cve_id"),
        "cwe_id": project.get("cwe_id"),
        "remote_url": remote_url,
        "status": status,
        "fix_commit_sequence": fix_commits,
        "revisions": {
            role: {"commit": commit, "source_path": str((target / role).resolve())}
            for role, commit in commits.items()
        },
        "ground_truth": [
            {
                "file": row.get("file"),
                "class": row.get("class"),
                "method": row.get("method"),
                "signature": row.get("signature"),
            }
            for row in ground_truth
        ],
        "ground_truth_file_presence": {
            role: {path: (target / role / path).is_file() for path in paths}
            for role in ("buggy", "fixed")
        },
    }


def _verify_pair(
    pair: Path,
    remote_url: str,
    commits: dict[str, str],
    run: Callable[[list[str], Path | None], str],
) -> None:
    for role, commit in commits.items():
        source = pair / role
        _verify_revision(source, remote_url, commit, run)


def _verify_revision(
    source: Path,
    remote_url: str,
    commit: str,
    run: Callable[[list[str], Path | None], str],
) -> None:
    if not (source / ".git").exists():
        raise MaterializationError(f"pair role is not a Git worktree: {source}")
    if run(["git", "-C", str(source), "rev-parse", "HEAD"]).lower() != commit:
        raise MaterializationError(f"pair revision mismatch: {source}")
    observed_remote = run(["git", "-C", str(source), "remote", "get-url", "origin"])
    if _normalize_remote(observed_remote) != _normalize_remote(remote_url):
        raise MaterializationError(f"pair remote mismatch: {source}")
    if run(["git", "-C", str(source), "status", "--porcelain"]):
        raise MaterializationError(f"pair worktree is not clean: {source}")


def _promote(staging: Path, target: Path, attempts: int = 6) -> None:
    """Promote a verified pair, tolerating short-lived Windows file locks."""
    for attempt in range(attempts):
        if target.exists():
            raise MaterializationError(f"materialization target already exists: {target}")
        try:
            os.replace(staging, target)
            return
        except PermissionError as error:
            if attempt == attempts - 1:
                raise MaterializationError(
                    f"cannot promote staging directory after {attempts} attempts: {error}"
                ) from error
            time.sleep(0.25 * (attempt + 1))


def _manifest(
    status: str,
    snapshot: Path,
    shortlist_path: Path,
    dataset_root: Path,
    revision: str | None,
    metadata_hashes: dict[str, str],
    records: list[dict[str, object]],
    commands_path: Path,
    error: str | None = None,
) -> dict[str, object]:
    materialized_count = sum(record["status"] in {"materialized", "resumed_materialization"} for record in records)
    reused_count = sum(record["status"] == "reused_verified" for record in records)
    resumed_count = sum(record["status"] == "resumed_materialization" for record in records)
    manifest = {
        "schema_version": 1,
        "status": status,
        "purpose": "od-002-source-materialization-only",
        "created_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "snapshot": {
            "path": str(snapshot),
            "revision": revision,
            "metadata_sha256": metadata_hashes,
        },
        "shortlist": {
            "path": str(shortlist_path.resolve()),
            "sha256": _hash(shortlist_path.read_bytes()),
        },
        "dataset_root": str(dataset_root.resolve()),
        "record_count": len(records),
        "materialized_count": materialized_count,
        "reused_count": reused_count,
        "resumed_count": resumed_count,
        "records": {
            "path": "records.jsonl",
            "sha256": _hash((commands_path.parent / "records.jsonl").read_bytes())
            if (commands_path.parent / "records.jsonl").is_file() else None,
        },
        "commands": {
            "path": "commands.jsonl",
            "sha256": _hash(commands_path.read_bytes()) if commands_path.is_file() else None,
        },
        "next_gate": "manual provenance and ground-truth review before CodeQL feasibility",
    }
    if error is not None:
        manifest["error"] = error
    return manifest


def _read_json(path: Path) -> dict[str, object]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise MaterializationError(f"cannot read shortlist: {error}") from error
    if not isinstance(payload, dict):
        raise MaterializationError("shortlist must be an object")
    return payload


def _read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8-sig", newline="") as stream:
        return list(csv.DictReader(stream))


def _run_command(arguments: list[str], cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(arguments, cwd=cwd, text=True, capture_output=True, check=False)


def _write_json(path: Path, payload: dict[str, object]) -> None:
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _write_jsonl(path: Path, records: list[dict[str, object]]) -> None:
    path.write_text(
        "".join(json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n" for record in records),
        encoding="utf-8",
    )


def _hash(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def _is_revision(value: str) -> bool:
    return re.fullmatch(r"[0-9a-f]{40}", value) is not None


def _normalize_remote(value: str) -> str:
    normalized = value.strip().lower().rstrip("/")
    return normalized[:-4] if normalized.endswith(".git") else normalized
