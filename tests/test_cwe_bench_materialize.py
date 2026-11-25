import csv
import hashlib
import json
from pathlib import Path
from subprocess import CompletedProcess

import pytest

from cwe_bench_materialize import MaterializationError, _promote, materialize


SNAPSHOT_REVISION = "a" * 40
BUGGY_REVISION = "b" * 40
FIXED_REVISION = "c" * 40
SLUG = "owner__repository_CVE-2024-1000_1.0"


def _write_snapshot(snapshot: Path) -> dict[str, str]:
    data = snapshot / "data"
    data.mkdir(parents=True)
    with (data / "project_info.csv").open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=[
            "project_slug", "cve_id", "cwe_id", "github_url",
            "buggy_commit_id", "fix_commit_ids",
        ])
        writer.writeheader()
        writer.writerow({
            "project_slug": SLUG,
            "cve_id": "CVE-2024-1000",
            "cwe_id": "CWE-022",
            "github_url": "https://example.invalid/owner/repository.git",
            "buggy_commit_id": BUGGY_REVISION,
            "fix_commit_ids": f"{'d' * 40};{FIXED_REVISION}",
        })
    with (data / "fix_info.csv").open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=["project_slug", "file", "class", "method", "signature"])
        writer.writeheader()
        writer.writerow({
            "project_slug": SLUG,
            "file": "src/main/java/Target.java",
            "class": "Target",
            "method": "read",
            "signature": "void read()",
        })
    (data / "build_info.csv").write_text("project_slug,status\n", encoding="utf-8")
    return {
        name: hashlib.sha256((data / name).read_bytes()).hexdigest()
        for name in ("project_info.csv", "fix_info.csv", "build_info.csv")
    }


def _write_shortlist(path: Path, hashes: dict[str, str]) -> None:
    path.write_text(json.dumps({
        "schema_version": 1,
        "status": "preregistered_acquisition_shortlist",
        "snapshot": {
            "revision": SNAPSHOT_REVISION,
            "project_count": 1,
            "metadata_sha256": hashes,
        },
        "project_slugs": [SLUG],
    }), encoding="utf-8")


class FakeGit:
    def __call__(self, arguments: list[str], cwd: Path | None = None) -> CompletedProcess[str]:
        if arguments[:2] == ["git", "init"]:
            Path(arguments[2]).mkdir(parents=True)
            (Path(arguments[2]) / ".git").mkdir()
        if arguments[:2] == ["git", "-C"] and arguments[3:5] == ["checkout", "--detach"]:
            (Path(arguments[2]) / ".revision").write_text(arguments[5], encoding="utf-8")
            target = Path(arguments[2]) / "src/main/java/Target.java"
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text("class Target {}", encoding="utf-8")
        stdout = ""
        if arguments[-2:] == ["rev-parse", "HEAD"]:
            path = Path(arguments[2])
            stdout = SNAPSHOT_REVISION if path.name == "snapshot" else (path / ".revision").read_text(encoding="utf-8")
        elif arguments[-3:] == ["remote", "get-url", "origin"]:
            stdout = "https://example.invalid/owner/repository.git"
        elif arguments[-2:] == ["status", "--porcelain"]:
            stdout = ""
        return CompletedProcess(arguments, 0, stdout=stdout, stderr="")


def test_materialize_writes_verified_pairs_and_provenance(tmp_path: Path) -> None:
    snapshot = tmp_path / "snapshot"
    hashes = _write_snapshot(snapshot)
    shortlist = tmp_path / "shortlist.json"
    _write_shortlist(shortlist, hashes)

    result = materialize(snapshot, shortlist, tmp_path / "pairs", tmp_path / "run", runner=FakeGit())

    assert result["status"] == "complete"
    assert result["materialized_count"] == 1
    assert result["reused_count"] == 0
    pair = tmp_path / "pairs" / SLUG
    assert (pair / "buggy" / ".git").is_dir()
    assert (pair / "fixed" / ".git").is_dir()
    assert not (pair / ".verisast-materialization-incomplete.json").exists()
    record = json.loads((tmp_path / "run" / "records.jsonl").read_text(encoding="utf-8").strip())
    assert record["revisions"]["buggy"]["commit"] == BUGGY_REVISION
    assert record["revisions"]["fixed"]["commit"] == FIXED_REVISION
    assert record["ground_truth"][0]["file"] == "src/main/java/Target.java"
    assert (tmp_path / "run" / "commands.jsonl").is_file()
    assert result["records"]["sha256"]


def test_materialize_is_no_overwrite(tmp_path: Path) -> None:
    snapshot = tmp_path / "snapshot"
    hashes = _write_snapshot(snapshot)
    shortlist = tmp_path / "shortlist.json"
    _write_shortlist(shortlist, hashes)
    output = tmp_path / "run"
    output.mkdir()

    with pytest.raises(MaterializationError, match="already exists"):
        materialize(snapshot, shortlist, tmp_path / "pairs", output, runner=FakeGit())


def test_materialize_rejects_snapshot_hash_mismatch(tmp_path: Path) -> None:
    snapshot = tmp_path / "snapshot"
    hashes = _write_snapshot(snapshot)
    shortlist = tmp_path / "shortlist.json"
    hashes["project_info.csv"] = "0" * 64
    _write_shortlist(shortlist, hashes)

    with pytest.raises(MaterializationError, match="metadata hash mismatch"):
        materialize(snapshot, shortlist, tmp_path / "pairs", tmp_path / "run", runner=FakeGit())


def test_materialize_retains_marker_and_resumes_incomplete_pair(tmp_path: Path) -> None:
    snapshot = tmp_path / "snapshot"
    hashes = _write_snapshot(snapshot)
    shortlist = tmp_path / "shortlist.json"
    _write_shortlist(shortlist, hashes)
    pair = tmp_path / "pairs" / SLUG
    pair.mkdir(parents=True)
    (pair / ".verisast-materialization-incomplete.json").write_text(json.dumps({
        "schema_version": 1,
        "project_slug": SLUG,
        "remote_url": "https://example.invalid/owner/repository.git",
        "commits": {"buggy": BUGGY_REVISION, "fixed": FIXED_REVISION},
        "run_id": "failed-run",
    }), encoding="utf-8")

    result = materialize(snapshot, shortlist, tmp_path / "pairs", tmp_path / "run", runner=FakeGit())

    assert result["resumed_count"] == 1
    assert not (pair / ".verisast-materialization-incomplete.json").exists()


def test_materialize_rejects_duplicate_or_unknown_slugs(tmp_path: Path) -> None:
    snapshot = tmp_path / "snapshot"
    hashes = _write_snapshot(snapshot)
    shortlist = tmp_path / "shortlist.json"
    _write_shortlist(shortlist, hashes)
    payload = json.loads(shortlist.read_text(encoding="utf-8"))
    payload["project_slugs"] = [SLUG, SLUG]
    shortlist.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(MaterializationError, match="unique"):
        materialize(snapshot, shortlist, tmp_path / "pairs", tmp_path / "run", runner=FakeGit())


def test_materialize_rejects_unsafe_slug(tmp_path: Path) -> None:
    snapshot = tmp_path / "snapshot"
    hashes = _write_snapshot(snapshot)
    shortlist = tmp_path / "shortlist.json"
    _write_shortlist(shortlist, hashes)
    payload = json.loads(shortlist.read_text(encoding="utf-8"))
    payload["project_slugs"] = ["../outside"]
    shortlist.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(MaterializationError, match="unsafe"):
        materialize(snapshot, shortlist, tmp_path / "pairs", tmp_path / "run", runner=FakeGit())


def test_promote_retries_transient_windows_access_denied(tmp_path: Path, monkeypatch) -> None:
    staging = tmp_path / "staging"
    target = tmp_path / "target"
    staging.mkdir()
    real_replace = __import__("os").replace
    attempts = 0

    def replace(source: Path, destination: Path) -> None:
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise PermissionError(5, "Access is denied")
        real_replace(source, destination)

    monkeypatch.setattr("cwe_bench_materialize.os.replace", replace)
    monkeypatch.setattr("cwe_bench_materialize.time.sleep", lambda _: None)

    _promote(staging, target)

    assert attempts == 2
    assert target.is_dir()
    assert not staging.exists()
