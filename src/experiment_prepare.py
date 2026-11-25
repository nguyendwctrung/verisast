"""Prepare a provenance-bound acquisition roster for the pinned CWE-Bench snapshot."""

import csv
import hashlib
import json
import re
import subprocess
from pathlib import Path


class PreparationError(ValueError):
    pass


def _rows(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8-sig", newline="") as stream:
        return list(csv.DictReader(stream))


def _hash(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def prepare_cwe_bench(
    snapshot: Path, output: Path, expected_count: int = 120,
    expected_revision: str | None = "afe0ebd0adc237abb46255f9cd479b1d71819136",
) -> dict[str, object]:
    """List every pinned target and generate an acquirable metadata-only shortlist."""
    if output.exists():
        raise PreparationError(f"preparation output already exists: {output}")
    data = snapshot / "data"
    names = ("project_info.csv", "fix_info.csv", "build_info.csv")
    for name in names:
        if not (data / name).is_file():
            raise PreparationError(f"CWE-Bench metadata missing: {data / name}")
    projects = _rows(data / "project_info.csv")
    fixes = _rows(data / "fix_info.csv")
    if len(projects) != expected_count or len({row["project_slug"] for row in projects}) != expected_count:
        raise PreparationError(f"expected {expected_count} unique CWE-Bench projects")
    revision = None
    if expected_revision is not None:
        result = subprocess.run(["git", "-C", str(snapshot), "rev-parse", "HEAD"],
                                capture_output=True, text=True, check=False)
        revision = result.stdout.strip() if result.returncode == 0 else None
        if revision != expected_revision:
            raise PreparationError("CWE-Bench snapshot revision differs from pinned source")
    ground_truth = {}
    for row in fixes:
        ground_truth.setdefault(row.get("project_slug", ""), []).append(row)
    roster = []
    acquirable = []
    for project in projects:
        slug = project["project_slug"]
        missing = [key for key in ("cve_id", "cwe_id", "github_url", "buggy_commit_id", "fix_commit_ids")
                   if not project.get(key)]
        commits = [part.strip().lower() for part in project.get("fix_commit_ids", "").split(";") if part.strip()]
        if re.fullmatch(r"[0-9a-f]{40}", project.get("buggy_commit_id", "").lower()) is None or not commits or any(
            re.fullmatch(r"[0-9a-f]{40}", commit) is None for commit in commits
        ):
            missing.append("immutable_commits")
        if not any(fix.get("file") and (fix.get("method") or fix.get("class"))
                   for fix in ground_truth.get(slug, [])):
            missing.append("ground_truth_file_symbol")
        record = {"project_slug": slug, "cve_id": project.get("cve_id"),
                  "cwe_id": project.get("cwe_id"), "source_url": project.get("github_url"),
                  "status": "metadata_complete" if not missing else "metadata_blocked",
                  "missing": sorted(set(missing))}
        roster.append(record)
        if not missing:
            acquirable.append(slug)
    output.mkdir(parents=True)
    shortlist = {
        "schema_version": 1, "status": "preregistered_acquisition_shortlist",
        "purpose": "source_acquisition_only_not_an_experiment_cohort",
        "snapshot": {
            "repository": "https://github.com/iris-sast/cwe-bench-java.git",
            "revision": expected_revision or revision,
            "project_count": expected_count,
            "metadata_sha256": {name: _hash(data / name) for name in names},
        },
        "project_slugs": acquirable,
        "final_cohort_selected": False,
        "held_out_execution_authorized": False,
    }
    (output / "acquisition-shortlist.json").write_text(json.dumps(shortlist, indent=2) + "\n", encoding="utf-8")
    (output / "roster.jsonl").write_text("".join(json.dumps(row, sort_keys=True) + "\n" for row in roster), encoding="utf-8")
    manifest = {
        "schema_version": 1, "status": "prepared_not_executed", "project_count": len(projects),
        "acquirable_count": len(acquirable), "blocked_count": len(projects) - len(acquirable),
        "source_repository": "https://github.com/iris-sast/cwe-bench-java.git",
        "snapshot_revision": expected_revision or revision,
        "metadata_sha256": shortlist["snapshot"]["metadata_sha256"],
        "roster_sha256": _hash(output / "roster.jsonl"),
        "shortlist_sha256": _hash(output / "acquisition-shortlist.json"),
        "next_step": "review roster and run explicit source materialization; resolve blocked metadata before full execution",
    }
    (output / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return manifest
