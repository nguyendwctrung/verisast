"""Outcome-independent selection and preflight for Phase 5 experiments."""

import csv
import hashlib
import re
import subprocess
from pathlib import Path


class ExperimentError(ValueError):
    pass


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def read_labels(path: Path) -> list[dict[str, object]]:
    rows = []
    with path.open(encoding="utf-8", newline="") as stream:
        for row in csv.reader(line for line in stream if not line.startswith("#")):
            if len(row) != 4 or not re.fullmatch(r"BenchmarkTest\d{5}", row[0]) or row[2] not in {"true", "false"}:
                raise ExperimentError(f"invalid OWASP ground-truth row: {row}")
            rows.append({"test_id": row[0], "cwe": int(row[3]), "vulnerable": row[2] == "true"})
    if len({row["test_id"] for row in rows}) != len(rows):
        raise ExperimentError("duplicate OWASP testcase ID")
    return rows


def build_owasp_selection(labels: Path, selected_ids: dict[str, list[str]]) -> list[dict[str, object]]:
    by_id = {str(row["test_id"]): row for row in read_labels(labels)}
    rows = []
    for cwe, ids in selected_ids.items():
        if not ids or len(ids) != len(set(ids)):
            raise ExperimentError(f"invalid selected IDs for CWE-{cwe}")
        chosen = []
        for test_id in ids:
            row = by_id.get(test_id)
            if row is None or row["cwe"] != int(cwe) or row in rows:
                raise ExperimentError(f"invalid selected OWASP testcase: {test_id}")
            chosen.append(row)
            rows.append(row)
        if {row["vulnerable"] for row in chosen} != {True, False}:
            raise ExperimentError(f"CWE-{cwe} must include both ground-truth labels")
    return rows


def validate_reviewed_units(units: object, selected_slugs: list[str]) -> list[dict[str, object]]:
    """Require one reviewed target/CVE unit and symbol scope per revision."""
    if not isinstance(units, list) or not all(isinstance(unit, dict) for unit in units):
        raise ExperimentError("reviewed CWE-Bench units must be a JSON array")
    expected = {f"{slug}/{role}" for slug in selected_slugs for role in ("buggy", "fixed")}
    observed = [unit.get("target_id") for unit in units]
    if set(observed) != expected or len(observed) != len(expected):
        raise ExperimentError("reviewed CWE-Bench units must cover each selected buggy/fixed revision exactly once")
    for unit in units:
        target_id = unit["target_id"]
        if (unit.get("revision_role") != target_id.rsplit("/", 1)[-1]
                or not isinstance(unit.get("cve_id"), str) or not unit["cve_id"]
                or type(unit.get("cwe")) is not int):
            raise ExperimentError(f"invalid reviewed CWE-Bench unit identity: {target_id}")
        prefixes = unit.get("path_prefixes")
        ranges = unit.get("symbol_ranges")
        if not isinstance(prefixes, list) or not prefixes or not all(isinstance(item, str) and item for item in prefixes):
            raise ExperimentError(f"invalid reviewed path_prefixes: {target_id}")
        if not isinstance(ranges, list) or not ranges or any(
            not isinstance(item, dict) or not isinstance(item.get("path"), str)
            or type(item.get("start")) is not int or type(item.get("end")) is not int
            or item["start"] < 1 or item["end"] < item["start"]
            or not any(item["path"].startswith(prefix) for prefix in prefixes)
            for item in ranges
        ):
            raise ExperimentError(f"invalid reviewed symbol_ranges: {target_id}")
    return units


def verify_reviewed_unit_provenance(units: list[dict[str, object]], snapshot: Path,
                                    pairs: Path | None = None) -> list[str]:
    """Cross-check reviewed units against immutable upstream metadata fields."""
    data = snapshot / "data"
    with (data / "project_info.csv").open(encoding="utf-8", newline="") as stream:
        projects = {row["project_slug"]: row for row in csv.DictReader(stream)}
    with (data / "fix_info.csv").open(encoding="utf-8", newline="") as stream:
        fixes = list(csv.DictReader(stream))
    issues = []
    for unit in units:
        slug = str(unit["target_id"]).rsplit("/", 1)[0]
        project = projects.get(slug)
        if project is None:
            issues.append(f"reviewed unit lacks project metadata: {slug}")
            continue
        if unit["cve_id"] != project.get("cve_id"):
            issues.append(f"reviewed unit CVE differs from metadata: {slug}")
        expected_cwe = project.get("cwe_id", "")
        if not expected_cwe.startswith("CWE-") or not expected_cwe[4:].isdigit() or unit["cwe"] != int(expected_cwe[4:]):
            issues.append(f"reviewed unit CWE differs from metadata: {slug}")
        paths = {row.get("file") for row in fixes if row.get("project_slug") == slug}
        for item in unit["symbol_ranges"]:
            if item["path"] not in paths:
                issues.append(f"reviewed unit symbol path lacks ground-truth metadata: {slug}/{item['path']}")
            if pairs is not None:
                source = pairs / slug / str(unit["revision_role"]) / item["path"]
                if not source.is_file():
                    issues.append(f"reviewed unit symbol source missing: {source}")
                elif item["end"] > len(source.read_text(encoding="utf-8", errors="replace").splitlines()):
                    issues.append(f"reviewed unit symbol range exceeds source: {source}")
    return issues


def _git_head(path: Path) -> str | None:
    result = subprocess.run(["git", "-C", str(path), "rev-parse", "HEAD"],
                            capture_output=True, text=True, check=False)
    return result.stdout.strip() if result.returncode == 0 else None


def _git_output(path: Path, *arguments: str) -> str | None:
    result = subprocess.run(["git", "-C", str(path), *arguments],
                            capture_output=True, text=True, check=False)
    return result.stdout.strip() if result.returncode == 0 else None


def preflight(
    manifest: dict[str, object], owasp_source: Path | None, labels: Path | None,
    cwe_snapshot: Path | None, cwe_pairs: Path | None,
    approvals: dict[str, bool] | None = None,
) -> dict[str, object]:
    """Inspect local inputs without creating a run or invoking model/CodeQL."""
    issues = []
    mode = manifest.get("mode")
    if mode not in {"partial", "full"}:
        issues.append("mode must be partial or full")
    owasp = manifest.get("owasp")
    if isinstance(owasp, dict):
        if owasp_source is None or not owasp_source.is_dir():
            issues.append(f"OWASP source is missing: {owasp_source}")
        elif owasp.get("commit") and _git_head(owasp_source) != owasp["commit"]:
            issues.append("OWASP source commit differs from manifest")
        elif _git_output(owasp_source, "status", "--porcelain") != "":
            issues.append("OWASP source worktree is not clean")
        if labels is None or not labels.is_file():
            issues.append(f"OWASP ground truth is missing: {labels}")
        else:
            try:
                rows = read_labels(labels)
                if owasp.get("labels_sha256") and sha256(labels) != owasp["labels_sha256"]:
                    issues.append("OWASP ground-truth hash differs from manifest")
                expected = owasp.get("expected_count")
                if mode == "full" and expected != 2740:
                    issues.append("full OWASP manifest must require 2740 testcases")
                if mode == "full" and len(rows) != expected:
                    issues.append(f"OWASP ground truth has {len(rows)} of required {expected} testcases")
                if mode == "partial":
                    build_owasp_selection(labels, owasp.get("selected_ids", {}))
                if owasp_source is not None and owasp_source.is_dir():
                    selected_ids = ([row["test_id"] for row in rows] if mode == "full" else
                                    [test_id for ids in owasp.get("selected_ids", {}).values() for test_id in ids])
                    for test_id in selected_ids:
                        source_file = owasp_source / "src" / "main" / "java" / "org" / "owasp" / "benchmark" / "testcode" / f"{test_id}.java"
                        if not source_file.is_file():
                            issues.append(f"OWASP testcase source missing: {test_id}")
            except (OSError, ValueError, TypeError) as error:
                issues.append(f"OWASP ground truth invalid: {error}")
    cwe = manifest.get("cwe_bench")
    if isinstance(cwe, dict):
        project_info = cwe_snapshot / "data" / "project_info.csv" if cwe_snapshot else None
        if project_info is None or not project_info.is_file():
            issues.append(f"CWE-Bench project metadata is missing: {project_info}")
        else:
            if cwe.get("snapshot_commit") and _git_head(cwe_snapshot) != cwe["snapshot_commit"]:
                issues.append("CWE-Bench metadata snapshot commit differs from manifest")
            if _git_output(cwe_snapshot, "status", "--porcelain") != "":
                issues.append("CWE-Bench metadata snapshot worktree is not clean")
            if cwe.get("project_info_sha256") and sha256(project_info) != cwe["project_info_sha256"]:
                issues.append("CWE-Bench project metadata hash differs from manifest")
            for filename, key in (("fix_info.csv", "fix_info_sha256"),
                                  ("build_info.csv", "build_info_sha256")):
                path = cwe_snapshot / "data" / filename
                if not path.is_file():
                    issues.append(f"CWE-Bench metadata missing: {filename}")
                elif cwe.get(key) and sha256(path) != cwe[key]:
                    issues.append(f"CWE-Bench metadata hash differs: {filename}")
            with project_info.open(encoding="utf-8", newline="") as stream:
                projects = list(csv.DictReader(stream))
            fix_path = cwe_snapshot / "data" / "fix_info.csv"
            if fix_path.is_file():
                with fix_path.open(encoding="utf-8", newline="") as stream:
                    fixes = list(csv.DictReader(stream))
            else:
                fixes = []
            fixes_by_slug: dict[str, list[dict[str, str]]] = {}
            for fix in fixes:
                fixes_by_slug.setdefault(fix.get("project_slug", ""), []).append(fix)
            expected = cwe.get("expected_pair_count")
            if mode == "full" and expected != 120:
                issues.append("full CWE-Bench manifest must require 120 CVE pairs")
            if len(projects) != expected and mode == "full":
                issues.append(f"CWE-Bench metadata has {len(projects)} of required {expected} projects")
            selected = cwe.get("selected_slugs") if mode == "partial" else [row["project_slug"] for row in projects]
            if not isinstance(selected, list):
                issues.append("CWE-Bench selected slugs are invalid")
            else:
                indexed = {row["project_slug"]: row for row in projects}
                if len(selected) != len(set(selected)):
                    issues.append("CWE-Bench selected slugs contain duplicates")
                for slug in selected:
                    row = indexed.get(slug)
                    if row is None:
                        issues.append(f"CWE-Bench metadata lacks {slug}")
                        continue
                    if not all(row.get(key) for key in ("cve_id", "cwe_id", "github_url", "buggy_commit_id", "fix_commit_ids")):
                        issues.append(f"CWE-Bench incomplete project metadata: {slug}")
                    commits = [item.strip().lower() for item in row.get("fix_commit_ids", "").split(";") if item.strip()]
                    if re.fullmatch(r"[0-9a-f]{40}", row.get("buggy_commit_id", "").lower()) is None or not commits or any(
                        re.fullmatch(r"[0-9a-f]{40}", item) is None for item in commits
                    ):
                        issues.append(f"CWE-Bench immutable commits invalid: {slug}")
                    ground_truth = fixes_by_slug.get(slug, [])
                    if not ground_truth or not any(
                        fix.get("file") and (fix.get("method") or fix.get("class"))
                        for fix in ground_truth
                    ):
                        issues.append(f"CWE-Bench ground truth incomplete: {slug}")
                    expected_commits = {
                        "buggy": row.get("buggy_commit_id", "").lower(),
                        "fixed": commits[-1] if commits else "",
                    }
                    for role in ("buggy", "fixed"):
                        path = cwe_pairs / slug / role if cwe_pairs else None
                        if path is None or not path.is_dir():
                            issues.append(f"CWE-Bench source missing: {slug}/{role}")
                            continue
                        if _git_head(path) != expected_commits[role]:
                            issues.append(f"CWE-Bench source revision mismatch: {slug}/{role}")
                        if _git_output(path, "status", "--porcelain") != "":
                            issues.append(f"CWE-Bench source worktree is not clean: {slug}/{role}")
                        remote = _git_output(path, "remote", "get-url", "origin")
                        if remote is None or remote.lower().rstrip("/").removesuffix(".git") != row.get("github_url", "").lower().rstrip("/").removesuffix(".git"):
                            issues.append(f"CWE-Bench source remote mismatch: {slug}/{role}")
                        for fix in ground_truth:
                            relative = fix.get("file", "")
                            if relative and not (path / relative).is_file():
                                issues.append(f"CWE-Bench ground-truth file missing: {slug}/{role}/{relative}")
    for gate in ("OD-002", "OD-006"):
        if not (approvals or {}).get(gate, False):
            issues.append(f"{gate} is not closed for experiment execution")
    return {"ready": not issues, "mode": mode, "issues": issues}
