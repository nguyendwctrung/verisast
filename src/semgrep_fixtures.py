import hashlib
import json
import re
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import TypedDict

from semgrep_compat import CommandResult, run_command
from semgrep_rules import EXPECTED_REMOTE, RuleGitInfo, read_git_info, sha256_file

SCHEMA_VERSION = 1
VERSION_PATTERN = re.compile(r"\d+\.\d+\.\d+")
ANNOTATION_PATTERN = re.compile(
    r"^\s*//\s*(ruleid|ok|todoruleid|todook):\s*(.+?)\s*$"
)

FAIL_MARKERS = (
    "test failed",
    "tests failed",
    "unit test failed",
    "missed",
    "false positive",
    "incorrect lines",
    "expected lines",
)


class FixtureError(ValueError):
    """Raised when fixture validation cannot be trusted."""


@dataclass(frozen=True)
class AnnotationCounts:
    positive: int
    negative: int
    todo_positive: int
    todo_negative: int


@dataclass(frozen=True)
class FixtureResult:
    status: str
    semgrep_version: str
    upstream_commit: str
    file_count: int
    pass_count: int
    fail_count: int
    error_count: int
    complete_annotation_count: int
    incomplete_annotation_count: int
    report_path: str


class InventoryData(TypedDict):
    upstream_commit: object
    rules: list[object]


class FixtureGroup(TypedDict):
    source_sha256: str
    fixture_path: Path
    fixture_sha256: str
    rule_ids: list[str]
    cwes: set[int]


CommandRunner = Callable[[list[str], Path | None], CommandResult]
GitReader = Callable[[Path], RuleGitInfo]


def parse_annotations(
    fixture_path: Path,
    rule_ids: set[str],
) -> AnnotationCounts:
    positive = 0
    negative = 0
    todo_positive = 0
    todo_negative = 0

    try:
        lines = fixture_path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError) as error:
        raise FixtureError(
            f"failed to read fixture {fixture_path}: {error}"
        ) from error

    for line in lines:
        match = ANNOTATION_PATTERN.match(line)
        if not match:
            continue

        kind = match.group(1)
        annotated_ids = {
            item.strip()
            for item in match.group(2).split(",")
            if item.strip()
        }
        matched_count = len(annotated_ids & rule_ids)

        if kind == "ruleid":
            positive += matched_count
        elif kind == "ok":
            negative += matched_count
        elif kind == "todoruleid":
            todo_positive += matched_count
        elif kind == "todook":
            todo_negative += matched_count

    return AnnotationCounts(
        positive=positive,
        negative=negative,
        todo_positive=todo_positive,
        todo_negative=todo_negative,
    )


def annotation_status(
    positive: int,
    negative: int,
) -> str:
    if positive > 0 and negative > 0:
        return "BOTH"
    if positive > 0:
        return "POSITIVE_ONLY"
    if negative > 0:
        return "NEGATIVE_ONLY"
    return "NONE"


def classify_test(result: CommandResult) -> str:
    if result.returncode == 0:
        return "PASS"

    diagnostic = f"{result.stdout}\n{result.stderr}".lower()
    if any(marker in diagnostic for marker in FAIL_MARKERS):
        return "FAIL"

    return "ERROR"


def validate_fixtures(
    rules_dir: Path,
    inventory_path: Path,
    run_dir: Path,
    semgrep_executable: str,
    expected_version: str,
    git_reader: GitReader = read_git_info,
    command_runner: CommandRunner = run_command,
) -> FixtureResult:
    rules_dir = rules_dir.resolve()
    inventory_path = inventory_path.resolve()
    run_dir = run_dir.resolve()

    if run_dir.exists():
        raise FixtureError(f"run directory already exists: {run_dir}")
    if not rules_dir.is_dir():
        raise FixtureError(f"rule directory not found: {rules_dir}")
    if not inventory_path.is_file():
        raise FixtureError(f"inventory not found: {inventory_path}")
    if run_dir.is_relative_to(rules_dir):
        raise FixtureError(
            "run directory must be outside the upstream checkout"
        )

    inventory = _load_inventory(inventory_path)
    git_info = git_reader(rules_dir)
    _validate_provenance(inventory, git_info)
    fixtures = _group_fixtures(inventory, rules_dir)

    version_result = command_runner(
        [semgrep_executable, "--version"],
        None,
    )
    if version_result.returncode != 0:
        detail = (
            version_result.stderr.strip()
            or version_result.stdout.strip()
        )
        raise FixtureError(
            f"failed to read Semgrep version: {detail}"
        )

    semgrep_version = _extract_version(version_result.stdout)
    if semgrep_version != expected_version:
        raise FixtureError(
            "unexpected Semgrep version: "
            f"expected {expected_version}, observed {semgrep_version}"
        )

    run_dir.mkdir(parents=True)
    raw_dir = run_dir / "raw"
    raw_dir.mkdir()

    files: list[dict[str, object]] = []
    test_summary: Counter[str] = Counter()
    annotation_summary: Counter[str] = Counter()

    for source_path, fixture in sorted(fixtures.items()):
        absolute_rule_path = rules_dir / source_path
        fixture_path = fixture["fixture_path"]
        rule_ids = set(fixture["rule_ids"])

        counts = parse_annotations(
            fixture_path,
            rule_ids,
        )
        coverage = annotation_status(
            counts.positive,
            counts.negative,
        )
        annotation_summary[coverage] += 1

        command = [
            semgrep_executable,
            "--test",
            "--config",
            str(absolute_rule_path),
            str(fixture_path),
        ]
        result = command_runner(command, run_dir)
        test_status = classify_test(result)
        test_summary[test_status] += 1

        evidence_id = hashlib.sha256(
            source_path.encode("utf-8")
        ).hexdigest()[:16]
        stdout_path = raw_dir / f"{evidence_id}.stdout.txt"
        stderr_path = raw_dir / f"{evidence_id}.stderr.txt"
        stdout_path.write_text(result.stdout, encoding="utf-8")
        stderr_path.write_text(result.stderr, encoding="utf-8")

        files.append(
            {
                "source_path": source_path,
                "source_sha256": fixture["source_sha256"],
                "fixture_path": fixture_path.relative_to(
                    rules_dir
                ).as_posix(),
                "fixture_sha256": fixture["fixture_sha256"],
                "rule_ids": sorted(rule_ids),
                "cwes": sorted(fixture["cwes"]),
                "positive_annotations": counts.positive,
                "negative_annotations": counts.negative,
                "todo_positive_annotations": counts.todo_positive,
                "todo_negative_annotations": counts.todo_negative,
                "annotation_status": coverage,
                "test_status": test_status,
                "command": command,
                "exit_code": result.returncode,
                "duration_ms": result.duration_ms,
                "stdout_path": stdout_path.relative_to(
                    run_dir
                ).as_posix(),
                "stdout_sha256": sha256_file(stdout_path),
                "stderr_path": stderr_path.relative_to(
                    run_dir
                ).as_posix(),
                "stderr_sha256": sha256_file(stderr_path),
            }
        )

    report_path = run_dir / "fixtures.json"
    report = {
        "schema_version": SCHEMA_VERSION,
        "status": "completed",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "semgrep_version": semgrep_version,
        "semgrep_executable": semgrep_executable,
        "upstream_url": git_info.remote_url,
        "upstream_commit": git_info.commit,
        "working_tree_clean": git_info.clean,
        "head_detached": git_info.detached,
        "inventory_path": str(inventory_path),
        "inventory_sha256": sha256_file(inventory_path),
        "candidate_rule_count": len(inventory["rules"]),
        "candidate_file_count": len(files),
        "summary": {
            status: test_summary[status]
            for status in ("PASS", "FAIL", "ERROR")
        },
        "annotation_summary": {
            status: annotation_summary[status]
            for status in (
                "BOTH",
                "POSITIVE_ONLY",
                "NEGATIVE_ONLY",
                "NONE",
            )
        },
        "files": files,
        "coverage_status": "upstream_fixtures_only",
        "ruleset_status": "not_frozen",
    }
    _write_json_atomic(report_path, report)

    complete_count = annotation_summary["BOTH"]
    return FixtureResult(
        status="completed",
        semgrep_version=semgrep_version,
        upstream_commit=git_info.commit,
        file_count=len(files),
        pass_count=test_summary["PASS"],
        fail_count=test_summary["FAIL"],
        error_count=test_summary["ERROR"],
        complete_annotation_count=complete_count,
        incomplete_annotation_count=len(files) - complete_count,
        report_path=str(report_path),
    )


def _load_inventory(path: Path) -> InventoryData:
    try:
        inventory = json.loads(path.read_text(encoding="utf-8"))
    except (
        OSError,
        UnicodeError,
        json.JSONDecodeError,
    ) as error:
        raise FixtureError(
            f"failed to read inventory: {error}"
        ) from error

    if not isinstance(inventory, dict):
        raise FixtureError("inventory root must be an object")
    if inventory.get("status") != "passed":
        raise FixtureError("inventory status is not passed")

    rules = inventory.get("rules")
    if not isinstance(rules, list) or not rules:
        raise FixtureError(
            "inventory contains no candidate rules"
        )

    return {
        "upstream_commit": inventory.get("upstream_commit"),
        "rules": rules,
    }


def _validate_provenance(
    inventory: InventoryData,
    git_info: RuleGitInfo,
) -> None:
    if _normalize_remote(
        git_info.remote_url
    ) != _normalize_remote(EXPECTED_REMOTE):
        raise FixtureError(
            f"unexpected Git remote: {git_info.remote_url}"
        )
    if not git_info.clean:
        raise FixtureError(
            "rule working tree is not clean"
        )
    if not git_info.detached:
        raise FixtureError(
            "rule HEAD is not detached"
        )
    if inventory["upstream_commit"] != git_info.commit:
        raise FixtureError(
            "inventory commit does not match rule checkout: "
            f"{inventory['upstream_commit']} != {git_info.commit}"
        )


def _group_fixtures(
    inventory: InventoryData,
    rules_dir: Path,
) -> dict[str, FixtureGroup]:
    grouped: dict[str, FixtureGroup] = {}
    observed: set[tuple[str, str]] = set()

    for index, item in enumerate(
        inventory["rules"],
        start=1,
    ):
        if not isinstance(item, dict):
            raise FixtureError(
                f"inventory rule {index} must be an object"
            )

        rule_id = item.get("id")
        source_path = item.get("source_path")
        source_hash = item.get("source_sha256")
        cwes = item.get("cwes")

        if not isinstance(rule_id, str) or not rule_id:
            raise FixtureError(
                f"inventory rule {index} has no valid ID"
            )
        if not isinstance(source_path, str) or not source_path:
            raise FixtureError(
                f"inventory rule {rule_id} has no source path"
            )
        if not isinstance(source_hash, str) or len(
            source_hash
        ) != 64:
            raise FixtureError(
                f"inventory rule {rule_id} has no valid source hash"
            )
        if not isinstance(cwes, list) or not all(
            isinstance(cwe, int) for cwe in cwes
        ):
            raise FixtureError(
                f"inventory rule {rule_id} has invalid CWEs"
            )

        identity = (source_path, rule_id)
        if identity in observed:
            raise FixtureError(
                "duplicate inventory rule identity: "
                f"{source_path}::{rule_id}"
            )
        observed.add(identity)

        rule_path = (rules_dir / source_path).resolve()
        if not rule_path.is_relative_to(rules_dir):
            raise FixtureError(
                f"rule path escapes checkout: {source_path}"
            )
        if not rule_path.is_file():
            raise FixtureError(
                f"rule file not found: {source_path}"
            )
        if sha256_file(rule_path) != source_hash:
            raise FixtureError(
                f"rule hash mismatch for {source_path}"
            )

        fixture_path = rule_path.with_suffix(".java")
        if not fixture_path.is_file():
            raise FixtureError(
                f"fixture not found for {source_path}: "
                f"{fixture_path}"
            )

        fixture_hash = sha256_file(fixture_path)

        if source_path not in grouped:
            grouped[source_path] = {
                "source_sha256": source_hash,
                "fixture_path": fixture_path,
                "fixture_sha256": fixture_hash,
                "rule_ids": [],
                "cwes": set(),
            }
        else:
            existing = grouped[source_path]
            if existing["source_sha256"] != source_hash:
                raise FixtureError(
                    f"conflicting source hashes for {source_path}"
                )
            if existing["fixture_sha256"] != fixture_hash:
                raise FixtureError(
                    f"conflicting fixture hashes for {source_path}"
                )

        grouped[source_path]["rule_ids"].append(rule_id)
        grouped[source_path]["cwes"].update(cwes)

    return grouped


def _extract_version(output: str) -> str:
    match = VERSION_PATTERN.search(output)
    if not match:
        raise FixtureError(
            f"unable to parse Semgrep version: {output.strip()}"
        )
    return match.group(0)


def _normalize_remote(url: str) -> str:
    normalized = url.strip().rstrip("/")
    normalized = normalized.removesuffix(".git")
    return normalized.lower()


def _write_json_atomic(
    path: Path,
    payload: dict[str, object],
) -> None:
    temporary_path = path.with_suffix(
        path.suffix + ".tmp"
    )
    temporary_path.write_text(
        json.dumps(
            payload,
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    temporary_path.replace(path)