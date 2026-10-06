import csv
import hashlib
import json
import re
import subprocess
import sys

from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Iterable


DATASET_ID = "owasp-benchmark-java-v1.2"
DATASET_VERSION = "1.2"
EXPECTED_REMOTE = "https://github.com/OWASP-Benchmark/BenchmarkJava.git"
EXPECTED_RECORDS = 2740
EXPECTED_CWES = frozenset({22, 78, 79, 89, 90, 327, 328, 330, 501, 614, 643})
TEST_ID_PATTERN = re.compile(r"^BenchmarkTest\d{5}$")
AUDIT_TOOL_VERSION = "1"


class AuditError(ValueError):
    """Raised when a dataset integrity or provenance check fails."""


@dataclass(frozen=True)
class GroundTruthRecord:
    """One normalized row from the OWASP Benchmark ground truth."""

    test_id: str
    category: str
    vulnerable: bool
    cwe: int


@dataclass(frozen=True)
class GitInfo:
    """Frozen Git provenance for a raw dataset checkout."""

    remote_url: str
    commit: str
    clean: bool
    detached: bool


@dataclass(frozen=True)
class AuditResult:
    """Summary returned after a successful audit."""

    audit_status: str
    dataset_id: str
    frozen_commit: str
    testcase_count: int
    source_file_count: int
    manifest_path: str


GitReader = Callable[[Path], GitInfo]


def load_ground_truth(csv_path: Path) -> list[GroundTruthRecord]:
    """Load and validate OWASP v1.2 ground-truth file."""

    if not csv_path.is_file():
        raise AuditError(f"ground-truth file not found: {csv_path}")

    records: list[GroundTruthRecord] = []
    seen: set[str] = set()

    with csv_path.open("r", encoding="utf-8-sig", newline="") as stream:
        reader = csv.reader(stream)
        header = next(reader, None)
        if header is None or not header[0].startswith("# test name"):
            raise AuditError("ground-truth comment header is missing or invalid")

        for line_number, row in enumerate(reader, start=2):
            if not row or all(not value.strip() for value in row):
                raise AuditError(f"blank ground-truth row at line {line_number}")
            if len(row) != 4:
                raise AuditError(
                    f"expected 4 columns at line {line_number}, found {len(row)}"
                )

            test_id, category, label, cwe_text = (value.strip() for value in row)
            if not TEST_ID_PATTERN.fullmatch(test_id):
                raise AuditError(f"invalid test ID at line {line_number}: {test_id}")
            if test_id in seen:
                raise AuditError(f"duplicate test ID at line {line_number}: {test_id}")
            if not category:
                raise AuditError(f"empty category at line {line_number}")
            if label not in {"true", "false"}:
                raise AuditError(f"invalid label at line {line_number}: {label}")
            if not cwe_text.isdigit():
                raise AuditError(f"invalid CWE at line {line_number}: {cwe_text}")

            seen.add(test_id)
            records.append(
                GroundTruthRecord(
                    test_id=test_id,
                    category=category,
                    vulnerable=label == "true",
                    cwe=int(cwe_text),
                )
            )

    if not records:
        raise AuditError("ground truth contains no records")
    return records


def map_java_sources(
    source_root: Path,
    records: Iterable[GroundTruthRecord],
) -> dict[str, Path]:
    """Require exactly one Java source for every ground-truth test ID."""

    if not source_root.is_dir():
        raise AuditError(f"source directory not found: {source_root}")

    record_ids = {record.test_id for record in records}
    sources: dict[str, list[Path]] = {}
    for path in source_root.rglob("BenchmarkTest*.java"):
        sources.setdefault(path.stem, []).append(path)

    for test_id in sorted(record_ids):
        matches = sources.get(test_id, [])
        if not matches:
            raise AuditError(f"missing Java source for {test_id}")
        if len(matches) != 1:
            raise AuditError(f"multiple Java sources for {test_id}: {len(matches)}")

    orphan_ids = sorted(set(sources) - record_ids)
    if orphan_ids:
        raise AuditError(f"orphan Java source: {orphan_ids[0]}")

    return {test_id: paths[0] for test_id, paths in sources.items()}


def read_git_info(dataset_dir: Path) -> GitInfo:
    """Read Git provenance without changing the dataset checkout."""

    def run_git(
        *args: str,
        allow_failure: bool = False,
    ) -> subprocess.CompletedProcess[str]:
        result = subprocess.run(
            ["git", "-C", str(dataset_dir), *args],
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
        )
        if result.returncode != 0 and not allow_failure:
            detail = result.stderr.strip() or result.stdout.strip()
            raise AuditError(f"Git command failed ({' '.join(args)}): {detail}")
        return result

    remote_url = run_git("remote", "get-url", "origin").stdout.strip()
    commit = run_git("rev-parse", "HEAD").stdout.strip()
    status = run_git("status", "--porcelain").stdout
    symbolic_ref = run_git("symbolic-ref", "-q", "HEAD", allow_failure=True)
    return GitInfo(
        remote_url=remote_url,
        commit=commit,
        clean=not status.strip(),
        detached=symbolic_ref.returncode != 0,
    )


def sha256_file(path: Path) -> str:
    """Hash one file without loading it fully into memory."""

    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def sha256_tree(root: Path, paths: Iterable[Path]) -> str:
    """Hash file paths and contents in deterministic relative-path order."""

    digest = hashlib.sha256()
    for path in sorted(paths, key=lambda item: item.relative_to(root).as_posix()):
        relative_path = path.relative_to(root).as_posix().encode("utf-8")
        digest.update(relative_path)
        digest.update(b"\0")
        digest.update(bytes.fromhex(sha256_file(path)))
    return digest.hexdigest()


def audit_dataset(
    dataset_dir: Path,
    manifest_path: Path,
    expected_commit: str,
    expected_records: int = EXPECTED_RECORDS,
    expected_cwes: set[int] | frozenset[int] = EXPECTED_CWES,
    git_reader: GitReader = read_git_info,
) -> AuditResult:
    """Audit the frozen dataset and write a manifest outside the raw checkout."""

    dataset_dir = dataset_dir.resolve()
    manifest_path = manifest_path.resolve()
    if not dataset_dir.is_dir():
        raise AuditError(f"dataset directory not found: {dataset_dir}")
    if manifest_path.is_relative_to(dataset_dir):
        raise AuditError("manifest must be outside the raw dataset directory")

    required_paths = {
        "ground_truth": dataset_dir / "expectedresults-1.2.csv",
        "license": dataset_dir / "LICENSE",
        "pom": dataset_dir / "pom.xml",
        "source": dataset_dir / "src",
    }
    for name, path in required_paths.items():
        if not path.exists():
            raise AuditError(f"required {name} path not found: {path}")

    git_info = git_reader(dataset_dir)
    if _normalize_remote(git_info.remote_url) != _normalize_remote(EXPECTED_REMOTE):
        raise AuditError(f"unexpected Git remote: {git_info.remote_url}")
    if git_info.commit != expected_commit:
        raise AuditError(
            f"unexpected Git commit: {git_info.commit}; expected {expected_commit}"
        )
    if not git_info.clean:
        raise AuditError("dataset working tree is not clean")
    if not git_info.detached:
        raise AuditError("dataset HEAD is not detached")

    records = load_ground_truth(required_paths["ground_truth"])
    if len(records) != expected_records:
        raise AuditError(
            f"unexpected ground-truth record count: {len(records)}; "
            f"expected {expected_records}"
        )

    observed_cwes = {record.cwe for record in records}
    if observed_cwes != set(expected_cwes):
        raise AuditError(
            "unexpected CWE set: "
            f"{sorted(observed_cwes)}; expected {sorted(expected_cwes)}"
        )

    source_map = map_java_sources(required_paths["source"], records)
    label_counts = Counter(str(record.vulnerable).lower() for record in records)
    cwe_counts = Counter(str(record.cwe) for record in records)
    source_paths = list(source_map.values())

    manifest = {
        "dataset_id": DATASET_ID,
        "name": "OWASP Benchmark for Java",
        "declared_version": DATASET_VERSION,
        "upstream_url": git_info.remote_url,
        "frozen_commit": git_info.commit,
        "acquired_snapshot_audited_at": datetime.now(timezone.utc).isoformat(),
        "license": "GPL-2.0",
        "ground_truth_path": "expectedresults-1.2.csv",
        "ground_truth_sha256": sha256_file(required_paths["ground_truth"]),
        "license_sha256": sha256_file(required_paths["license"]),
        "pom_sha256": sha256_file(required_paths["pom"]),
        "java_corpus_sha256": sha256_tree(dataset_dir, source_paths),
        "testcase_count": len(records),
        "source_file_count": len(source_paths),
        "label_counts": dict(sorted(label_counts.items())),
        "cwe_counts": dict(sorted(cwe_counts.items(), key=lambda item: int(item[0]))),
        "cwe_list": sorted(observed_cwes),
        "working_tree_clean": git_info.clean,
        "head_detached": git_info.detached,
        "audit_status": "passed",
        "audit_tool_version": AUDIT_TOOL_VERSION,
        "python_version": sys.version.split()[0],
    }
    _write_json_atomic(manifest_path, manifest)

    return AuditResult(
        audit_status="passed",
        dataset_id=DATASET_ID,
        frozen_commit=git_info.commit,
        testcase_count=len(records),
        source_file_count=len(source_paths),
        manifest_path=str(manifest_path),
    )


def _normalize_remote(url: str) -> str:
    normalized = url.strip().rstrip("/")
    if normalized.endswith(".git"):
        normalized = normalized[:-4]
    return normalized.lower()


def _write_json_atomic(path: Path, payload: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary_path = path.with_suffix(path.suffix + ".tmp")
    temporary_path.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    temporary_path.replace(path)
