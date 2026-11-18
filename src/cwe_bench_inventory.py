import hashlib
import json
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable


class InventoryError(ValueError):
    pass


RevisionReader = Callable[[Path], str]
RemoteReader = Callable[[Path], str]
CleanReader = Callable[[Path], bool]


def parse_candidate_name(name: str) -> dict[str, str | None]:
    """Parse the local CWE-Bench pair directory convention."""
    match = re.fullmatch(
        r"(?P<owner>[^_]+(?:-[^_]+)*)__"
        r"(?P<repository>.+)_(?P<cve>CVE-\d{4}-\d+)(?:_(?P<release>.+))?",
        name,
    )
    if match is None:
        raise InventoryError(f"invalid CWE-Bench pair directory name: {name}")
    owner = match.group("owner")
    repository = match.group("repository")
    return {
        "owner": owner,
        "repository": repository,
        "repository_id": f"{owner}/{repository}",
        "cve_id": match.group("cve"),
        "dataset_release": match.group("release"),
    }


def detect_build_systems(source: Path) -> list[str]:
    """Detect top-level build entry points without executing them."""
    detected = []
    if (source / "build.gradle").is_file() or (source / "build.gradle.kts").is_file() or (source / "gradlew").is_file():
        detected.append("gradle")
    if (source / "pom.xml").is_file() or (source / "mvnw").is_file():
        detected.append("maven")
    if (source / "build.xml").is_file():
        detected.append("ant")
    return sorted(detected)


def discover(
    dataset_root: Path,
    protocol_path: Path,
    output: Path,
    revision_reader: RevisionReader | None = None,
    remote_reader: RemoteReader | None = None,
    clean_reader: CleanReader | None = None,
) -> dict[str, object]:
    """Create a no-overwrite inventory of locally available vulnerable/fixed pairs."""
    if output.exists():
        raise InventoryError(f"discovery output already exists: {output}")
    root = dataset_root.resolve()
    if not root.is_dir():
        raise InventoryError(f"dataset root not found: {root}")
    protocol = _read_protocol(protocol_path)
    roles = protocol["required_revision_roles"]
    revision_reader = revision_reader or _git_revision
    remote_reader = remote_reader or _git_remote
    clean_reader = clean_reader or _git_clean
    records = []
    for pair in sorted((path for path in root.iterdir() if path.is_dir()), key=lambda path: path.name):
        identity = parse_candidate_name(pair.name)
        revisions = {}
        missing_roles = [role for role in roles if not (pair / role).is_dir()]
        if missing_roles:
            raise InventoryError(
                f"pair {pair.name} missing revision role: {', '.join(missing_roles)}"
            )
        for role in roles:
            source = pair / role
            if not (source / ".git").exists():
                raise InventoryError(f"pair {pair.name} role {role} is not a Git worktree")
            if not clean_reader(source):
                raise InventoryError(f"pair {pair.name} role {role} has uncommitted source changes")
            commit = revision_reader(source).strip()
            if re.fullmatch(r"[0-9a-f]{40}", commit) is None:
                raise InventoryError(f"pair {pair.name} role {role} has invalid Git revision")
            revisions[role] = {
                "source_path": str(source.resolve()),
                "commit": commit,
                "worktree_clean": True,
                "build_systems": detect_build_systems(source),
            }
        remote_url = remote_reader(pair / roles[0]).strip()
        if not remote_url:
            raise InventoryError(f"pair {pair.name} lacks an origin remote URL")
        records.append({
            "schema_version": 1,
            "candidate_id": pair.name,
            **identity,
            "remote_url": remote_url,
            "required_revision_roles": roles,
            "revisions": revisions,
            "ground_truth_review_status": "not_reviewed",
            "feasibility_status": "not_run",
            "selection_status": "discovered_not_reviewed",
        })
    if not records:
        raise InventoryError("dataset root contains no candidate pair directories")
    encoded_records = "".join(
        json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n"
        for record in records
    )
    output.mkdir(parents=True)
    protocol_snapshot = output / "selection-protocol-snapshot.json"
    protocol_snapshot.write_bytes(protocol_path.read_bytes())
    candidates_path = output / "candidates.jsonl"
    candidates_path.write_text(encoded_records, encoding="utf-8")
    minimum_pairs = protocol.get("cohort_target", {}).get("minimum_pairs")
    manifest = {
        "schema_version": 1,
        "status": "complete",
        "purpose": "od-002-local-discovery-only",
        "created_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "dataset_id": protocol["dataset_id"],
        "dataset_root": str(root),
        "selection_protocol": {
            "snapshot": "selection-protocol-snapshot.json",
            "sha256": _hash(protocol_snapshot.read_bytes()),
        },
        "candidates": {
            "path": "candidates.jsonl",
            "sha256": _hash(candidates_path.read_bytes()),
            "count": len(records),
        },
        "candidate_count": len(records),
        "unique_repository_count": len({record["repository_id"] for record in records}),
        "minimum_pair_target": minimum_pairs,
        "minimum_pair_target_met": isinstance(minimum_pairs, int) and len(records) >= minimum_pairs,
        "next_gate": "manual provenance and ground-truth review before feasibility scanning",
    }
    (output / "manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return manifest


def _read_protocol(path: Path) -> dict[str, object]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise InventoryError(f"cannot read selection protocol: {error}") from error
    if not isinstance(payload, dict):
        raise InventoryError("selection protocol must be an object")
    if payload.get("status") != "preregistered_not_executed" or payload.get("dataset_id") != "cwe-bench-java":
        raise InventoryError("selection protocol is not a preregistered CWE-Bench protocol")
    roles = payload.get("required_revision_roles")
    if roles != ["buggy", "fixed"]:
        raise InventoryError("selection protocol must require buggy and fixed revisions")
    return payload


def _git_revision(source: Path) -> str:
    return _git(source, "rev-parse", "HEAD")


def _git_remote(source: Path) -> str:
    return _git(source, "config", "--get", "remote.origin.url")


def _git_clean(source: Path) -> bool:
    return not _git(source, "status", "--porcelain")


def _git(source: Path, *arguments: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(source), *arguments],
        text=True,
        capture_output=True,
        check=False,
    )
    if result.returncode:
        message = result.stderr.strip() or result.stdout.strip()
        raise InventoryError(f"Git command failed for {source}: {message}")
    return result.stdout.strip()


def _hash(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()
