import json
from pathlib import Path

import pytest

from cwe_bench_inventory import (
    InventoryError,
    detect_build_systems,
    discover,
    parse_candidate_name,
)


def test_candidate_name_preserves_repository_cve_and_release() -> None:
    parsed = parse_candidate_name("codehaus-plexus__plexus-utils_CVE-2022-4244_3.0.23")

    assert parsed == {
        "owner": "codehaus-plexus",
        "repository": "plexus-utils",
        "repository_id": "codehaus-plexus/plexus-utils",
        "cve_id": "CVE-2022-4244",
        "dataset_release": "3.0.23",
    }


def test_candidate_name_rejects_unstructured_directory() -> None:
    with pytest.raises(InventoryError, match="directory name"):
        parse_candidate_name("plexus-utils")


def test_build_system_detection_is_revision_specific(tmp_path: Path) -> None:
    (tmp_path / "pom.xml").write_text("<project/>", encoding="utf-8")
    (tmp_path / "gradlew").write_text("", encoding="utf-8")

    assert detect_build_systems(tmp_path) == ["gradle", "maven"]


def test_discovery_writes_no_overwrite_provenance(tmp_path: Path) -> None:
    root = tmp_path / "dataset"
    pair = root / "owner__repository_CVE-2024-1000_1.0"
    for role in ("buggy", "fixed"):
        revision = pair / role
        revision.mkdir(parents=True)
        (revision / ".git").write_text("gitdir: fake", encoding="utf-8")
        (revision / "pom.xml").write_text("<project/>", encoding="utf-8")
    protocol = tmp_path / "protocol.json"
    protocol.write_text(json.dumps({
        "schema_version": 1,
        "status": "preregistered_not_executed",
        "dataset_id": "cwe-bench-java",
        "required_revision_roles": ["buggy", "fixed"],
    }), encoding="utf-8")
    revisions = {"buggy": "a" * 40, "fixed": "b" * 40}

    result = discover(
        root,
        protocol,
        tmp_path / "output",
        revision_reader=lambda path: revisions[path.name],
        remote_reader=lambda path: "https://example.invalid/owner/repository.git",
        clean_reader=lambda path: True,
    )

    records = [json.loads(line) for line in (tmp_path / "output" / "candidates.jsonl").read_text(encoding="utf-8").splitlines()]
    assert result["candidate_count"] == 1
    assert records[0]["selection_status"] == "discovered_not_reviewed"
    assert records[0]["revisions"]["buggy"]["commit"] == "a" * 40
    assert records[0]["revisions"]["fixed"]["build_systems"] == ["maven"]
    assert records[0]["remote_url"] == "https://example.invalid/owner/repository.git"
    with pytest.raises(InventoryError, match="already exists"):
        discover(root, protocol, tmp_path / "output")


def test_discovery_rejects_incomplete_or_dirty_pairs(tmp_path: Path) -> None:
    root = tmp_path / "dataset"
    pair = root / "owner__repository_CVE-2024-1000_1.0"
    (pair / "buggy").mkdir(parents=True)
    protocol = tmp_path / "protocol.json"
    protocol.write_text(json.dumps({
        "schema_version": 1,
        "status": "preregistered_not_executed",
        "dataset_id": "cwe-bench-java",
        "required_revision_roles": ["buggy", "fixed"],
    }), encoding="utf-8")

    with pytest.raises(InventoryError, match="missing revision role"):
        discover(root, protocol, tmp_path / "output")

    (pair / "fixed").mkdir()
    with pytest.raises(InventoryError, match="not a Git worktree"):
        discover(root, protocol, tmp_path / "output")


def test_committed_protocol_freezes_outcome_independent_selection() -> None:
    protocol_path = Path(__file__).parents[1] / "inventory" / "cwe-bench-development-v1" / "selection-protocol.json"
    protocol = json.loads(protocol_path.read_text(encoding="utf-8"))

    assert protocol["status"] == "preregistered_not_executed"
    assert protocol["cohort_target"] == {"minimum_pairs": 5, "preferred_pairs": 8, "maximum_pairs": 10}
    assert "whether CodeQL reports a target finding" in protocol["forbidden_selection_evidence"]
    assert "NO_CODEQL_FINDING" in protocol["prohibited_exclusion_reason_codes"]
    assert protocol["split_policy"]["held_out_execution_authorized"] is False
