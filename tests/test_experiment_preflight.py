from pathlib import Path

from experiment import ExperimentError, build_owasp_selection, preflight, validate_reviewed_units, verify_reviewed_unit_provenance


def test_partial_selection_is_balanced_and_frozen(tmp_path: Path) -> None:
    labels = tmp_path / "labels.csv"
    labels.write_text(
        "BenchmarkTest00001,x,true,22\nBenchmarkTest00002,x,false,22\n"
        "BenchmarkTest00003,x,true,78\nBenchmarkTest00004,x,false,78\n",
        encoding="utf-8",
    )
    selected = build_owasp_selection(labels, {
        "22": ["BenchmarkTest00001", "BenchmarkTest00002"],
        "78": ["BenchmarkTest00003", "BenchmarkTest00004"],
    })
    assert len(selected) == 4
    assert {(row["cwe"], row["vulnerable"]) for row in selected} == {
        (22, True), (22, False), (78, True), (78, False),
    }


def test_preflight_lists_missing_full_pairs_and_gates(tmp_path: Path) -> None:
    labels = tmp_path / "labels.csv"
    labels.write_text("BenchmarkTest00001,x,true,22\n", encoding="utf-8")
    source = tmp_path / "owasp"
    source.mkdir()
    snapshot = tmp_path / "snapshot"
    data = snapshot / "data"
    data.mkdir(parents=True)
    (data / "project_info.csv").write_text(
        "project_slug,cve_id,cwe_id,github_url,buggy_commit_id,fix_commit_ids\n"
        "repo_CVE-1_1,CVE-1,CWE-022,https://example.test/repo,abc,def\n",
        encoding="utf-8",
    )
    manifest = {"mode": "full", "owasp": {"expected_count": 1},
                "cwe_bench": {"expected_pair_count": 1}}
    result = preflight(manifest, source, labels, snapshot, tmp_path / "pairs",
                       approvals={"OD-002": False, "OD-006": False})
    assert not result["ready"]
    assert any("repo_CVE-1_1" in item for item in result["issues"])
    assert any("OD-002" in item for item in result["issues"])
    assert any("OD-006" in item for item in result["issues"])


def test_preflight_rejects_wrong_full_count(tmp_path: Path) -> None:
    labels = tmp_path / "labels.csv"
    labels.write_text("BenchmarkTest00001,x,true,22\n", encoding="utf-8")
    source = tmp_path / "source"
    source.mkdir()
    manifest = {"mode": "full", "owasp": {"expected_count": 2740}}
    result = preflight(manifest, source, labels, None, None,
                       approvals={"OD-002": True, "OD-006": True})
    assert any("2740" in item for item in result["issues"])


def test_preflight_checks_ground_truth_and_revision(tmp_path: Path) -> None:
    snapshot = tmp_path / "snapshot"
    data = snapshot / "data"
    data.mkdir(parents=True)
    (data / "project_info.csv").write_text(
        "project_slug,cve_id,cwe_id,github_url,buggy_commit_id,fix_commit_ids\n"
        "sample,CVE-1,CWE-022,https://example.test/repo,abc,def\n", encoding="utf-8")
    (data / "fix_info.csv").write_text("project_slug,file,class,method\n", encoding="utf-8")
    (data / "build_info.csv").write_text("project_slug,status\nsample,success\n", encoding="utf-8")
    result = preflight({"mode": "partial", "cwe_bench": {
        "expected_pair_count": 1, "selected_slugs": ["sample"]}},
        None, None, snapshot, tmp_path / "pairs",
        approvals={"OD-002": True, "OD-006": True})
    assert any("ground truth" in item for item in result["issues"])
    assert any("source missing" in item for item in result["issues"])
    assert any("immutable commits" in item for item in result["issues"])


def test_reviewed_units_require_both_roles_and_symbol_ranges() -> None:
    units = [{"target_id": f"sample/{role}", "cve_id": "CVE-1", "revision_role": role,
              "cwe": 22, "path_prefixes": ["src/A.java"]} for role in ("buggy", "fixed")]
    try:
        validate_reviewed_units(units, ["sample"])
    except ExperimentError as error:
        assert "symbol_ranges" in str(error)
    else:
        raise AssertionError("unreviewed symbol range was accepted")


def test_reviewed_unit_provenance_rejects_wrong_cve(tmp_path: Path) -> None:
    data = tmp_path / "data"
    data.mkdir()
    (data / "project_info.csv").write_text(
        "project_slug,cve_id,cwe_id\nsample,CVE-1,CWE-022\n", encoding="utf-8")
    (data / "fix_info.csv").write_text(
        "project_slug,file,class,method\nsample,src/A.java,A,m\n", encoding="utf-8")
    units = [{"target_id": f"sample/{role}", "cve_id": "CVE-WRONG", "revision_role": role,
              "cwe": 22, "path_prefixes": ["src/A.java"],
              "symbol_ranges": [{"path": "src/A.java", "start": 20, "end": 30}]}
             for role in ("buggy", "fixed")]
    assert any("CVE" in issue for issue in verify_reviewed_unit_provenance(units, tmp_path))
