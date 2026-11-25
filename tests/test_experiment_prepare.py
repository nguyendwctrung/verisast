import json
from pathlib import Path

import pytest

from experiment_prepare import PreparationError, prepare_cwe_bench


def test_prepare_keeps_all_projects_and_flags_missing_metadata(tmp_path: Path) -> None:
    snapshot = tmp_path / "snapshot"
    data = snapshot / "data"
    data.mkdir(parents=True)
    (data / "project_info.csv").write_text(
        "project_slug,cve_id,cwe_id,github_url,buggy_commit_id,fix_commit_ids\n"
        f"ready,CVE-1,CWE-022,https://example.test/repo,{'a' * 40},{'b' * 40}\n"
        f"missing,CVE-2,CWE-078,,{'a' * 40},{'b' * 40}\n", encoding="utf-8")
    (data / "fix_info.csv").write_text(
        "project_slug,file,class,method\nready,src/A.java,A,m\n", encoding="utf-8")
    (data / "build_info.csv").write_text("project_slug,status\nready,success\n", encoding="utf-8")
    result = prepare_cwe_bench(snapshot, tmp_path / "prepared", expected_count=2,
                               expected_revision=None)
    assert result["project_count"] == 2
    assert result["acquirable_count"] == 1
    assert result["blocked_count"] == 1
    roster = [json.loads(line) for line in (tmp_path / "prepared" / "roster.jsonl").read_text().splitlines()]
    assert {row["project_slug"] for row in roster} == {"ready", "missing"}
    with pytest.raises(PreparationError, match="already exists"):
        prepare_cwe_bench(snapshot, tmp_path / "prepared", expected_count=2,
                          expected_revision=None)
