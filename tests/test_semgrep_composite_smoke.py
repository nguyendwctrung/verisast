import json
from pathlib import Path

import pytest

from semgrep_composite_smoke import CompositeSmokeError, run_composite_smoke
from semgrep_rules import sha256_file


def write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value), encoding="utf-8")


def write_inputs(tmp_path: Path) -> dict[str, Path]:
    upstream = tmp_path / "upstream"
    project = tmp_path / "project"
    source = tmp_path / "source"
    upstream_rule = upstream / "java" / "upstream.yaml"
    project_rule = project / "rules" / "project" / "rule.yaml"
    source_file = source / "Smoke.java"
    for path in (upstream_rule, project_rule, source_file):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("rule" if path.suffix == ".yaml" else "class Smoke {}\n", encoding="utf-8")
    catalog = tmp_path / "catalog.json"
    review = tmp_path / "review.json"
    ruleset = tmp_path / "ruleset.json"
    write_json(catalog, {"schema_version": 1, "status": "passed"})
    write_json(review, {"inventory_sha256": sha256_file(catalog)})
    write_json(
        ruleset,
        {
            "schema_version": 1,
            "status": "development",
            "purpose": "development",
            "reportable": False,
            "rule_count": 2,
            "unresolved_review_count": 0,
            "catalog_sha256": sha256_file(catalog),
            "review_sha256": sha256_file(review),
            "rules": [
                {"identity": "upstream::rule", "rule_id": "upstream-rule", "source_path": "java/upstream.yaml", "source_root": "upstream_rules", "source_sha256": sha256_file(upstream_rule)},
                {"identity": "project::rule", "rule_id": "project-cwe327-desede-ecb-default", "source_path": "rules/project/rule.yaml", "source_root": "project_root", "source_sha256": sha256_file(project_rule)},
            ],
        },
    )
    return {"upstream": upstream, "project": project, "source": source, "catalog": catalog, "review": review, "ruleset": ruleset}


def fake_scan_factory(project_findings: int):
    def fake_scan(upstream_rules, ruleset, source_root, raw_dir, semgrep, version, project_root=None):
        raw_dir.mkdir(parents=True)
        scans = []
        for index, rule in enumerate(ruleset["rules"]):
            stdout = raw_dir / f"{index}.stdout.json"
            stderr = raw_dir / f"{index}.stderr.txt"
            stdout.write_text("{}", encoding="utf-8")
            stderr.write_text("", encoding="utf-8")
            scans.append({"rule_id": rule["rule_id"], "finding_count": project_findings if index else 0, "stdout_path": str(stdout), "stdout_sha256": sha256_file(stdout), "stderr_path": str(stderr), "stderr_sha256": sha256_file(stderr)})
        return scans
    return fake_scan


def test_composite_smoke_writes_immutable_evidence(tmp_path: Path) -> None:
    inputs = write_inputs(tmp_path)
    run_dir = tmp_path / "run"
    result = run_composite_smoke(run_id="smoke-1", upstream_rules_dir=inputs["upstream"], project_root=inputs["project"], catalog_path=inputs["catalog"], review_path=inputs["review"], ruleset_path=inputs["ruleset"], source_root=inputs["source"], run_dir=run_dir, semgrep_executable="semgrep", expected_version="1.180.0", scan_runner=fake_scan_factory(1))

    manifest = json.loads(Path(result.manifest_path).read_text(encoding="utf-8"))
    assert result.project_finding_count == 1
    assert manifest["status"] == "completed"
    assert manifest["inputs"]["source_files"][0]["path"] == "Smoke.java"
    assert manifest["reportable"] is False


def test_composite_smoke_rejects_missing_project_finding(tmp_path: Path) -> None:
    inputs = write_inputs(tmp_path)
    run_dir = tmp_path / "run"

    with pytest.raises(CompositeSmokeError, match="produced no smoke finding"):
        run_composite_smoke(run_id="smoke-2", upstream_rules_dir=inputs["upstream"], project_root=inputs["project"], catalog_path=inputs["catalog"], review_path=inputs["review"], ruleset_path=inputs["ruleset"], source_root=inputs["source"], run_dir=run_dir, semgrep_executable="semgrep", expected_version="1.180.0", scan_runner=fake_scan_factory(0))

    assert json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))["status"] == "failed"
