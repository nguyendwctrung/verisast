import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from semgrep_catalog import CatalogError, build_composite_catalog, run_catalog_command
from semgrep_rules import sha256_file


UPSTREAM_COMMIT = "a84ff9cc2453ca91d581380de4b8b3f272f6f4be"


def write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


def write_rule(path: Path) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "rules:\n"
        "  - id: project-cwe327-desede-ecb-default\n"
        "    languages: [java]\n"
        "    severity: WARNING\n"
        "    metadata:\n"
        "      category: security\n"
        "      cwe: [CWE-327]\n"
        "    pattern: $P.getProperty(\"cryptoAlg1\", \"DESede/ECB/PKCS5Padding\")\n",
        encoding="utf-8",
    )
    return sha256_file(path)


def write_upstream_inventory(path: Path) -> None:
    write_json(
        path,
        {
            "schema_version": 1,
            "status": "passed",
            "upstream_commit": UPSTREAM_COMMIT,
            "candidate_rule_count": 1,
            "rules": [
                {
                    "id": "cbc-padding-oracle",
                    "source_path": "java/lang/security/audit/cbc-padding-oracle.yaml",
                    "source_sha256": "a" * 64,
                    "languages": ["java"],
                    "mode": "search",
                    "severity": "WARNING",
                    "category": "security",
                    "cwes": [327],
                    "confidence": "HIGH",
                    "technology": ["java"],
                }
            ],
        },
    )


def write_project_manifest(path: Path, rule_hash: str) -> None:
    write_json(
        path,
        {
            "schema_version": 1,
            "source_type": "project_authored",
            "rules": [
                {
                    "rule_id": "project-cwe327-desede-ecb-default",
                    "source_path": "rules/project/java/security/project-cwe327-desede-ecb-default.yaml",
                    "source_sha256": rule_hash,
                    "languages": ["java"],
                    "mode": "search",
                    "severity": "WARNING",
                    "category": "security",
                    "cwes": [327],
                    "confidence": "HIGH",
                    "technology": ["java"],
                    "license": "Project-authored",
                    "references": [
                        "https://cwe.mitre.org/data/definitions/327.html"
                    ],
                    "fixtures": [],
                    "rationale": "Independent configuration-default CWE-327 rule.",
                }
            ],
        },
    )


def create_inputs(tmp_path: Path) -> tuple[Path, Path, Path, Path]:
    project_root = tmp_path / "project"
    inventory_path = project_root / "rules" / "inventory" / "upstream.json"
    manifest_path = project_root / "rules" / "project" / "manifest.json"
    output_path = project_root / "rules" / "inventory" / "composite.json"
    rule_path = (
        project_root
        / "rules"
        / "project"
        / "java"
        / "security"
        / "project-cwe327-desede-ecb-default.yaml"
    )
    rule_hash = write_rule(rule_path)
    write_upstream_inventory(inventory_path)
    write_project_manifest(manifest_path, rule_hash)
    return project_root, inventory_path, manifest_path, output_path


def test_build_composite_catalog_preserves_separate_provenance(tmp_path: Path) -> None:
    project_root, inventory_path, manifest_path, output_path = create_inputs(tmp_path)

    result = build_composite_catalog(
        upstream_inventory=inventory_path,
        project_manifest=manifest_path,
        project_root=project_root,
        output_path=output_path,
    )

    assert result.rule_count == 2
    catalog = json.loads(output_path.read_text(encoding="utf-8"))
    assert catalog["upstream_commit"] == UPSTREAM_COMMIT
    assert catalog["candidate_rule_count"] == 2
    assert catalog["sources"] == [
        {
            "source_type": "official_upstream",
            "upstream_commit": UPSTREAM_COMMIT,
        },
        {
            "source_type": "project_authored",
            "manifest_path": "rules/project/manifest.json",
        },
    ]

    rules_by_id = {rule["id"]: rule for rule in catalog["rules"]}
    assert rules_by_id["cbc-padding-oracle"]["source_type"] == "official_upstream"
    assert (
        rules_by_id["project-cwe327-desede-ecb-default"]["source_type"]
        == "project_authored"
    )
    assert (
        rules_by_id["project-cwe327-desede-ecb-default"]["source_root"]
        == "project_root"
    )


def test_build_composite_catalog_rejects_changed_project_rule(tmp_path: Path) -> None:
    project_root, inventory_path, manifest_path, output_path = create_inputs(tmp_path)
    rule_path = (
        project_root
        / "rules"
        / "project"
        / "java"
        / "security"
        / "project-cwe327-desede-ecb-default.yaml"
    )
    rule_path.write_text("rules: []\n", encoding="utf-8")

    with pytest.raises(CatalogError, match="project rule hash mismatch"):
        build_composite_catalog(
            upstream_inventory=inventory_path,
            project_manifest=manifest_path,
            project_root=project_root,
            output_path=output_path,
        )


def test_project_rule_manifest_declares_java_technology() -> None:
    manifest_path = (
        Path(__file__).resolve().parents[1]
        / "rules"
        / "project"
        / "manifest.json"
    )
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

    assert manifest["rules"][0]["technology"] == ["java"]


def test_run_catalog_command_returns_zero(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    project_root, inventory_path, manifest_path, output_path = create_inputs(tmp_path)
    args = SimpleNamespace(
        upstream_inventory=inventory_path,
        project_manifest=manifest_path,
        project_root=project_root,
        output=output_path,
    )

    assert run_catalog_command(args) == 0
    assert str(output_path) in capsys.readouterr().out
