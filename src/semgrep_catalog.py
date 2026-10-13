import json
from dataclasses import dataclass
from pathlib import Path
from typing import cast

from semgrep_rules import sha256_file


class CatalogError(ValueError):
    pass


@dataclass(frozen=True)
class CatalogResult:
    rule_count: int
    output_path: str


def run_catalog_command(args: object) -> int:
    result = build_composite_catalog(
        upstream_inventory=Path(getattr(args, "upstream_inventory")),
        project_manifest=Path(getattr(args, "project_manifest")),
        project_root=Path(getattr(args, "project_root")),
        output_path=Path(getattr(args, "output")),
    )
    print(f"COMPOSITE_CATALOG={result.output_path}")
    return 0


def build_composite_catalog(
    *,
    upstream_inventory: Path,
    project_manifest: Path,
    project_root: Path,
    output_path: Path,
) -> CatalogResult:
    upstream_inventory = upstream_inventory.resolve()
    project_manifest = project_manifest.resolve()
    project_root = project_root.resolve()
    output_path = output_path.resolve()

    if output_path.exists():
        raise CatalogError(f"catalog output already exists: {output_path}")

    upstream = _read_object(upstream_inventory, "upstream inventory")
    manifest = _read_object(project_manifest, "project rule manifest")
    upstream_rules = _validate_upstream_inventory(upstream)
    project_rules = _load_project_rules(manifest, project_root)

    rules = [
        {**rule, "source_type": "official_upstream"}
        for rule in upstream_rules
    ]
    rules.extend(project_rules)

    identities = {
        (str(rule.get("source_path", "")), str(rule.get("id", "")))
        for rule in rules
    }
    if len(identities) != len(rules):
        raise CatalogError("composite catalog contains duplicate rule identities")

    try:
        manifest_path = project_manifest.relative_to(project_root).as_posix()
    except ValueError as error:
        raise CatalogError("project manifest must be inside project root") from error

    payload = {
        "schema_version": 1,
        "status": "passed",
        "upstream_commit": upstream["upstream_commit"],
        "candidate_rule_count": len(rules),
        "sources": [
            {
                "source_type": "official_upstream",
                "upstream_commit": upstream["upstream_commit"],
            },
            {
                "source_type": "project_authored",
                "manifest_path": manifest_path,
            },
        ],
        "rules": rules,
    }
    _write_json(output_path, payload)
    return CatalogResult(rule_count=len(rules), output_path=str(output_path))


def _validate_upstream_inventory(inventory: dict[str, object]) -> list[dict[str, object]]:
    if inventory.get("schema_version") != 1 or inventory.get("status") != "passed":
        raise CatalogError("upstream inventory is not a passed schema version 1 report")
    commit = inventory.get("upstream_commit")
    if not isinstance(commit, str) or len(commit) != 40:
        raise CatalogError("upstream inventory commit is invalid")
    rules = inventory.get("rules")
    if not isinstance(rules, list) or not rules:
        raise CatalogError("upstream inventory rules must be a non-empty list")
    if inventory.get("candidate_rule_count") != len(rules):
        raise CatalogError("upstream inventory rule count mismatch")
    return [cast(dict[str, object], rule) for rule in rules if isinstance(rule, dict)]


def _load_project_rules(
    manifest: dict[str, object],
    project_root: Path,
) -> list[dict[str, object]]:
    if manifest.get("schema_version") != 1:
        raise CatalogError("unsupported project rule manifest schema version")
    if manifest.get("source_type") != "project_authored":
        raise CatalogError("project rule manifest source_type must be project_authored")
    values = manifest.get("rules")
    if not isinstance(values, list) or not values:
        raise CatalogError("project rule manifest must contain rules")

    rules: list[dict[str, object]] = []
    for index, value in enumerate(values, 1):
        if not isinstance(value, dict):
            raise CatalogError(f"project rule {index} must be an object")
        rule_id = value.get("rule_id")
        source_path = value.get("source_path")
        expected_hash = value.get("source_sha256")
        if not isinstance(rule_id, str) or not rule_id:
            raise CatalogError(f"project rule {index} has invalid rule_id")
        if not isinstance(source_path, str) or not source_path:
            raise CatalogError(f"project rule {index} has invalid source_path")
        if not isinstance(expected_hash, str) or len(expected_hash) != 64:
            raise CatalogError(f"project rule {index} has invalid source_sha256")

        source = (project_root / source_path).resolve()
        if not source.is_relative_to(project_root) or not source.is_file():
            raise CatalogError(f"project rule file not found: {source_path}")
        if sha256_file(source) != expected_hash:
            raise CatalogError(f"project rule hash mismatch: {source_path}")

        rules.append(
            {
                "id": rule_id,
                "source_path": source_path,
                "source_sha256": expected_hash,
                "languages": _required_list(value, "languages", index),
                "mode": _required_text(value, "mode", index),
                "severity": _required_text(value, "severity", index),
                "category": _required_text(value, "category", index),
                "cwes": _required_list(value, "cwes", index),
                "confidence": value.get("confidence"),
                "technology": _required_list(value, "technology", index),
                "references": _required_list(value, "references", index),
                "source_type": "project_authored",
                "source_root": "project_root",
            }
        )
    return rules


def _required_text(value: dict[str, object], field: str, index: int) -> str:
    item = value.get(field)
    if not isinstance(item, str) or not item:
        raise CatalogError(f"project rule {index} has invalid {field}")
    return item


def _required_list(value: dict[str, object], field: str, index: int) -> list[object]:
    item = value.get(field)
    if not isinstance(item, list) or not item:
        raise CatalogError(f"project rule {index} has invalid {field}")
    return item


def _read_object(path: Path, label: str) -> dict[str, object]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise CatalogError(f"failed to read {label}: {error}") from error
    if not isinstance(value, dict):
        raise CatalogError(f"{label} must be a JSON object")
    return value


def _write_json(path: Path, payload: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    temporary.replace(path)
