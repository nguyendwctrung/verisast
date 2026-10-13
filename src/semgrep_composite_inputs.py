import json
import shutil
from dataclasses import dataclass
from pathlib import Path

from semgrep_rules import sha256_file


class CompositeInputError(ValueError):
    pass


@dataclass(frozen=True)
class CompositeInputResult:
    output_dir: str
    manifest_path: str


def freeze_composite_inputs(
    *,
    catalog_path: Path,
    review_path: Path,
    ruleset_path: Path,
    output_dir: Path,
) -> CompositeInputResult:
    catalog_path = catalog_path.resolve()
    review_path = review_path.resolve()
    ruleset_path = ruleset_path.resolve()
    output_dir = output_dir.resolve()
    if output_dir.exists():
        raise CompositeInputError(f"composite input directory already exists: {output_dir}")
    catalog = _read_object(catalog_path, "composite catalog")
    review = _read_object(review_path, "composite review")
    ruleset = _read_object(ruleset_path, "composite ruleset")
    _validate_chain(catalog, review, ruleset, catalog_path, review_path)

    output_dir.mkdir(parents=True)
    copies = {
        "catalog": output_dir / "catalog.json",
        "review": output_dir / "review.json",
        "ruleset": output_dir / "ruleset.json",
    }
    for source, target in (
        (catalog_path, copies["catalog"]),
        (review_path, copies["review"]),
        (ruleset_path, copies["ruleset"]),
    ):
        shutil.copy2(source, target)
    payload = {
        "schema_version": 1,
        "status": "frozen",
        "purpose": "development",
        "reportable": False,
        "sources": {
            name: {"path": str(path), "sha256": sha256_file(path)}
            for name, path in (
                ("catalog", catalog_path),
                ("review", review_path),
                ("ruleset", ruleset_path),
            )
        },
        "artifacts": {
            name: {"path": path.name, "sha256": sha256_file(path)}
            for name, path in copies.items()
        },
    }
    manifest_path = output_dir / "manifest.json"
    _write_json(manifest_path, payload)
    return CompositeInputResult(str(output_dir), str(manifest_path))


def validate_composite_inputs(input_dir: Path) -> CompositeInputResult:
    input_dir = input_dir.resolve()
    manifest_path = input_dir / "manifest.json"
    manifest = _read_object(manifest_path, "composite input manifest")
    if manifest.get("schema_version") != 1 or manifest.get("status") != "frozen":
        raise CompositeInputError("composite input manifest is not frozen")
    if manifest.get("purpose") != "development" or manifest.get("reportable") is not False:
        raise CompositeInputError("composite input manifest is not development-only")
    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, dict):
        raise CompositeInputError("composite input artifacts are missing")
    for name in ("catalog", "review", "ruleset"):
        record = artifacts.get(name)
        if not isinstance(record, dict) or not isinstance(record.get("path"), str):
            raise CompositeInputError(f"composite input artifact is invalid: {name}")
        path = (input_dir / record["path"]).resolve()
        if not path.is_relative_to(input_dir) or not path.is_file():
            raise CompositeInputError(f"composite input artifact is missing: {name}")
        if sha256_file(path) != record.get("sha256"):
            raise CompositeInputError(f"composite input artifact hash mismatch: {name}")
    catalog = _read_object(input_dir / "catalog.json", "copied composite catalog")
    review = _read_object(input_dir / "review.json", "copied composite review")
    ruleset = _read_object(input_dir / "ruleset.json", "copied composite ruleset")
    _validate_chain(
        catalog,
        review,
        ruleset,
        input_dir / "catalog.json",
        input_dir / "review.json",
    )
    return CompositeInputResult(str(input_dir), str(manifest_path))


def run_freeze_command(args: object) -> int:
    result = freeze_composite_inputs(
        catalog_path=Path(getattr(args, "catalog")),
        review_path=Path(getattr(args, "review")),
        ruleset_path=Path(getattr(args, "ruleset")),
        output_dir=Path(getattr(args, "output_dir")),
    )
    print(f"COMPOSITE_INPUTS={result.output_dir}")
    print(f"COMPOSITE_INPUT_MANIFEST={result.manifest_path}")
    return 0


def run_validate_command(args: object) -> int:
    result = validate_composite_inputs(Path(getattr(args, "input_dir")))
    print("COMPOSITE_INPUT_STATUS=validated")
    print(f"COMPOSITE_INPUT_MANIFEST={result.manifest_path}")
    return 0


def _validate_chain(
    catalog: dict[str, object],
    review: dict[str, object],
    ruleset: dict[str, object],
    catalog_path: Path,
    review_path: Path,
) -> None:
    if catalog.get("schema_version") != 1 or catalog.get("status") != "passed":
        raise CompositeInputError("composite catalog is not a passed schema version 1 artifact")
    if review.get("inventory_sha256") != sha256_file(catalog_path):
        raise CompositeInputError("composite review catalog hash mismatch")
    if ruleset.get("catalog_sha256") != sha256_file(catalog_path):
        raise CompositeInputError("composite ruleset catalog hash mismatch")
    if ruleset.get("review_sha256") != sha256_file(review_path):
        raise CompositeInputError("composite ruleset review hash mismatch")
    if ruleset.get("purpose") != "development" or ruleset.get("reportable") is not False:
        raise CompositeInputError("composite ruleset is not development-only")


def _read_object(path: Path, label: str) -> dict[str, object]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise CompositeInputError(f"cannot read {label}: {error}") from error
    if not isinstance(value, dict):
        raise CompositeInputError(f"{label} must be a JSON object")
    return value


def _write_json(path: Path, payload: dict[str, object]) -> None:
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(path)
