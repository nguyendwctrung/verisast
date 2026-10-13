import json
from pathlib import Path

import pytest

from semgrep_composite_inputs import CompositeInputError, freeze_composite_inputs, validate_composite_inputs
from semgrep_rules import sha256_file


def write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value), encoding="utf-8")


def write_chain(tmp_path: Path) -> tuple[Path, Path, Path]:
    catalog = tmp_path / "catalog.json"
    review = tmp_path / "review.json"
    ruleset = tmp_path / "ruleset.json"
    write_json(catalog, {"schema_version": 1, "status": "passed"})
    write_json(review, {"inventory_sha256": sha256_file(catalog)})
    write_json(ruleset, {"catalog_sha256": sha256_file(catalog), "review_sha256": sha256_file(review), "purpose": "development", "reportable": False})
    return catalog, review, ruleset


def test_freeze_and_validate_composite_inputs(tmp_path: Path) -> None:
    catalog, review, ruleset = write_chain(tmp_path)
    result = freeze_composite_inputs(catalog_path=catalog, review_path=review, ruleset_path=ruleset, output_dir=tmp_path / "inputs")

    assert Path(result.manifest_path).is_file()
    assert validate_composite_inputs(tmp_path / "inputs").output_dir == str((tmp_path / "inputs").resolve())


def test_validate_composite_inputs_rejects_changed_snapshot(tmp_path: Path) -> None:
    catalog, review, ruleset = write_chain(tmp_path)
    output_dir = tmp_path / "inputs"
    freeze_composite_inputs(catalog_path=catalog, review_path=review, ruleset_path=ruleset, output_dir=output_dir)
    (output_dir / "ruleset.json").write_text("changed", encoding="utf-8")

    with pytest.raises(CompositeInputError, match="artifact hash mismatch"):
        validate_composite_inputs(output_dir)
