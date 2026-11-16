"""Freeze and verify the invariant inputs of a paired B/C development run."""

import hashlib
import json
from pathlib import Path


class PairedManifestError(ValueError):
    pass


_INPUT_NAMES = ("findings", "contexts", "prompt", "schema", "config", "neutral_contract")


def create(
    findings_path: Path,
    contexts_path: Path,
    prompt_path: Path,
    config_path: Path,
    output_path: Path,
    source_revision: str,
    intended_b_command: list[str],
) -> dict[str, object]:
    """Create one non-overwritable paired-development input manifest."""
    if output_path.exists():
        raise PairedManifestError(f"paired manifest already exists: {output_path}")
    if not isinstance(source_revision, str) or not source_revision.strip():
        raise PairedManifestError("source_revision is required")
    if not _valid_command(intended_b_command):
        raise PairedManifestError("intended_b_command must be a non-empty string list")
    config, schema_path, neutral_contract_path = _config_provenance(config_path)
    manifest = {
        "schema_version": 1,
        "kind": "paired-development-input-manifest",
        "purpose": "development_only",
        "source_revision": source_revision,
        "intended_b_command": intended_b_command,
        "inputs": {
            "findings": _record(findings_path),
            "contexts": _record(contexts_path),
            "prompt": _record(prompt_path),
            "schema": _record(schema_path),
            "config": _record(config_path),
            "neutral_contract": _record(neutral_contract_path),
        },
        "model": {"name": config["model"], "digest": config["model_digest"]},
    }
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return manifest


def validate(
    manifest_path: Path,
    findings_path: Path,
    contexts_path: Path,
    prompt_path: Path,
    config_path: Path,
) -> dict[str, object]:
    """Ensure current paired-run inputs are exactly the frozen inputs."""
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise PairedManifestError(f"invalid paired manifest: {error}") from error
    _validate_shape(manifest)
    config, schema_path, neutral_contract_path = _config_provenance(config_path)
    actual = {
        "findings": findings_path,
        "contexts": contexts_path,
        "prompt": prompt_path,
        "schema": schema_path,
        "config": config_path,
        "neutral_contract": neutral_contract_path,
    }
    for name, path in actual.items():
        frozen = manifest["inputs"][name]
        record = _record(path)
        if frozen["path"] != record["path"]:
            raise PairedManifestError(f"{name} path does not match paired manifest")
        if frozen["sha256"] != record["sha256"]:
            label = "neutral contract" if name == "neutral_contract" else name
            raise PairedManifestError(f"{label} hash does not match paired manifest")
    if manifest["model"]["name"] != config["model"]:
        raise PairedManifestError("model name does not match paired manifest")
    if manifest["model"]["digest"] != config["model_digest"]:
        raise PairedManifestError("model digest does not match paired manifest")
    return manifest


def _config_provenance(config_path: Path) -> tuple[dict[str, str], Path, Path]:
    try:
        config = json.loads(config_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise PairedManifestError(f"invalid paired configuration: {error}") from error
    if not isinstance(config, dict) or config.get("interface") != "neutral-triage":
        raise PairedManifestError("neutral triage configuration is required")
    required = ("schema", "neutral_contract", "model", "model_digest")
    if any(not isinstance(config.get(name), str) or not config[name] for name in required):
        raise PairedManifestError("paired configuration is missing required provenance")
    schema_path = config_path.parent / str(config["schema"])
    neutral_contract_path = config_path.parent / str(config["neutral_contract"])
    try:
        neutral_contract = json.loads(neutral_contract_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise PairedManifestError(f"invalid neutral contract: {error}") from error
    if not isinstance(neutral_contract, dict) or neutral_contract.get("contract_id") != "neutral-triage-interface":
        raise PairedManifestError("neutral triage contract is invalid")
    _record(schema_path)
    return config, schema_path, neutral_contract_path


def _validate_shape(manifest: object) -> None:
    if not isinstance(manifest, dict):
        raise PairedManifestError("paired manifest must be an object")
    if manifest.get("schema_version") != 1 or manifest.get("kind") != "paired-development-input-manifest":
        raise PairedManifestError("paired manifest schema is invalid")
    if manifest.get("purpose") != "development_only":
        raise PairedManifestError("paired manifest must be development_only")
    if not isinstance(manifest.get("source_revision"), str) or not manifest["source_revision"]:
        raise PairedManifestError("source_revision is required")
    if not _valid_command(manifest.get("intended_b_command")):
        raise PairedManifestError("intended_b_command must be a non-empty string list")
    inputs = manifest.get("inputs")
    if not isinstance(inputs, dict):
        raise PairedManifestError("paired manifest inputs are required")
    for name in _INPUT_NAMES:
        value = inputs.get(name)
        if not isinstance(value, dict) or not isinstance(value.get("path"), str) or not isinstance(value.get("sha256"), str):
            raise PairedManifestError(f"paired manifest input is invalid: {name}")
    model = manifest.get("model")
    if not isinstance(model, dict) or not isinstance(model.get("name"), str) or not isinstance(model.get("digest"), str):
        raise PairedManifestError("paired manifest model is invalid")


def _record(path: Path) -> dict[str, str]:
    try:
        data = path.read_bytes()
    except OSError as error:
        raise PairedManifestError(f"unable to read frozen input {path}: {error}") from error
    return {"path": str(path.resolve()), "sha256": hashlib.sha256(data).hexdigest()}


def _valid_command(value: object) -> bool:
    return isinstance(value, list) and bool(value) and all(isinstance(item, str) and item for item in value)
