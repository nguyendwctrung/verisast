"""Command-line entry point for Phase 5 preparation and execution."""

import argparse
import hashlib
import json
import secrets
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

from experiment import ExperimentError, preflight, validate_reviewed_units, verify_reviewed_unit_provenance
from experiment_execution import ExecutionError, execute, selected_sources
from experiment_prepare import PreparationError, prepare_cwe_bench
from experiment_runner import RunnerError, run_mock, validate_result_name
from ollama_client import OllamaError, metadata


def _load_manifest(path: Path) -> dict[str, object]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict) or payload.get("schema_version") != 1:
        raise ExperimentError("experiment manifest must be a schema-version-1 object")
    return payload


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="run_experiment")
    commands = parser.add_subparsers(dest="action", required=True)
    for action in ("preflight", "run", "mock", "prepare"):
        command = commands.add_parser(action)
        command.add_argument("--output-dir", type=Path, default=Path("artifacts/experiments"))
        command.add_argument("--result-name", required=True)
        if action == "prepare":
            command.add_argument("--source-root", type=Path, default=Path("datasets/raw"))
        elif action != "mock":
            command.add_argument("--mode", choices=("partial", "full"), required=False)
            command.add_argument("--dataset", choices=("owasp", "cwe-bench", "both"), default="both")
            command.add_argument("--source-root", type=Path, default=Path("datasets/raw"))
            command.add_argument("--manifest", type=Path, required=True)
            command.add_argument("--gate-evidence", type=Path)
            command.add_argument("--reviewed-units", type=Path)
            command.add_argument("--retrieval-contracts", type=Path)
            command.add_argument("--feasibility-manifest", type=Path)
            command.add_argument("--scan-config", type=Path, default=Path("configs/scan.json"))
            command.add_argument("--inference-config", type=Path, default=Path("configs/inference.json"))
            command.add_argument("--prompt", type=Path, default=Path("prompts/triage.txt"))
    args = parser.parse_args(argv)
    try:
        if args.action == "mock":
            result = run_mock(args.output_dir, args.result_name)
        elif args.action == "prepare":
            validate_result_name(args.result_name)
            stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
            target = args.output_dir / f"{args.result_name}-{stamp}-{secrets.token_hex(4)}"
            result = prepare_cwe_bench(args.source_root / "cwe-bench-java-120", target)
            result["output"] = str(target)
        else:
            manifest = _load_manifest(args.manifest)
            if args.mode and args.mode != manifest.get("mode"):
                raise ExperimentError("--mode differs from the frozen experiment manifest")
            selected = dict(manifest)
            if args.dataset == "owasp":
                selected.pop("cwe_bench", None)
            elif args.dataset == "cwe-bench":
                selected.pop("owasp", None)
            roots = args.source_root
            gates = _gate_status(args.gate_evidence)
            result = preflight(
                selected,
                roots / "owasp-benchmark-java-v1.2" if "owasp" in selected else None,
                roots / "owasp-benchmark-java-v1.2" / "expectedresults-1.2.csv" if "owasp" in selected else None,
                roots / "cwe-bench-java-120" if "cwe_bench" in selected else None,
                roots / "cwe-bench-java" if "cwe_bench" in selected else None,
                approvals=gates,
            )
            if "cwe_bench" in selected:
                if args.reviewed_units is None or not args.reviewed_units.is_file():
                    result["issues"].append("reviewed CWE-Bench evaluation units are missing (--reviewed-units)")
                else:
                    try:
                        units = json.loads(args.reviewed_units.read_text(encoding="utf-8"))
                        source_specs = selected_sources(selected, "cwe-bench", roots)
                        slugs = sorted({str(item["slug"]) for item in source_specs})
                        validate_reviewed_units(units, slugs)
                        result["issues"].extend(verify_reviewed_unit_provenance(
                            units, roots / "cwe-bench-java-120", roots / "cwe-bench-java"))
                    except (ExperimentError, ValueError, OSError) as error:
                        result["issues"].append(f"reviewed CWE-Bench units invalid: {error}")
            if args.feasibility_manifest is None or not args.feasibility_manifest.is_file():
                result["issues"].append("CodeQL feasibility manifest is missing (--feasibility-manifest)")
            else:
                result["issues"].extend(_feasibility_issues(args.feasibility_manifest, selected, args.dataset, roots))
            contract_paths = _contracts(args.retrieval_contracts)
            required_cwes = _required_cwes(selected, args.dataset, roots)
            if not contract_paths:
                result["issues"].append("admitted retrieval contracts are missing (--retrieval-contracts)")
            result["issues"].extend(_contract_issues(contract_paths, required_cwes))
            contract_paths = {cwe: path for cwe, path in contract_paths.items() if cwe in required_cwes}
            for label, path in (("scan config", args.scan_config),
                                ("inference config", args.inference_config), ("prompt", args.prompt)):
                if not path.is_file():
                    result["issues"].append(f"{label} is missing: {path}")
            if not result["issues"]:
                result["issues"].extend(_runtime_issues(args.scan_config, args.inference_config))
            result["ready"] = not result["issues"]
            result["dataset"] = args.dataset
            result["manifest"] = str(args.manifest.resolve())
            if args.action == "run" and not result["ready"]:
                print(json.dumps(result, indent=2))
                return 2
            if args.action == "run":
                result = execute(selected, args.manifest, args.dataset, roots,
                                 args.output_dir, args.result_name, args.scan_config,
                                 args.inference_config, args.prompt, contract_paths,
                                 args.reviewed_units)
        print(json.dumps(result, indent=2))
        return 0 if result.get("ready", True) else 2
    except (ExperimentError, PreparationError, RunnerError, RuntimeError, OSError, ValueError, json.JSONDecodeError) as error:
        print(f"ERROR={error}", file=sys.stderr)
        return 1


def _gate_status(path: Path | None) -> dict[str, bool]:
    if path is None or not path.is_file():
        return {"OD-002": False, "OD-006": False}
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ExperimentError("gate evidence must be an object")
    status = {}
    for name in ("OD-002", "OD-006"):
        record = payload.get(name)
        if not isinstance(record, dict) or record.get("status") != "accepted":
            status[name] = False
            continue
        evidence = record.get("evidence_path")
        expected_hash = record.get("sha256")
        if not isinstance(evidence, str) or not isinstance(expected_hash, str):
            status[name] = False
            continue
        source = Path(evidence)
        if not source.is_absolute():
            source = path.parent / source
        status[name] = source.is_file() and hashlib.sha256(source.read_bytes()).hexdigest() == expected_hash
    decisions = Path(__file__).resolve().parent.parent / ".agent" / "planning" / "OPEN_DECISIONS.md"
    if decisions.is_file():
        active = decisions.read_text(encoding="utf-8").split("## Resolved decisions", 1)[0]
        for name in status:
            if f"| {name} |" in active:
                status[name] = False
    return status


def _contracts(path: Path | None) -> dict[str, Path]:
    if path is None or not path.is_file():
        return {}
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict) or not all(isinstance(key, str) and isinstance(value, str)
                                                for key, value in payload.items()):
        raise ExperimentError("retrieval contracts map must be an object of CWE IDs to paths")
    return {key: Path(value) for key, value in payload.items()}


def _required_cwes(manifest: dict[str, object], dataset: str, roots: Path) -> set[str]:
    import csv
    required = set()
    if dataset in {"owasp", "both"} and "owasp" in manifest:
        if manifest["mode"] == "partial":
            required.update(manifest["owasp"].get("selected_ids", {}))
        else:
            required.update(str(item) for item in (22, 78, 79, 89, 90, 327, 328, 330, 501, 614, 643))
    if dataset in {"cwe-bench", "both"} and "cwe_bench" in manifest:
        metadata = roots / "cwe-bench-java-120" / "data" / "project_info.csv"
        if metadata.is_file():
            with metadata.open(encoding="utf-8", newline="") as stream:
                rows = list(csv.DictReader(stream))
            selected = set(manifest["cwe_bench"].get("selected_slugs", [])) if manifest["mode"] == "partial" else None
            for row in rows:
                if selected is None or row["project_slug"] in selected:
                    raw = row.get("cwe_id", "")
                    if raw.upper().startswith("CWE-") and raw[4:].isdigit():
                        required.add(str(int(raw[4:])))
    return required


def _feasibility_issues(path: Path, manifest: dict[str, object], dataset: str, roots: Path) -> list[str]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict) or not isinstance(payload.get("sources"), list):
        return ["CodeQL feasibility manifest must list sources"]
    indexed = {(item.get("dataset"), item.get("slug"), item.get("role")): item
               for item in payload["sources"] if isinstance(item, dict)}
    issues = []
    try:
        expected = selected_sources(manifest, dataset, roots)
    except (ExecutionError, OSError) as error:
        return [f"CodeQL feasibility scope invalid: {error}"]
    for source in expected:
        key = (source["dataset"], source["slug"], source["role"])
        item = indexed.get(key)
        if item is None or item.get("status") != "complete" or item.get("target_file_extracted") is not True:
            issues.append(f"CodeQL feasibility incomplete: {source['slug']}/{source['role']}")
            continue
        evidence = item.get("evidence_path")
        expected_hash = item.get("sha256")
        evidence_path = Path(evidence) if isinstance(evidence, str) else None
        if evidence_path is not None and not evidence_path.is_absolute():
            evidence_path = path.parent / evidence_path
        if (evidence_path is None or not evidence_path.is_file() or not isinstance(expected_hash, str)
                or hashlib.sha256(evidence_path.read_bytes()).hexdigest() != expected_hash):
            issues.append(f"CodeQL feasibility evidence missing or changed: {source['slug']}/{source['role']}")
            continue
        try:
            scan_record = json.loads(evidence_path.read_text(encoding="utf-8"))
            if scan_record.get("status") != "complete" or Path(str(scan_record.get("source", ""))).resolve() != Path(source["path"]).resolve():
                issues.append(f"CodeQL feasibility scan differs from source: {source['slug']}/{source['role']}")
        except (OSError, ValueError, TypeError):
            issues.append(f"CodeQL feasibility scan is invalid: {source['slug']}/{source['role']}")
    return issues


def _contract_issues(contracts: dict[str, Path], required_cwes: set[str]) -> list[str]:
    issues = []
    for cwe in sorted(required_cwes, key=int):
        path = contracts.get(cwe)
        if path is None or not path.is_file():
            issues.append(f"admitted retrieval contract missing for CWE-{cwe}")
            continue
        try:
            contract = json.loads(path.read_text(encoding="utf-8"))
            if (not isinstance(contract, dict)
                    or contract.get("contract_id") not in {"variant-c-retrieval-bundle-v1", "variant-c-retrieval-bundle-v2"}
                    or contract.get("metadata_filter", {}).get("cwe_id") != int(cwe)):
                issues.append(f"retrieval contract does not match CWE-{cwe}")
                continue
            admitted = contract.get("admitted_retrieval", {})
            for name in ("chunks_path", "documents_path"):
                source = Path(str(admitted.get(name, "")))
                if not source.is_file():
                    issues.append(f"CWE-{cwe} retrieval {name} is missing: {source}")
                elif admitted.get(name.replace("_path", "_sha256")) != hashlib.sha256(source.read_bytes()).hexdigest():
                    issues.append(f"CWE-{cwe} retrieval {name} hash mismatch")
        except (OSError, ValueError, TypeError) as error:
            issues.append(f"invalid retrieval contract for CWE-{cwe}: {error}")
    return issues


def _codeql_version(executable: str) -> str | None:
    import re
    try:
        result = subprocess.run([executable, "version"], capture_output=True, text=True,
                                check=False, timeout=30)
    except (OSError, subprocess.TimeoutExpired):
        return None
    match = re.search(r"\b\d+\.\d+\.\d+\b", result.stdout) if result.returncode == 0 else None
    return match.group(0) if match else None


def _runtime_issues(scan_path: Path, inference_path: Path) -> list[str]:
    issues = []
    try:
        scan = json.loads(scan_path.read_text(encoding="utf-8"))
        inference = json.loads(inference_path.read_text(encoding="utf-8"))
        if not isinstance(scan, dict) or not isinstance(inference, dict):
            return ["scan and inference configuration must be objects"]
        observed = _codeql_version(str(scan.get("codeql", "codeql")))
        if observed != scan.get("codeql_version"):
            issues.append(f"CodeQL version mismatch: expected {scan.get('codeql_version')}, observed {observed}")
        if inference.get("provider", "ollama") != "ollama":
            issues.append("inference provider is not implemented")
        else:
            model = metadata(str(inference["endpoint"]), str(inference["model"]),
                             int(inference["timeout_seconds"]))
            if model.get("model_digest") != inference.get("model_digest"):
                issues.append("inference model digest mismatch")
    except (OSError, ValueError, TypeError, KeyError, OllamaError) as error:
        issues.append(f"runtime provenance unavailable: {error}")
    return issues


if __name__ == "__main__":
    raise SystemExit(main())
