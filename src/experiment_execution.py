"""No-overwrite A/B/C execution over preflighted experiment inputs."""

import csv
import hashlib
import json
import time
from datetime import datetime, timezone
from pathlib import Path

from context import build as build_context
from context import write as write_context
from evaluate import _finding_matches_cwe_bench_unit, score, score_cwe_bench
from experiment import read_labels, sha256, validate_reviewed_units
from experiment_report import evaluate_variants, model_usage, write_reports
from experiment_resources import ResourceMonitor
from experiment_runner import allocate_run
from paired_manifest import create as create_paired_manifest
from sarif import normalize, write as write_findings
from scan import run as scan_source
from stability import compare_deterministic_repetitions
from triage import run_paired
from triage_stability import aggregate_triage_runs


class ExecutionError(ValueError):
    pass


def selected_sources(manifest: dict[str, object], dataset: str, source_root: Path) -> list[dict[str, object]]:
    """Enumerate all source revisions without using scanner outcomes."""
    sources = []
    if dataset in {"owasp", "both"}:
        if not isinstance(manifest.get("owasp"), dict):
            raise ExecutionError("OWASP manifest is missing")
        sources.append({"dataset": "owasp", "slug": "owasp-benchmark-java-v1.2", "role": "source",
                        "path": source_root / "owasp-benchmark-java-v1.2",
                        "revision": manifest["owasp"]["commit"]})
    if dataset in {"cwe-bench", "both"}:
        cwe = manifest.get("cwe_bench")
        if not isinstance(cwe, dict):
            raise ExecutionError("CWE-Bench manifest is missing")
        metadata = source_root / "cwe-bench-java-120" / "data" / "project_info.csv"
        if manifest.get("mode") == "full":
            if not metadata.is_file():
                raise ExecutionError("CWE-Bench project metadata is missing")
            with metadata.open(encoding="utf-8", newline="") as stream:
                slugs = [row["project_slug"] for row in csv.DictReader(stream)]
        else:
            slugs = cwe.get("selected_slugs")
        if not isinstance(slugs, list) or not slugs or not all(isinstance(item, str) for item in slugs):
            raise ExecutionError("CWE-Bench project slugs are missing")
        if len(slugs) != len(set(slugs)):
            raise ExecutionError("CWE-Bench project slugs contain duplicates")
        for slug in slugs:
            for role in ("buggy", "fixed"):
                sources.append({"dataset": "cwe-bench", "slug": slug, "role": role,
                                "path": source_root / "cwe-bench-java" / slug / role,
                                "revision": None})
    return sources


def _jsonl(path: Path) -> list[dict[str, object]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]


def _selection(manifest: dict[str, object], source: dict[str, object],
               findings: list[dict[str, object]], units: list[dict[str, object]]) -> list[dict[str, object]]:
    if source["dataset"] == "owasp" and manifest["mode"] == "partial":
        selected = {test_id for ids in manifest["owasp"]["selected_ids"].values() for test_id in ids}
        return [row for row in findings if row.get("test_id") in selected]
    if source["dataset"] == "cwe-bench":
        scoped = [unit for unit in units if unit.get("target_id") == f"{source['slug']}/{source['role']}"]
        if len(scoped) != 1:
            raise ExecutionError(f"expected one reviewed target unit: {source['slug']}/{source['role']}")
        unit = scoped[0]
        return [row for row in findings if _finding_matches_cwe_bench_unit(row, unit)]
    return findings


def execute(
    manifest: dict[str, object], manifest_path: Path, dataset: str, source_root: Path,
    output_dir: Path, result_name: str, scan_config_path: Path, inference_config_path: Path,
    prompt_path: Path, retrieval_contracts: dict[str, Path],
    reviewed_units_path: Path | None,
) -> dict[str, object]:
    """Execute only after external preflight and gate review have passed."""
    sources = selected_sources(manifest, dataset, source_root)
    scan_config = json.loads(scan_config_path.read_text(encoding="utf-8"))
    inference_config = json.loads(inference_config_path.read_text(encoding="utf-8"))
    cwe_units = json.loads(reviewed_units_path.read_text(encoding="utf-8")) if reviewed_units_path else []
    if any(source["dataset"] == "cwe-bench" for source in sources):
        selected_slugs = sorted({str(source["slug"]) for source in sources if source["dataset"] == "cwe-bench"})
        validate_reviewed_units(cwe_units, selected_slugs)
        cwe_units = [{**unit, "pair_id": str(unit["target_id"]).rsplit("/", 1)[0]}
                     for unit in cwe_units]
    run = allocate_run(output_dir, result_name)
    started_clock = time.monotonic()
    started_at = datetime.now(timezone.utc).isoformat()
    manifest_record = {
        "schema_version": 1, "run_id": run.name, "status": "running", "mode": manifest["mode"],
        "dataset": dataset, "started_at": started_at,
        "input_manifest": {"path": str(manifest_path.resolve()), "sha256": sha256(manifest_path)},
        "scan_config": {"path": str(scan_config_path.resolve()), "sha256": sha256(scan_config_path)},
        "inference_config": {"path": str(inference_config_path.resolve()), "sha256": sha256(inference_config_path)},
        "prompt": {"path": str(prompt_path.resolve()), "sha256": sha256(prompt_path)},
        "reviewed_units": {"path": str(reviewed_units_path.resolve()), "sha256": sha256(reviewed_units_path)} if reviewed_units_path else None,
        "retrieval_contracts": {key: {"path": str(path.resolve()), "sha256": sha256(path)}
                                for key, path in retrieval_contracts.items()},
        "sources": [],
    }
    (run / "manifest.json").write_text(json.dumps(manifest_record, indent=2) + "\n", encoding="utf-8")
    monitor = ResourceMonitor()
    monitor.start()
    try:
        outcomes = _execute_sources(run, manifest, sources, source_root, scan_config,
                                    inference_config_path, prompt_path, retrieval_contracts, cwe_units)
        resources = monitor.stop()
        manifest_record["status"] = "completed"
        manifest_record["sources"] = outcomes["sources"]
        manifest_record["resources"] = resources
        source_set_hash = hashlib.sha256(json.dumps(
            [{"dataset": item["dataset"], "slug": item["slug"], "role": item["role"],
              "source_revision": item["source_revision"]} for item in outcomes["sources"]],
            sort_keys=True).encode("utf-8")).hexdigest()
        corpus_ids = {}
        for cwe, path in retrieval_contracts.items():
            contract = json.loads(path.read_text(encoding="utf-8"))
            corpus_ids[cwe] = contract["admitted_retrieval"]["corpus_id"]
        identity = {"source_set_sha256": source_set_hash,
                    "codeql_version": scan_config.get("codeql_version"),
                    "query_pack": scan_config.get("query_pack"),
                    "query_pack_version": scan_config.get("query_pack_version"),
                    "query_suite": scan_config.get("suite"),
                    "model": inference_config.get("model"),
                    "model_digest": inference_config.get("model_digest"),
                    "corpus_ids": json.dumps(corpus_ids, sort_keys=True)}
        manifest_record["reports"] = _report(run, manifest, outcomes["collected"], resources, identity)
        manifest_record["finished_at"] = datetime.now(timezone.utc).isoformat()
        manifest_record["duration_seconds"] = round(time.monotonic() - started_clock, 3)
    except Exception as error:
        manifest_record["resources"] = monitor.stop()
        manifest_record["status"] = "failed"
        manifest_record["error"] = f"{type(error).__name__}: {error}"
        manifest_record["finished_at"] = datetime.now(timezone.utc).isoformat()
        manifest_record["duration_seconds"] = round(time.monotonic() - started_clock, 3)
        (run / "manifest.json").write_text(json.dumps(manifest_record, indent=2) + "\n", encoding="utf-8")
        raise
    (run / "manifest.json").write_text(json.dumps(manifest_record, indent=2) + "\n", encoding="utf-8")
    return {"status": "completed", "run_directory": str(run), "run_id": run.name}


def _execute_sources(
    run: Path, manifest: dict[str, object], sources: list[dict[str, object]],
    source_root: Path, scan_config: dict[str, object], inference_config_path: Path,
    prompt_path: Path, retrieval_contracts: dict[str, Path],
    cwe_units: list[dict[str, object]],
) -> dict[str, object]:
    collected = {name: {"findings": [], "B": {}, "C": {}, "units": [], "usage": {},
                        "retrieval": {}, "scan_seconds": 0.0}
                 for name in ("owasp", "cwe-bench")}
    source_records = []
    owasp_labels = source_root / "owasp-benchmark-java-v1.2" / "expectedresults-1.2.csv"
    if any(source["dataset"] == "owasp" for source in sources):
        labels = read_labels(owasp_labels)
        if manifest["mode"] == "partial":
            selected = {test_id for ids in manifest["owasp"]["selected_ids"].values() for test_id in ids}
            labels = [row for row in labels if row["test_id"] in selected]
        collected["owasp"]["units"] = labels
    collected["cwe-bench"]["units"] = cwe_units
    for source in sources:
        dataset = str(source["dataset"])
        slug = str(source["slug"])
        role = str(source["role"])
        root = run / "sources" / dataset / slug / role
        root.mkdir(parents=True)
        repeats = []
        for index in (1, 2):
            scan_dir = root / f"A-{index}"
            scan_record = scan_source(Path(source["path"]), scan_dir, str(scan_config["codeql"]), str(scan_config["suite"]))
            source_revision = str(source["revision"] or _git_revision(Path(source["path"])))
            findings = normalize(scan_dir / "raw" / "results.sarif", source_revision,
                                 str(scan_config["query_pack"]), str(scan_config["suite"]))
            findings = _selection(manifest, source, findings, collected[dataset]["units"])
            contexts = build_context(Path(source["path"]), findings)
            if any(context.get("truncated") or context.get("missing_evidence") for context in contexts):
                raise ExecutionError(f"incomplete source context: {slug}/{role}")
            if dataset == "owasp":
                matches = score(collected[dataset]["units"], findings)["matches"]
            else:
                local_findings = [{**finding, "target_id": f"{slug}/{role}"} for finding in findings]
                matches = score_cwe_bench(
                    [unit for unit in cwe_units if unit["target_id"] == f"{slug}/{role}"],
                    local_findings, require_pairs=False,
                )["matches"]
            findings_path = scan_dir / "normalized" / "findings.jsonl"
            contexts_path = scan_dir / "context" / "contexts.jsonl"
            write_findings(findings_path, findings)
            write_context(contexts_path, contexts)
            repeats.append({"findings": findings, "contexts": contexts, "matches": matches,
                            "scan": scan_record,
                            "findings_path": findings_path, "contexts_path": contexts_path})
        baseline_gate = compare_deterministic_repetitions([
            {"findings": item["findings"], "contexts": item["contexts"],
             "matches": item["matches"]} for item in repeats
        ])
        first = repeats[0]
        paired_path = root / "paired-manifest.json"
        create_paired_manifest(first["findings_path"], first["contexts_path"], prompt_path,
                               inference_config_path, paired_path, str(source["revision"] or
                               _git_revision(Path(source["path"]))), ["triage", "--variant", "B"])
        aggregate = {}
        usage = {}
        retrieval = {}
        stability = {}
        for variant in ("B", "C"):
            contracts = {int(cwe): path for cwe, path in retrieval_contracts.items()} if variant == "C" else None
            variant_runs = []
            for index in (1, 2, 3):
                triage_dir = root / f"{variant}-{index}"
                run_paired(first["findings_path"], first["contexts_path"], prompt_path,
                           inference_config_path, triage_dir, variant,
                           paired_manifest_path=paired_path, retrieval_contract_paths=contracts)
                variant_runs.append(triage_dir)
            aggregate_dir = root / f"{variant}-aggregate"
            stability[variant] = aggregate_triage_runs(variant_runs, aggregate_dir)
            aggregate[variant] = {str(row["candidate_id"]): row for row in _jsonl(aggregate_dir / "verdicts.jsonl")}
            usage[variant] = [model_usage(path, [str(item["id"]) for item in first["findings"]])
                              for path in variant_runs]
            retrieval[variant] = [{str(row["candidate_id"]): row.get("retrieval_seconds")
                                   for row in _jsonl(path / "verdicts.jsonl")} for path in variant_runs]
        collected[dataset]["scan_seconds"] += sum(float(item["scan"]["duration_seconds"]) for item in repeats)
        for finding in first["findings"]:
            original_id = str(finding["id"])
            qualified = f"{slug}/{role}/{original_id}"
            copied = {**finding, "id": qualified}
            if dataset == "cwe-bench":
                copied["target_id"] = f"{slug}/{role}"
            collected[dataset]["findings"].append(copied)
            for variant in ("B", "C"):
                collected[dataset][variant][qualified] = aggregate[variant][original_id]
                collected[dataset]["usage"][(variant, qualified)] = [item[original_id] for item in usage[variant]]
                collected[dataset]["retrieval"][(variant, qualified)] = [item.get(original_id) for item in retrieval[variant]]
        source_records.append({"dataset": dataset, "slug": slug, "role": role,
                               "source_revision": str(source["revision"] or _git_revision(Path(source["path"]))),
                               "candidate_count": len(first["findings"]),
                               "candidate_sha256": sha256(first["findings_path"]),
                               "context_sha256": sha256(first["contexts_path"]),
                               "baseline_stability": baseline_gate,
                               "baseline_repetitions": [str(root / "A-1"), str(root / "A-2")],
                               "paired_manifest": str(paired_path),
                               "triage_stability": {variant: {"status": stability[variant]["gate"]["status"],
                                                              "manifest": str(root / f"{variant}-aggregate" / "manifest.json"),
                                                              "verdicts_sha256": sha256(root / f"{variant}-aggregate" / "verdicts.jsonl")}
                                                    for variant in ("B", "C")},
                               "triage_repetitions": {variant: [str(root / f"{variant}-{index}") for index in (1, 2, 3)]
                                                     for variant in ("B", "C")}})
    return {"sources": source_records, "collected": collected}


def _git_revision(source: Path) -> str:
    import subprocess
    result = subprocess.run(["git", "-C", str(source), "rev-parse", "HEAD"],
                            capture_output=True, text=True, check=False)
    if result.returncode or not result.stdout.strip():
        raise ExecutionError(f"source revision unavailable: {source}")
    return result.stdout.strip()


def _report(run: Path, manifest: dict[str, object], collected: dict[str, dict[str, object]],
            resources: dict[str, object], identity: dict[str, object]) -> dict[str, object]:
    report_paths = {}
    for dataset, data in collected.items():
        if not data["units"]:
            continue
        results = evaluate_variants(dataset, data["units"], data["findings"], data["B"], data["C"])
        report_dir = run / "reports" / dataset
        report_dir.mkdir(parents=True)
        (report_dir / "metrics.json").write_text(json.dumps(results, indent=2) + "\n", encoding="utf-8")
        run_rows = []
        finding_rows = []
        unit_rows = []
        for variant, outcome in results.items():
            usage = [item for (name, _), entries in data["usage"].items() if name == variant for item in entries]
            input_tokens = sum(item["input_tokens"] for item in usage) if usage and all(item["input_tokens"] is not None for item in usage) else None
            output_tokens = sum(item["output_tokens"] for item in usage) if usage and all(item["output_tokens"] is not None for item in usage) else None
            inference_seconds = sum(item["duration_seconds"] for item in usage) if usage and all(item["duration_seconds"] is not None for item in usage) else None
            retrieval_values = [value for (name, _), entries in data["retrieval"].items() if name == variant
                                for value in entries]
            retrieval_seconds = (sum(retrieval_values) if retrieval_values and all(value is not None for value in retrieval_values)
                                 else 0.0 if variant in {"A", "B"} else None)
            duration_seconds = (data["scan_seconds"] + (inference_seconds or 0) + (retrieval_seconds or 0)
                                if variant == "A" or inference_seconds is not None and retrieval_seconds is not None else None)
            run_rows.append({"dataset": dataset, "mode": manifest["mode"], "variant": variant,
                             "status": "completed", **identity, **outcome["overall"],
                             "pair_count": outcome.get("pair_count"), "pair_accuracy": outcome.get("pair_accuracy"),
                             "matching_policy": outcome["matching_policy"],
                             "evaluation_unit": "OWASP testcase/CWE" if dataset == "owasp" else "target-CVE revision",
                             "false_positives_reduced": outcome.get("false_positives_reduced"),
                             "true_positives_lost": outcome.get("true_positives_lost"),
                             "recall_preservation": outcome.get("recall_preservation"),
                             "uncertain_count": outcome.get("uncertain_count"),
                             "uncertain_denominator": outcome.get("uncertain_denominator"),
                             "uncertain_rate": outcome.get("uncertain_rate"),
                             "input_tokens": input_tokens, "output_tokens": output_tokens,
                             "scan_seconds": data["scan_seconds"],
                             "retrieval_seconds": retrieval_seconds,
                             "inference_seconds": inference_seconds,
                             "duration_seconds": duration_seconds,
                             "peak_ram_mb": resources["peak_ram_mb"],
                             "peak_vram_mb": resources["peak_vram_mb"],
                             "resource_status": resources["resource_status"]})
            for finding in data["findings"]:
                candidate_id = str(finding["id"])
                verdict = data[variant].get(candidate_id, {}) if variant != "A" else {}
                usage_rows = data["usage"].get((variant, candidate_id), [])
                retrieval_rows = data["retrieval"].get((variant, candidate_id), [])
                finding_rows.append({"dataset": dataset, "mode": manifest["mode"], "variant": variant,
                                     "candidate_id": candidate_id,
                                     "effective_verdict": verdict.get("effective_verdict", "CANDIDATE"),
                                     "error": verdict.get("error"),
                                     "input_tokens": sum(item["input_tokens"] for item in usage_rows) if usage_rows and all(item["input_tokens"] is not None for item in usage_rows) else None,
                                     "output_tokens": sum(item["output_tokens"] for item in usage_rows) if usage_rows and all(item["output_tokens"] is not None for item in usage_rows) else None,
                                     "retrieval_seconds": sum(retrieval_rows) if retrieval_rows and all(value is not None for value in retrieval_rows) else None,
                                     "duration_seconds": sum(item["duration_seconds"] for item in usage_rows) if usage_rows and all(item["duration_seconds"] is not None for item in usage_rows) else None,
                                     "usage_missing_reason": next((item["missing_reason"] for item in usage_rows if item["missing_reason"]), None)})
            for unit in outcome["matches"]:
                unit_id = unit.get("test_id") or unit.get("target_id")
                unit_rows.append({"dataset": dataset, "mode": manifest["mode"], "variant": variant,
                                  "unit_id": unit_id, "cwe": unit["cwe"],
                                  "vulnerable": unit.get("vulnerable", unit.get("revision_role") == "buggy"),
                                  "candidate_ids": json.dumps(unit["candidate_ids"]), "outcome": unit["outcome"]})
        write_reports(report_dir, run.name, "../../manifest.json", run_rows, finding_rows, unit_rows)
        report_paths[dataset] = {
            name: {"path": str(report_dir / filename), "sha256": sha256(report_dir / filename)}
            for name, filename in (("metrics", "metrics.json"), ("runs_csv", "runs.csv"),
                                   ("findings_csv", "findings.csv"), ("units_csv", "units.csv"))
        }
    return report_paths
