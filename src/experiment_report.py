"""Variant-aware evaluation and traceable Phase 5 summaries."""

import csv
import json
from pathlib import Path

from evaluate import score, score_cwe_bench


class ReportError(ValueError):
    pass


def evaluate_variants(
    dataset: str, units: list[dict[str, object]], findings: list[dict[str, object]],
    b_verdicts: dict[str, dict[str, object]], c_verdicts: dict[str, dict[str, object]],
) -> dict[str, dict[str, object]]:
    """Evaluate A/B/C over identical candidate and ground-truth universes."""
    scorer = score if dataset == "owasp" else score_cwe_bench if dataset == "cwe-bench" else None
    if scorer is None:
        raise ReportError(f"unsupported dataset: {dataset}")
    candidate_ids = {str(row["id"]) for row in findings}
    for name, verdicts in (("B", b_verdicts), ("C", c_verdicts)):
        if set(verdicts) != candidate_ids:
            raise ReportError(f"{name} verdict candidate set differs from A")
        if any(row.get("effective_verdict") not in {"TRUE_POSITIVE", "FALSE_POSITIVE", "UNCERTAIN"}
               for row in verdicts.values()):
            raise ReportError(f"{name} has an invalid effective verdict")
    baseline = scorer(units, findings)
    _group_metrics(baseline)
    results = {"A": baseline}
    for name, verdicts in (("B", b_verdicts), ("C", c_verdicts)):
        kept = [finding for finding in findings
                if verdicts[str(finding["id"])]["effective_verdict"] != "FALSE_POSITIVE"]
        result = scorer(units, kept)
        _group_metrics(result)
        original_tp = baseline["overall"]["tp"]
        result["recall_preservation"] = (
            sum(base["outcome"] == "TP" and observed["outcome"] == "TP"
                for base, observed in zip(baseline["matches"], result["matches"])) / original_tp
            if original_tp else None
        )
        result["false_positives_reduced"] = baseline["overall"]["fp"] - result["overall"]["fp"]
        result["true_positives_lost"] = original_tp - result["overall"]["tp"]
        result["uncertain_count"] = sum(row["effective_verdict"] == "UNCERTAIN" for row in verdicts.values())
        result["uncertain_denominator"] = len(findings)
        result["uncertain_rate"] = result["uncertain_count"] / len(findings) if findings else None
        results[name] = result
    return results


def _group_metrics(result: dict[str, object]) -> None:
    counts_by_cwe: dict[str, dict[str, int]] = {}
    for row in result["matches"]:
        key = str(row["cwe"])
        counts = counts_by_cwe.setdefault(key, {name: 0 for name in ("tp", "fp", "tn", "fn")})
        counts[str(row["outcome"]).lower()] += 1
    by_cwe = {}
    for key, counts in sorted(counts_by_cwe.items(), key=lambda item: int(item[0])):
        tp, fp, tn, fn = (counts[name] for name in ("tp", "fp", "tn", "fn"))
        precision = tp / (tp + fp) if tp + fp else None
        recall = tp / (tp + fn) if tp + fn else None
        by_cwe[key] = {**counts, "precision": precision, "recall": recall,
                       "f1": 2 * precision * recall / (precision + recall)
                       if precision is not None and recall is not None and precision + recall else None,
                       "fpr": fp / (fp + tn) if fp + tn else None}
    result["by_cwe"] = by_cwe
    macro = {}
    for metric in ("precision", "recall", "f1", "fpr"):
        values = [row[metric] for row in by_cwe.values() if row[metric] is not None]
        macro[metric] = sum(values) / len(values) if values else None
    result["macro"] = macro


def model_usage(run: Path, candidate_ids: list[str]) -> dict[str, dict[str, object]]:
    """Read provider-reported usage; never estimate absent token counts."""
    result = {}
    for candidate_id in candidate_ids:
        path = run / "raw" / f"{candidate_id}.json"
        if not path.is_file():
            result[candidate_id] = {"input_tokens": None, "output_tokens": None,
                                    "duration_seconds": None, "missing_reason": "raw_response_missing"}
            continue
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            raise ReportError(f"invalid raw model response {path}: {error}") from error
        if not isinstance(payload, dict):
            raise ReportError(f"raw model response must be an object: {path}")
        prompt_tokens = payload.get("prompt_eval_count")
        output_tokens = payload.get("eval_count")
        duration = payload.get("total_duration")
        result[candidate_id] = {
            "input_tokens": prompt_tokens if type(prompt_tokens) is int and prompt_tokens >= 0 else None,
            "output_tokens": output_tokens if type(output_tokens) is int and output_tokens >= 0 else None,
            "duration_seconds": duration / 1_000_000_000 if type(duration) is int and duration >= 0 else None,
            "missing_reason": None if all(type(value) is int and value >= 0 for value in
                                          (prompt_tokens, output_tokens, duration)) else "provider_usage_missing",
        }
    return result


def _write_csv(path: Path, columns: list[str], rows: list[dict[str, object]]) -> None:
    if path.exists():
        raise ReportError(f"report already exists: {path}")
    with path.open("x", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=columns, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def write_reports(
    output: Path, run_id: str, manifest_path: str,
    runs: list[dict[str, object]], findings: list[dict[str, object]],
    units: list[dict[str, object]],
) -> None:
    """Write stable CSV tables whose rows link to one immutable run manifest."""
    output.mkdir(parents=True, exist_ok=True)
    for filename, columns, records in (
        ("runs.csv", ["run_id", "manifest", "dataset", "mode", "variant", "status",
                      "source_set_sha256", "codeql_version", "query_pack", "query_pack_version", "query_suite",
                      "model", "model_digest", "corpus_ids",
                      "tp", "fp", "tn", "fn", "precision", "recall", "f1", "fpr",
                      "pair_count", "pair_accuracy", "matching_policy", "evaluation_unit",
                      "false_positives_reduced", "true_positives_lost", "recall_preservation",
                      "uncertain_count", "uncertain_denominator", "uncertain_rate",
                      "input_tokens", "output_tokens", "scan_seconds", "retrieval_seconds",
                      "inference_seconds", "duration_seconds", "peak_ram_mb", "peak_vram_mb",
                      "resource_status"], runs),
        ("findings.csv", ["run_id", "manifest", "dataset", "mode", "variant", "candidate_id",
                          "effective_verdict", "error", "input_tokens", "output_tokens",
                          "retrieval_seconds", "duration_seconds", "usage_missing_reason"], findings),
        ("units.csv", ["run_id", "manifest", "dataset", "mode", "variant", "unit_id",
                       "cwe", "vulnerable", "candidate_ids", "outcome"], units),
    ):
        decorated = [{"run_id": run_id, "manifest": manifest_path, **row} for row in records]
        _write_csv(output / filename, columns, decorated)
