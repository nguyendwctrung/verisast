from collections import defaultdict


class EvaluationError(ValueError):
    pass


def evaluate_findings(
    cohort: dict[str, object],
    findings: list[dict[str, object]],
    raw_finding_count: int,
) -> tuple[list[dict[str, object]], dict[str, object]]:
    units = cohort.get("units")
    if not isinstance(units, list):
        raise EvaluationError("cohort units must be a list")
    candidates_by_unit: dict[tuple[str, int], set[str]] = defaultdict(set)
    mapped_ids: set[str] = set()
    for finding in findings:
        candidate_id = str(finding.get("candidate_id", ""))
        test_id = finding.get("test_id")
        cwes = finding.get("reviewed_cwes")
        if not isinstance(test_id, str) or not isinstance(cwes, list):
            continue
        for cwe in cwes:
            if isinstance(cwe, int):
                candidates_by_unit[(test_id, cwe)].add(candidate_id)
    matches: list[dict[str, object]] = []
    overall = _empty_counts()
    per_cwe_counts: dict[int, dict[str, int]] = defaultdict(_empty_counts)
    predicted_units = 0
    for value in units:
        if not isinstance(value, dict):
            raise EvaluationError("cohort unit must be an object")
        test_id = value.get("test_id")
        cwe = value.get("cwe")
        vulnerable = value.get("vulnerable")
        if not isinstance(test_id, str) or not isinstance(cwe, int) or not isinstance(vulnerable, bool):
            raise EvaluationError("cohort unit has invalid fields")
        candidate_ids = sorted(candidates_by_unit.get((test_id, cwe), set()))
        predicted = bool(candidate_ids)
        if predicted:
            predicted_units += 1
            mapped_ids.update(candidate_ids)
        outcome = _outcome(vulnerable, predicted)
        overall[outcome] += 1
        per_cwe_counts[cwe][outcome] += 1
        matches.append(
            {
                "test_id": test_id,
                "cwe": cwe,
                "vulnerable": vulnerable,
                "predicted_vulnerable": predicted,
                "outcome": outcome.upper(),
                "candidate_ids": candidate_ids,
            }
        )
    metrics = {
        "matching_policy": "owasp-testcase-cwe-any-finding-v1",
        "raw_finding_count": raw_finding_count,
        "normalized_candidate_count": len(findings),
        "predicted_unit_count": predicted_units,
        "unmapped_candidate_count": len(findings) - len(mapped_ids),
        "overall": _metrics(overall),
        "per_cwe": {str(cwe): _metrics(counts) for cwe, counts in sorted(per_cwe_counts.items())},
    }
    return matches, metrics


def _empty_counts() -> dict[str, int]:
    return {"tp": 0, "fp": 0, "tn": 0, "fn": 0}


def _outcome(vulnerable: bool, predicted: bool) -> str:
    if vulnerable and predicted:
        return "tp"
    if vulnerable:
        return "fn"
    if predicted:
        return "fp"
    return "tn"


def _ratio(numerator: int, denominator: int) -> float | None:
    return numerator / denominator if denominator else None


def _metrics(counts: dict[str, int]) -> dict[str, int | float | None]:
    tp, fp, tn, fn = counts["tp"], counts["fp"], counts["tn"], counts["fn"]
    precision = _ratio(tp, tp + fp)
    recall = _ratio(tp, tp + fn)
    f1 = None
    if precision is not None and recall is not None and precision + recall:
        f1 = 2 * precision * recall / (precision + recall)
    return {
        **counts,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "fpr": _ratio(fp, fp + tn),
    }
