from collections import defaultdict
import re


class EvaluationError(ValueError):
    pass


def score(units: list[dict[str, object]], findings: list[dict[str, object]]) -> dict[str, object]:
    predicted: dict[tuple[str, int], set[str]] = defaultdict(set)
    for finding in findings:
        test_id = finding.get("test_id")
        if not isinstance(test_id, str):
            path = finding.get("path")
            match = re.search(r"BenchmarkTest\d{5}", path) if isinstance(path, str) else None
            test_id = match.group(0) if match else None
        cwes = finding.get("cwes")
        if isinstance(test_id, str) and isinstance(cwes, list):
            for cwe in cwes:
                if isinstance(cwe, int):
                    predicted[(test_id, cwe)].add(str(finding["id"]))
    counts = {"tp": 0, "fp": 0, "tn": 0, "fn": 0}
    matches = []
    for unit in units:
        key = (unit["test_id"], unit["cwe"])
        found = sorted(predicted.get(key, set()))
        positive = bool(unit["vulnerable"])
        outcome = "tp" if positive and found else "fn" if positive else "fp" if found else "tn"
        counts[outcome] += 1
        matches.append({**unit, "candidate_ids": found, "outcome": outcome.upper()})
    tp, fp, tn, fn = (counts[name] for name in ("tp", "fp", "tn", "fn"))
    precision = tp / (tp + fp) if tp + fp else None
    recall = tp / (tp + fn) if tp + fn else None
    return {"matching_policy": "owasp-testcase-cwe-any-finding-v2", "matches": matches, "overall": {**counts, "precision": precision, "recall": recall, "f1": 2 * precision * recall / (precision + recall) if precision is not None and recall is not None and precision + recall else None, "fpr": fp / (fp + tn) if fp + tn else None}}


def score_cwe_bench(
    units: list[dict[str, object]],
    findings: list[dict[str, object]],
    require_pairs: bool = True,
) -> dict[str, object]:
    """Score target-CVE revision units using frozen CWE and path scope."""
    normalized_units = [_validate_cwe_bench_unit(unit) for unit in units]
    by_target: dict[str, list[dict[str, object]]] = defaultdict(list)
    for finding in findings:
        target_id = finding.get("target_id")
        if isinstance(target_id, str):
            by_target[target_id].append(finding)
    matches = []
    counts = {"tp": 0, "fp": 0, "tn": 0, "fn": 0}
    pair_outcomes: dict[str, dict[str, bool]] = defaultdict(dict)
    for unit in normalized_units:
        matched_ids = sorted(
            str(finding["id"])
            for finding in by_target.get(str(unit["target_id"]), [])
            if _finding_matches_cwe_bench_unit(finding, unit)
        )
        positive = unit["revision_role"] == "buggy"
        outcome = "tp" if positive and matched_ids else "fn" if positive else "fp" if matched_ids else "tn"
        counts[outcome] += 1
        matches.append({**unit, "candidate_ids": matched_ids, "outcome": outcome.upper()})
        pair_outcomes[str(unit["pair_id"])][str(unit["revision_role"])] = outcome in {"tp", "tn"}
    if require_pairs and any(set(roles) != {"buggy", "fixed"} for roles in pair_outcomes.values()):
        raise EvaluationError("each CWE-Bench pair must contain one vulnerable/fixed pair")
    complete_pairs = [roles for roles in pair_outcomes.values() if set(roles) == {"buggy", "fixed"}]
    pair_accuracy = (
        sum(all(roles.values()) for roles in complete_pairs) / len(complete_pairs)
        if complete_pairs else None
    )
    return {
        "matching_policy": "cwe-bench-target-cve-revision-cwe-path-v1",
        "matches": matches,
        "overall": _metrics(counts),
        "pair_count": len(complete_pairs),
        "pair_accuracy": pair_accuracy,
    }


def _validate_cwe_bench_unit(unit: dict[str, object]) -> dict[str, object]:
    required_strings = ("target_id", "cve_id", "revision_role")
    if not all(isinstance(unit.get(field), str) and unit[field] for field in required_strings):
        raise EvaluationError("CWE-Bench unit lacks target_id, cve_id, or revision_role")
    if unit["revision_role"] not in {"buggy", "fixed"}:
        raise EvaluationError("CWE-Bench revision_role must be buggy or fixed")
    if not isinstance(unit.get("cwe"), int):
        raise EvaluationError("CWE-Bench unit cwe must be an integer")
    path_prefixes = unit.get("path_prefixes")
    if not isinstance(path_prefixes, list) or not path_prefixes or not all(
        isinstance(prefix, str) and prefix for prefix in path_prefixes
    ):
        raise EvaluationError("CWE-Bench path_prefixes must be a non-empty string list")
    ranges = unit.get("symbol_ranges")
    if ranges is not None and (not isinstance(ranges, list) or not ranges or any(
        not isinstance(item, dict) or not isinstance(item.get("path"), str)
        or type(item.get("start")) is not int or type(item.get("end")) is not int
        or item["start"] < 1 or item["end"] < item["start"] for item in ranges
    )):
        raise EvaluationError("CWE-Bench symbol_ranges must contain valid path/start/end entries")
    return {**unit, "pair_id": unit.get("pair_id", unit["cve_id"])}


def _finding_matches_cwe_bench_unit(finding: dict[str, object], unit: dict[str, object]) -> bool:
    cwes = finding.get("cwes")
    path = finding.get("path")
    flow = finding.get("flow")
    locations = [(path, finding.get("start"))]
    if isinstance(flow, list):
        locations.extend((step.get("path"), step.get("line")) for step in flow if isinstance(step, dict))
    path_match = (
        isinstance(cwes, list)
        and unit["cwe"] in cwes
        and any(isinstance(location_path, str) and
                any(location_path.startswith(prefix) for prefix in unit["path_prefixes"])
                for location_path, _ in locations)
    )
    if not path_match:
        return False
    ranges = unit.get("symbol_ranges")
    if ranges is None:
        return True
    return any(location_path == item["path"] and type(line) is int and item["start"] <= line <= item["end"]
               for location_path, line in locations for item in ranges)


def _metrics(counts: dict[str, int]) -> dict[str, object]:
    tp, fp, tn, fn = (counts[name] for name in ("tp", "fp", "tn", "fn"))
    precision = tp / (tp + fp) if tp + fp else None
    recall = tp / (tp + fn) if tp + fn else None
    return {
        **counts,
        "precision": precision,
        "recall": recall,
        "f1": 2 * precision * recall / (precision + recall)
        if precision is not None and recall is not None and precision + recall else None,
        "fpr": fp / (fp + tn) if fp + tn else None,
    }

