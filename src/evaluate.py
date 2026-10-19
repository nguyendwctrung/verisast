from collections import defaultdict
import re


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

