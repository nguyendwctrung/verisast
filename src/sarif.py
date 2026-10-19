import hashlib
import json
import re
from pathlib import Path


class SarifError(ValueError):
    pass


def normalize(path: Path, source_revision: str, pack: str, suite: str) -> list[dict[str, object]]:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise SarifError(f"invalid SARIF: {error}") from error
    runs = document.get("runs")
    if not isinstance(runs, list) or len(runs) != 1:
        raise SarifError("SARIF must contain exactly one run")
    run = runs[0]
    if not isinstance(run, dict):
        raise SarifError("SARIF run must be an object")
    rules = _rules(run)
    results = run.get("results")
    if not isinstance(results, list):
        raise SarifError("SARIF results must be a list")
    findings = []
    for index, result in enumerate(results):
        if not isinstance(result, dict):
            continue
        rule_id = result.get("ruleId")
        location = _location(result)
        if not isinstance(rule_id, str) or location is None:
            continue
        cwes = _cwes(rules.get(rule_id, {}), result)
        identity = f"{rule_id}|{location['path']}|{location['start']}|{location['end']}|{','.join(map(str, cwes))}"
        findings.append({
            "id": hashlib.sha256(identity.encode("utf-8")).hexdigest(),
            "scanner": "codeql",
            "source_revision": source_revision,
            "query_pack": pack,
            "query_suite": suite,
            "rule_id": rule_id,
            "cwes": cwes,
            "message": _message(result),
            "severity": result.get("level", "warning"),
            "path": location["path"],
            "start": location["start"],
            "end": location["end"],
            "flow": _flow(result),
            "raw_index": index,
            "test_id": _test_id(location["path"]),
        })
    return findings


def write(path: Path, findings: list[dict[str, object]]) -> None:
    if path.exists():
        raise SarifError(f"output already exists: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(item, sort_keys=True) + "\n" for item in findings), encoding="utf-8")


def read(path: Path) -> list[dict[str, object]]:
    try:
        return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]
    except (OSError, json.JSONDecodeError) as error:
        raise SarifError(f"invalid finding JSONL: {error}") from error


def _rules(run: dict[str, object]) -> dict[str, dict[str, object]]:
    tool = run.get("tool")
    if not isinstance(tool, dict) or not isinstance(tool.get("driver"), dict):
        return {}
    rules = tool["driver"].get("rules")
    if not isinstance(rules, list):
        return {}
    return {item["id"]: item for item in rules if isinstance(item, dict) and isinstance(item.get("id"), str)}


def _location(result: dict[str, object]) -> dict[str, object] | None:
    locations = result.get("locations")
    if not isinstance(locations, list) or not locations or not isinstance(locations[0], dict):
        return None
    physical = locations[0].get("physicalLocation")
    if not isinstance(physical, dict) or not isinstance(physical.get("artifactLocation"), dict):
        return None
    uri = physical["artifactLocation"].get("uri")
    region = physical.get("region", {})
    if not isinstance(uri, str) or not isinstance(region, dict) or not isinstance(region.get("startLine"), int):
        return None
    return {"path": uri.replace("\\", "/"), "start": region["startLine"], "end": region.get("endLine", region["startLine"])}


def _flow(result: dict[str, object]) -> list[dict[str, object]]:
    flow = []
    for code_flow in result.get("codeFlows", []) if isinstance(result.get("codeFlows"), list) else []:
        if not isinstance(code_flow, dict):
            continue
        for thread in code_flow.get("threadFlows", []) if isinstance(code_flow.get("threadFlows"), list) else []:
            for step in thread.get("locations", []) if isinstance(thread, dict) and isinstance(thread.get("locations"), list) else []:
                if not isinstance(step, dict) or not isinstance(step.get("location"), dict):
                    continue
                found = _location({"locations": [step["location"]]})
                if found:
                    flow.append({"path": found["path"], "line": found["start"], "message": _message(step.get("location", {}))})
    return flow


def _cwes(rule: dict[str, object], result: dict[str, object]) -> list[int]:
    text = json.dumps([rule.get("properties", {}), result.get("properties", {})])
    return sorted({int(value) for value in re.findall(r"cwe[-_/ ]?(\d+)", text, re.IGNORECASE)})


def _message(value: object) -> str:
    if isinstance(value, dict):
        message = value.get("message")
        if isinstance(message, dict) and isinstance(message.get("text"), str):
            return message["text"]
    return ""


def _test_id(path: str) -> str | None:
    match = re.search(r"BenchmarkTest\d{5}", path)
    return match.group(0) if match else None

