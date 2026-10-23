import copy
import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path

from context import read as read_contexts
from ollama_client import OllamaError, generate, metadata, running_model
from sarif import read as read_findings
from verdict import check


class TriageError(RuntimeError):
    pass


def _input_hashes(findings: Path, contexts: Path, prompt: Path, schema: Path, config: Path) -> dict[str, dict[str, str]]:
    return {name: {"path": str(path.resolve()), "sha256": hashlib.sha256(path.read_bytes()).hexdigest()} for name, path in {"findings": findings, "contexts": contexts, "prompt": prompt, "schema": schema, "config": config}.items()}


def _guard_lines(guard: dict[str, object]) -> tuple[list[str], list[str], bool]:
    condition_lines = guard.get("condition_lines")
    action_lines = guard.get("action_lines")
    action_blocks_sink = guard.get("action_blocks_sink")
    if not isinstance(condition_lines, list) or not isinstance(action_lines, list) or not condition_lines or not action_lines:
        raise TriageError("context guard lacks condition or action lines")
    if not all(isinstance(line, str) for line in condition_lines + action_lines):
        raise TriageError("context guard lines must be strings")
    if not isinstance(action_blocks_sink, bool):
        raise TriageError("context guard lacks an action control-flow fact")
    return condition_lines, action_lines, action_blocks_sink


def _guard_contract(guards: dict[str, dict[str, object]]) -> list[dict[str, object]]:
    contract = []
    for guard_id in sorted(guards):
        condition_lines, action_lines, action_blocks_sink = _guard_lines(guards[guard_id])
        contract.append({"guard_id": guard_id, "condition_lines": condition_lines, "action_lines": action_lines, "action_blocks_sink": action_blocks_sink})
    return contract


def _packet_lines(lines: dict[str, str], line_ids: list[str]) -> list[dict[str, str]]:
    packet_lines = []
    for line_id in line_ids:
        snippet = lines.get(line_id)
        if snippet is None:
            raise TriageError(f"context guard line is absent: {line_id}")
        packet_lines.append({"line_id": line_id, "snippet": snippet})
    return packet_lines


def _expressions(condition: list[dict[str, str]]) -> tuple[dict[str, str], dict[str, str]]:
    missing = {"status": "missing", "reason": "not_syntactically_extractable"}
    for item in condition:
        match = re.search(r"\bif\s*\(\s*!?\s*(?P<candidate>.+?)\s*\.startsWith\s*\((?P<base>.+)\)\s*\)\s*\{?\s*$", item["snippet"])
        if match is not None:
            return (
                {"status": "extracted", "value": match.group("candidate").strip(), "line_id": item["line_id"]},
                {"status": "extracted", "value": match.group("base").strip(), "line_id": item["line_id"]},
            )
    return missing, missing.copy()


def _guard_packet(context: dict[str, object], guards: dict[str, dict[str, object]]) -> list[dict[str, object]]:
    source_lines = context.get("lines")
    if not isinstance(source_lines, list):
        raise TriageError("context lacks source lines for guard packet")
    lines = {str(item["id"]): item["text"] for item in source_lines if isinstance(item, dict) and isinstance(item.get("id"), str) and isinstance(item.get("text"), str)}
    packet = []
    for guard_id in sorted(guards):
        guard = guards[guard_id]
        condition_lines, action_lines, action_blocks_sink = _guard_lines(guard)
        kind = guard.get("kind")
        if not isinstance(kind, str):
            raise TriageError("context guard lacks a kind")
        condition = _packet_lines(lines, condition_lines)
        candidate_expression, base_expression = _expressions(condition)
        packet.append({
            "guard_id": guard_id,
            "kind": kind,
            "condition": condition,
            "action": _packet_lines(lines, action_lines),
            "candidate_expression": candidate_expression,
            "base_expression": base_expression,
            "action_blocks_sink": action_blocks_sink,
        })
    return packet


def _schema_for(schema: dict[str, object], guards: dict[str, dict[str, object]]) -> dict[str, object]:
    bound = copy.deepcopy(schema)
    try:
        assessments = bound["properties"]["guard_assessments"]
        assessments["minItems"] = len(guards)
        assessments["maxItems"] = len(guards)
    except (KeyError, TypeError) as error:
        raise TriageError("LLM schema must define guard_assessments") from error
    if not guards:
        return bound
    if not isinstance(assessments.get("items"), dict):
        raise TriageError("LLM schema guard_assessments must define items")
    guard_ids = sorted(guards)
    assessments["items"] = {"allOf": [assessments["items"], {"type": "object", "properties": {"guard_id": {"enum": guard_ids}}, "required": ["guard_id", "condition_blocks_path", "effective", "reason"]}]}
    return bound


def _request(prompt: str, schema: dict[str, object], guards: dict[str, dict[str, object]], guard_packet: list[dict[str, object]], retrieved_knowledge: list[object], inference_options: dict[str, object]) -> dict[str, object]:
    return {"prompt": prompt, "schema": schema, "guard_ids": sorted(guards), "guard_contract": _guard_contract(guards), "guard_packet": guard_packet, "retrieved_knowledge": retrieved_knowledge, "inference_options": inference_options}


def _inference_options(config: dict[str, object]) -> dict[str, object]:
    try:
        temperature = float(config["temperature"])
        num_predict = int(config["max_response_tokens"])
        num_ctx = int(config["context_tokens"])
        keep_alive = config["keep_alive"]
    except (KeyError, TypeError, ValueError) as error:
        raise TriageError(f"invalid LLM inference configuration: {error}") from error
    if num_predict < 1 or num_ctx < 1 or not isinstance(keep_alive, str) or not keep_alive:
        raise TriageError("invalid LLM inference configuration values")
    return {"temperature": temperature, "num_predict": num_predict, "num_ctx": num_ctx, "keep_alive": keep_alive}


def run(findings_path: Path, contexts_path: Path, prompt_path: Path, config_path: Path, output: Path) -> dict[str, object]:
    if output.exists():
        raise TriageError(f"run directory already exists: {output}")
    config = json.loads(config_path.read_text(encoding="utf-8"))
    schema_name = config.get("schema")
    if not isinstance(schema_name, str):
        raise TriageError("LLM schema path is required")
    try:
        schema_path = config_path.parent / schema_name
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise TriageError(f"invalid LLM schema: {error}") from error
    if not isinstance(schema, dict):
        raise TriageError("LLM schema must be an object")
    if config.get("variant") != "B":
        raise TriageError("only Variant B is supported")
    inference_options = _inference_options(config)
    try:
        schema["properties"]["knowledge_used"]["maxItems"] = 0
    except (KeyError, TypeError) as error:
        raise TriageError("LLM schema must define knowledge_used") from error
    template = prompt_path.read_text(encoding="utf-8")
    findings, contexts = read_findings(findings_path), read_contexts(contexts_path)
    try:
        model = metadata(str(config["endpoint"]), str(config["model"]), int(config["timeout_seconds"]))
    except OllamaError as error:
        model = {"requested_model": str(config["model"]), "metadata_error": str(error)}
    output.mkdir(parents=True)
    raw_dir = output / "raw"
    raw_dir.mkdir()
    requests_dir = output / "requests"
    requests_dir.mkdir()
    rows = []
    for finding in findings:
        candidate_id = str(finding["id"])
        context = contexts.get(candidate_id)
        if context is None:
            rows.append({"candidate_id": candidate_id, "effective_verdict": "UNCERTAIN", "error": "missing_context"})
            continue
        guards = {str(guard["id"]): guard for guard in context.get("guards", []) if isinstance(guard, dict) and isinstance(guard.get("id"), str)}
        guard_packet = _guard_packet(context, guards)
        prompt = template.replace("{guard_packet}", json.dumps(guard_packet, sort_keys=True)).replace("{finding}", json.dumps(finding, sort_keys=True)).replace("{context}", json.dumps(context, sort_keys=True)).replace("{required_guard_ids}", json.dumps(sorted(guards))).replace("{retrieved_knowledge}", "[]")
        candidate_schema = _schema_for(schema, guards)
        request = _request(prompt, candidate_schema, guards, guard_packet, [], inference_options)
        (requests_dir / f"{candidate_id}.json").write_text(json.dumps(request, indent=2), encoding="utf-8")
        try:
            decoded, raw = generate(
                str(config["endpoint"]), str(config["model"]), prompt,
                int(config["timeout_seconds"]), int(inference_options["num_predict"]),
                candidate_schema, float(inference_options["temperature"]),
                int(inference_options["num_ctx"]), str(inference_options["keep_alive"]),
            )
            (raw_dir / f"{candidate_id}.json").write_text(raw, encoding="utf-8")
            lines = {str(line["id"]) for line in context["lines"] if isinstance(line, dict) and isinstance(line.get("id"), str)}
            verdict = check(str(decoded["response"]), lines, set(), guards)
            row = {"candidate_id": candidate_id, "effective_verdict": verdict.effective, "reported_verdict": verdict.reported, "error": verdict.error}
            if verdict.payload is not None and isinstance(verdict.payload.get("context_bound_evidence"), list):
                row["context_bound_evidence"] = verdict.payload["context_bound_evidence"]
            rows.append(row)
        except OllamaError as error:
            rows.append({"candidate_id": candidate_id, "effective_verdict": "UNCERTAIN", "error": f"transport:{error}"})
    (output / "verdicts.jsonl").write_text("".join(json.dumps(row, sort_keys=True) + "\n" for row in rows), encoding="utf-8")
    try:
        model["runtime"] = running_model(str(config["endpoint"]), str(config["model"]), int(config["timeout_seconds"]))
    except OllamaError as error:
        model["runtime_error"] = str(error)
    manifest = {"schema_version": 1, "status": "completed", "created_at": datetime.now(timezone.utc).isoformat(), "variant": config["variant"], "config": config, "inference_options": inference_options, "model": model, "inputs": _input_hashes(findings_path, contexts_path, prompt_path, schema_path, config_path), "candidate_count": len(findings), "verdict_counts": {name: sum(row["effective_verdict"] == name for row in rows) for name in ("TRUE_POSITIVE", "FALSE_POSITIVE", "UNCERTAIN")}}
    (output / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return manifest

