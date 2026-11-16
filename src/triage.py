import copy
import hashlib
import json
import re
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

from context import read as read_contexts
from neutral_interface import bind_knowledge_schema, render_prompt
from ollama_client import OllamaError, generate, metadata, running_model
from paired_manifest import PairedManifestError
from paired_manifest import validate as validate_paired_manifest
from sarif import read as read_findings
from triage_retrieval import build_provider
from variant_contract import retrieval_failure_row
from verdict import check


class TriageError(RuntimeError):
    pass


def validate_paired_config(config_path: Path) -> tuple[dict[str, object], dict[str, object], Path]:
    """Load the neutral interface configuration and required provenance."""
    try:
        config = json.loads(config_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise TriageError(f"invalid paired triage configuration: {error}") from error
    if not isinstance(config, dict) or config.get("interface") != "neutral-triage":
        raise TriageError("neutral triage configuration is required")
    string_fields = ("schema", "neutral_contract", "endpoint", "model", "model_digest", "keep_alive")
    integer_fields = ("timeout_seconds", "max_response_tokens", "context_tokens")
    missing = [name for name in string_fields if not isinstance(config.get(name), str) or not config[name]]
    missing.extend(name for name in integer_fields if type(config.get(name)) is not int or config[name] < 1)
    if missing:
        raise TriageError(f"paired triage configuration is missing or invalid: {', '.join(sorted(set(missing)))}")
    schema_path = config_path.parent / str(config["schema"])
    neutral_path = config_path.parent / str(config["neutral_contract"])
    try:
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        neutral_contract = json.loads(neutral_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise TriageError(f"invalid paired triage provenance input: {error}") from error
    if not isinstance(schema, dict):
        raise TriageError("LLM schema must be an object")
    if not isinstance(neutral_contract, dict) or neutral_contract.get("contract_id") != "neutral-triage-interface":
        raise TriageError("neutral triage contract is invalid")
    return config, schema, neutral_path


def _neutral_candidate_request(
    template: str,
    schema: dict[str, object],
    finding: dict[str, object],
    context: dict[str, object],
    guards: dict[str, dict[str, object]],
    guard_packet: list[dict[str, object]],
    inference_options: dict[str, object],
    retrieved_knowledge: list[object],
) -> dict[str, object]:
    """Build one paired B/C request; knowledge is the only variant input."""
    prompt = render_prompt(
        template,
        guard_packet=json.dumps(guard_packet, sort_keys=True),
        finding=json.dumps(finding, sort_keys=True),
        context=json.dumps(context, sort_keys=True),
        required_guard_ids=json.dumps(sorted(guards)),
        retrieved_knowledge=retrieved_knowledge,
    )
    bound_schema = _schema_for(bind_knowledge_schema(schema, 3), guards)
    return _request(prompt, bound_schema, guards, guard_packet, retrieved_knowledge, inference_options)


def _retrieval_failure(candidate_id: str, message: str) -> dict[str, object]:
    """Return the mandatory C failure result without invoking the LLM."""
    return retrieval_failure_row(candidate_id, message)


def run_paired(
    findings_path: Path,
    contexts_path: Path,
    prompt_path: Path,
    config_path: Path,
    output: Path,
    variant: str,
    retrieval_provider: object = None,
    retrieval_contract_path: Path | None = None,
    paired_manifest_path: Path | None = None,
) -> dict[str, object]:
    """Prepare one neutral paired B/C run and preserve retrieval failures."""
    if output.exists():
        raise TriageError(f"run directory already exists: {output}")
    if variant not in {"B", "C"}:
        raise TriageError("variant must be B or C")
    if paired_manifest_path is None:
        raise TriageError("paired manifest is required")
    config, schema, neutral_path = validate_paired_config(config_path)
    try:
        paired_manifest = validate_paired_manifest(
            paired_manifest_path, findings_path, contexts_path, prompt_path, config_path,
        )
    except PairedManifestError as error:
        raise TriageError(str(error)) from error
    try:
        model = metadata(str(config["endpoint"]), str(config["model"]), int(config["timeout_seconds"]))
    except OllamaError as error:
        raise TriageError(f"unable to verify local model provenance: {error}") from error
    if model.get("model_digest") != config["model_digest"]:
        raise TriageError("local model digest does not match configuration")
    if variant == "C" and retrieval_provider is None:
        if retrieval_contract_path is None:
            raise TriageError("C requires a retrieval contract path")
        retrieval_provider = build_provider(retrieval_contract_path)
    template = prompt_path.read_text(encoding="utf-8")
    findings, contexts = read_findings(findings_path), read_contexts(contexts_path)
    output.mkdir(parents=True)
    requests_dir = output / "requests"
    requests_dir.mkdir()
    raw_dir = output / "raw"
    raw_dir.mkdir()
    bundles_dir = output / "retrieval-bundles"
    if variant == "C":
        bundles_dir.mkdir()
    rows = []
    retrieval_rows = []
    retrieval_errors = []
    for finding in findings:
        candidate_id = str(finding["id"])
        context = contexts.get(candidate_id)
        if context is None:
            rows.append({"candidate_id": candidate_id, "effective_verdict": "UNCERTAIN", "error": "missing_context"})
            continue
        knowledge = []
        if variant == "C":
            try:
                if not callable(retrieval_provider):
                    raise TriageError("C requires a retrieval provider")
                bundle = retrieval_provider(finding, context)
                if not isinstance(bundle, dict) or not isinstance(bundle.get("knowledge_items"), list) or not bundle["knowledge_items"]:
                    raise TriageError("C retrieval provider returned an invalid bundle")
                knowledge = bundle["knowledge_items"]
                retrieval_rows.append({"candidate_id": candidate_id, "bundle": bundle})
                (bundles_dir / f"{candidate_id}.json").write_text(json.dumps(bundle, indent=2, sort_keys=True), encoding="utf-8")
            except Exception as error:
                row = _retrieval_failure(candidate_id, str(error))
                rows.append(row)
                retrieval_errors.append(row)
                continue
        guards = {str(item["id"]): item for item in context.get("guards", []) if isinstance(item, dict) and isinstance(item.get("id"), str)}
        request = _neutral_candidate_request(template, schema, finding, context, guards, _guard_packet(context, guards), {"temperature": 0}, knowledge)
        (requests_dir / f"{candidate_id}.json").write_text(json.dumps(request, indent=2), encoding="utf-8")
        try:
            decoded, raw = generate(
                str(config["endpoint"]), str(config["model"]), str(request["prompt"]),
                int(config["timeout_seconds"]), int(config["max_response_tokens"]),
                request["schema"], 0.0, int(config["context_tokens"]), str(config["keep_alive"]),
            )
            (raw_dir / f"{candidate_id}.json").write_text(raw, encoding="utf-8")
            line_ids = {str(line["id"]) for line in context["lines"] if isinstance(line, dict) and isinstance(line.get("id"), str)}
            knowledge_ids = {str(item["knowledge_id"]) for item in knowledge if isinstance(item, dict) and isinstance(item.get("knowledge_id"), str)}
            verdict = check(str(decoded["response"]), line_ids, knowledge_ids, guards)
            rows.append({"candidate_id": candidate_id, "effective_verdict": verdict.effective, "reported_verdict": verdict.reported, "error": verdict.error})
        except OllamaError as error:
            rows.append({"candidate_id": candidate_id, "effective_verdict": "UNCERTAIN", "error": f"transport:{error}"})
    (output / "verdicts.jsonl").write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
    if variant == "C":
        (output / "retrieval-records.jsonl").write_text("".join(json.dumps(row) + "\n" for row in retrieval_rows), encoding="utf-8")
        (output / "retrieval-errors.jsonl").write_text("".join(json.dumps(row) + "\n" for row in retrieval_errors), encoding="utf-8")
    inputs = _input_hashes(findings_path, contexts_path, prompt_path, config_path.parent / str(config["schema"]), config_path)
    contracts = {"neutral": {"path": str(neutral_path), "sha256": hashlib.sha256(neutral_path.read_bytes()).hexdigest()}}
    if retrieval_contract_path is not None:
        contracts["retrieval"] = {"path": str(retrieval_contract_path), "sha256": hashlib.sha256(retrieval_contract_path.read_bytes()).hexdigest()}
    manifest = {"status": "completed", "variant": variant, "candidate_count": len(findings), "config": config, "model": model, "inputs": inputs, "contracts": contracts, "paired_manifest": {"path": str(paired_manifest_path), "sha256": hashlib.sha256(paired_manifest_path.read_bytes()).hexdigest(), "source_revision": paired_manifest["source_revision"]}, "raw_responses": "raw", "retrieval_bundle_snapshots": "retrieval-bundles" if variant == "C" else None}
    (output / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return manifest


def _progress_event(event: str, started_at: str, elapsed_seconds: float, candidate_index: int, candidate_count: int, candidate_id: str | None = None, row: dict[str, object] | None = None, candidate_elapsed_seconds: float | None = None) -> dict[str, object]:
    elapsed_seconds = round(elapsed_seconds, 3)
    progress = {
        "schema_version": 1,
        "event": event,
        "timestamp": (datetime.fromisoformat(started_at) + timedelta(seconds=elapsed_seconds)).isoformat(),
        "started_at": started_at,
        "elapsed_seconds": elapsed_seconds,
        "candidate_index": candidate_index,
        "candidate_count": candidate_count,
        "completion_percent": round(100 * candidate_index / candidate_count, 2) if candidate_count else (0.0 if event == "run_started" else 100.0),
        "eta_seconds": round(elapsed_seconds * (candidate_count - candidate_index) / candidate_index, 3) if candidate_index else None,
    }
    if candidate_id is not None:
        progress["candidate_id"] = candidate_id
    if candidate_elapsed_seconds is not None:
        progress["candidate_elapsed_seconds"] = round(candidate_elapsed_seconds, 3)
    if row is not None:
        progress["effective_verdict"] = row.get("effective_verdict")
        progress["error"] = row.get("error")
    return progress


def _progress_block(progress: dict[str, object]) -> str:
    eta = progress["eta_seconds"]
    eta_text = "unknown" if eta is None else f"{eta}s"
    return "\n".join([
        "====================",
        f"{progress['candidate_index']}/{progress['candidate_count']}",
        f"elapsed={progress['elapsed_seconds']}s",
        f"eta={eta_text}",
        f"candidate={progress.get('candidate_id')}",
        f"verdict={progress.get('effective_verdict')}",
    ])


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
    progress_path = output / "progress.jsonl"
    rows = []
    started_at = datetime.now(timezone.utc).isoformat()
    started = time.monotonic()
    candidate_count = len(findings)
    print(f"CODEQL_FINDINGS candidates={candidate_count}")
    with progress_path.open("w", encoding="utf-8") as progress_file:
        start_event = _progress_event("run_started", started_at, 0, 0, candidate_count)
        start_event.update({"run_id": output.name, "variant": config["variant"]})
        progress_file.write(json.dumps(start_event, sort_keys=True) + "\n")
        progress_file.flush()
        for candidate_index, finding in enumerate(findings, start=1):
            candidate_started = time.monotonic()
            candidate_id = str(finding["id"])
            context = contexts.get(candidate_id)
            if context is None:
                row = {"candidate_id": candidate_id, "effective_verdict": "UNCERTAIN", "error": "missing_context"}
            else:
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
                except OllamaError as error:
                    row = {"candidate_id": candidate_id, "effective_verdict": "UNCERTAIN", "error": f"transport:{error}"}
            rows.append(row)
            progress = _progress_event(
                "candidate_completed", started_at, time.monotonic() - started,
                candidate_index, candidate_count, candidate_id, row,
                time.monotonic() - candidate_started,
            )
            progress.update({"run_id": output.name, "variant": config["variant"]})
            progress_file.write(json.dumps(progress, sort_keys=True) + "\n")
            progress_file.flush()
            print(_progress_block(progress))
        complete_event = _progress_event(
            "run_completed", started_at, time.monotonic() - started,
            candidate_count, candidate_count,
        )
        complete_event.update({"run_id": output.name, "variant": config["variant"]})
        progress_file.write(json.dumps(complete_event, sort_keys=True) + "\n")
        progress_file.flush()
    (output / "verdicts.jsonl").write_text("".join(json.dumps(row, sort_keys=True) + "\n" for row in rows), encoding="utf-8")
    try:
        model["runtime"] = running_model(str(config["endpoint"]), str(config["model"]), int(config["timeout_seconds"]))
    except OllamaError as error:
        model["runtime_error"] = str(error)
    manifest = {"schema_version": 1, "status": "completed", "created_at": datetime.now(timezone.utc).isoformat(), "variant": config["variant"], "config": config, "inference_options": inference_options, "model": model, "inputs": _input_hashes(findings_path, contexts_path, prompt_path, schema_path, config_path), "candidate_count": candidate_count, "progress": {"path": "progress.jsonl", "schema_version": 1, "event_count": candidate_count + 2}, "verdict_counts": {name: sum(row["effective_verdict"] == name for row in rows) for name in ("TRUE_POSITIVE", "FALSE_POSITIVE", "UNCERTAIN")}}
    (output / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return manifest

