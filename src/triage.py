import json
from datetime import datetime, timezone
from pathlib import Path

from context import read as read_contexts
from ollama_client import OllamaError, generate
from sarif import read as read_findings
from verdict import check


class TriageError(RuntimeError):
    pass


def run(findings_path: Path, contexts_path: Path, prompt_path: Path, config_path: Path, output: Path) -> dict[str, object]:
    if output.exists():
        raise TriageError(f"run directory already exists: {output}")
    config = json.loads(config_path.read_text(encoding="utf-8"))
    schema_name = config.get("schema")
    if not isinstance(schema_name, str):
        raise TriageError("LLM schema path is required")
    try:
        schema = json.loads((config_path.parent / schema_name).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise TriageError(f"invalid LLM schema: {error}") from error
    if not isinstance(schema, dict):
        raise TriageError("LLM schema must be an object")
    if config.get("variant") != "B":
        raise TriageError("only Variant B is supported")
    try:
        schema["properties"]["knowledge_used"]["maxItems"] = 0
    except (KeyError, TypeError) as error:
        raise TriageError("LLM schema must define knowledge_used") from error
    template = prompt_path.read_text(encoding="utf-8")
    findings, contexts = read_findings(findings_path), read_contexts(contexts_path)
    output.mkdir(parents=True)
    raw_dir = output / "raw"
    raw_dir.mkdir()
    rows = []
    for finding in findings:
        candidate_id = str(finding["id"])
        context = contexts.get(candidate_id)
        if context is None:
            rows.append({"candidate_id": candidate_id, "effective_verdict": "UNCERTAIN", "error": "missing_context"})
            continue
        prompt = template.replace("{finding}", json.dumps(finding, sort_keys=True)).replace("{context}", json.dumps(context, sort_keys=True)).replace("{retrieved_knowledge}", "[]")
        try:
            decoded, raw = generate(str(config["endpoint"]), str(config["model"]), prompt, int(config["timeout_seconds"]), int(config["max_response_tokens"]), schema)
            (raw_dir / f"{candidate_id}.json").write_text(raw, encoding="utf-8")
            lines = {str(line["id"]) for line in context["lines"] if isinstance(line, dict) and isinstance(line.get("id"), str)}
            verdict = check(str(decoded["response"]), lines, set())
            rows.append({"candidate_id": candidate_id, "effective_verdict": verdict.effective, "reported_verdict": verdict.reported, "error": verdict.error})
        except OllamaError as error:
            rows.append({"candidate_id": candidate_id, "effective_verdict": "UNCERTAIN", "error": f"transport:{error}"})
    (output / "verdicts.jsonl").write_text("".join(json.dumps(row, sort_keys=True) + "\n" for row in rows), encoding="utf-8")
    manifest = {"schema_version": 1, "status": "completed", "created_at": datetime.now(timezone.utc).isoformat(), "variant": config["variant"], "config": config, "candidate_count": len(findings), "verdict_counts": {name: sum(row["effective_verdict"] == name for row in rows) for name in ("TRUE_POSITIVE", "FALSE_POSITIVE", "UNCERTAIN")}}
    (output / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return manifest

