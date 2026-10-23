import json
from dataclasses import dataclass


@dataclass(frozen=True)
class Verdict:
    effective: str
    reported: str | None
    error: str | None
    payload: dict[str, object] | None


def check(text: str, lines: set[str], knowledge: set[str], guards: dict[str, dict[str, object]] | None = None) -> Verdict:
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        return Verdict("UNCERTAIN", None, "invalid_json", None)
    
    if not isinstance(payload, dict) or payload.get("schema_version") != "verdict-v6":
        return Verdict("UNCERTAIN", None, "invalid_schema", payload if isinstance(payload, dict) else None)
    
    verdict = payload.get("verdict")

    if verdict not in {"TRUE_POSITIVE", "FALSE_POSITIVE", "UNCERTAIN"}:
        return Verdict("UNCERTAIN", None, "invalid_verdict", payload)
    
    if verdict != "UNCERTAIN" and payload.get("missing_evidence"):
        return Verdict("UNCERTAIN", str(verdict), "essential_unknown", payload)
    
    citations = []

    for field in ("source", "sink", "dataflow"):
        value = payload.get(field)

        if not isinstance(value, dict) or not isinstance(value.get("evidence_lines"), list):
            return Verdict("UNCERTAIN", str(verdict), f"invalid_{field}", payload)
        
        citations.extend(value["evidence_lines"])

    barriers = payload.get("barriers")

    if not isinstance(barriers, list):
        return Verdict("UNCERTAIN", str(verdict), "invalid_barriers", payload)
    
    effective = False

    for barrier in barriers:
        if not isinstance(barrier, dict) or barrier.get("kind") not in {"PATH_PREFIX_CHECK", "OTHER"} or not isinstance(barrier.get("effective"), bool):
            return Verdict("UNCERTAIN", str(verdict), "invalid_barrier", payload)
        
        if not isinstance(barrier.get("evidence_lines"), list) or not isinstance(barrier.get("reason"), str) or not barrier["reason"].strip():
            return Verdict("UNCERTAIN", str(verdict), "invalid_barrier", payload)
        
        if barrier["kind"] == "PATH_PREFIX_CHECK" and len(set(barrier["evidence_lines"])) < 2:
            return Verdict("UNCERTAIN", str(verdict), "incomplete_path_prefix_check", payload)
        
        citations.extend(barrier["evidence_lines"])
        effective = effective or barrier["effective"]

    expected_guards = guards or {}
    assessments = payload.get("guard_assessments")

    if not isinstance(assessments, list):
        return Verdict("UNCERTAIN", str(verdict), "invalid_guard_assessments", payload)
    
    assessed = set()
    context_bound_evidence = []

    for assessment in assessments:
        if not isinstance(assessment, dict):
            return Verdict("UNCERTAIN", str(verdict), "invalid_guard_assessment", payload)
        
        if set(assessment) != {"guard_id", "condition_blocks_path", "effective", "reason"}:
            return Verdict("UNCERTAIN", str(verdict), "invalid_guard_assessment", payload)
        
        guard_id = assessment.get("guard_id")

        if not isinstance(guard_id, str) or guard_id not in expected_guards:
            return Verdict("UNCERTAIN", str(verdict), "unexpected_guard_assessment", payload)
        
        if guard_id in assessed:
            return Verdict("UNCERTAIN", str(verdict), "duplicate_guard_assessment", payload)
        
        reason = assessment.get("reason")
        condition_blocks_path = assessment.get("condition_blocks_path")

        if not isinstance(condition_blocks_path, bool):
            return Verdict("UNCERTAIN", str(verdict), "invalid_guard_assessment", payload)
        
        if not isinstance(assessment.get("effective"), bool) or not isinstance(reason, str) or not reason.strip():
            return Verdict("UNCERTAIN", str(verdict), "invalid_guard_assessment", payload)
        
        guard = expected_guards[guard_id]
        condition_lines = guard.get("condition_lines")
        action_lines = guard.get("action_lines")
        action_blocks_sink = guard.get("action_blocks_sink")

        if not isinstance(condition_lines, list) or not isinstance(action_lines, list) or not isinstance(action_blocks_sink, bool):
            return Verdict("UNCERTAIN", str(verdict), "invalid_context_guard", payload)
        
        if not all(isinstance(item, str) for item in condition_lines + action_lines):
            return Verdict("UNCERTAIN", str(verdict), "invalid_context_guard", payload)
        
        if assessment["effective"] != (condition_blocks_path and action_blocks_sink):
            return Verdict("UNCERTAIN", str(verdict), "inconsistent_guard_assessment", payload)
        
        assessed.add(guard_id)
        context_bound_evidence.append({"guard_id": guard_id, "citation_source": "context_contract", "condition_lines": condition_lines, "action_lines": action_lines, "action_blocks_sink": action_blocks_sink})
        effective = effective or assessment["effective"]

    if set(expected_guards) != assessed:
        return Verdict("UNCERTAIN", str(verdict), "missing_guard_assessment", payload)
    
    if not citations or any(not isinstance(item, str) or item not in lines for item in citations):
        return Verdict("UNCERTAIN", str(verdict), "invalid_citation", payload)
    
    if verdict == "FALSE_POSITIVE" and not effective:
        return Verdict("UNCERTAIN", str(verdict), "missing_effective_barrier", payload)
    
    if verdict == "TRUE_POSITIVE" and effective:
        return Verdict("UNCERTAIN", str(verdict), "contradictory_effective_barrier", payload)
    
    used = payload.get("knowledge_used")

    if not isinstance(used, list) or any(not isinstance(item, str) or item not in knowledge for item in used):
        return Verdict("UNCERTAIN", str(verdict), "invalid_knowledge", payload)
    
    if not isinstance(payload.get("reason"), str) or not payload["reason"].strip():
        return Verdict("UNCERTAIN", str(verdict), "missing_reason", payload)
    
    payload["context_bound_evidence"] = context_bound_evidence
    
    return Verdict(str(verdict), str(verdict), None, payload)
