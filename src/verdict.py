import json
from dataclasses import dataclass


@dataclass(frozen=True)
class Verdict:
    effective: str
    reported: str | None
    error: str | None
    payload: dict[str, object] | None


def check(text: str, lines: set[str], knowledge: set[str]) -> Verdict:
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        return Verdict("UNCERTAIN", None, "invalid_json", None)
    if not isinstance(payload, dict) or payload.get("schema_version") != "verdict-v2":
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
    return Verdict(str(verdict), str(verdict), None, payload)
