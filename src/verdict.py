import json
from dataclasses import dataclass
ALLOWED_VERDICTS = {"KEEP", "SUPPRESS_CANDIDATE", "UNCERTAIN"}
ALLOWED_REASONS = {
    "EFFECTIVE_SANITIZER",
    "CONTROLLED_SOURCE",
    "INFEASIBLE_PATH",
    "UNREACHABLE_CODE",
    "RULE_MISMATCH",
}


@dataclass(frozen=True)
class VerdictResult:
    effective_verdict: str
    model_verdict: str | None
    reason_code: str | None
    error: str | None
    payload: dict[str, object] | None


def validate_verdict(
    response_text: str,
    allowed_lines: set[int],
) -> VerdictResult:
    try:
        payload = json.loads(response_text)
    except json.JSONDecodeError:
        return VerdictResult("UNCERTAIN", None, None, "invalid_json", None)

    if not isinstance(payload, dict):
        return VerdictResult("UNCERTAIN", None, None, "response_not_object", None)

    if payload.get("schema_version") != "llm-verdict-v1":
        return VerdictResult("UNCERTAIN", None, None, "invalid_schema_version", payload)

    verdict = payload.get("verdict")
    if verdict not in ALLOWED_VERDICTS:
        return VerdictResult("UNCERTAIN", None, None, "invalid_verdict", payload)

    if verdict != "SUPPRESS_CANDIDATE":
        return VerdictResult(str(verdict), str(verdict), None, None, payload)

    reason_code = payload.get("reason_code")
    citations = payload.get("source_citations")
    unknowns = payload.get("essential_unknowns")
    explanation = payload.get("explanation")

    if reason_code not in ALLOWED_REASONS:
        return VerdictResult("UNCERTAIN", str(verdict), None, "invalid_reason", payload)
    if not isinstance(citations, list) or not citations:
        return VerdictResult("UNCERTAIN", str(verdict), str(reason_code), "missing_citations", payload)
    if not isinstance(unknowns, list) or unknowns:
        return VerdictResult("UNCERTAIN", str(verdict), str(reason_code), "essential_unknown", payload)
    if not isinstance(explanation, str) or not explanation.strip():
        return VerdictResult("UNCERTAIN", str(verdict), str(reason_code), "missing_explanation", payload)

    confidence = payload.get("confidence")
    if not isinstance(confidence, (int, float)) or isinstance(confidence, bool) or not 0 <= confidence <= 1:
        return VerdictResult("UNCERTAIN", str(verdict), str(reason_code), "invalid_confidence", payload)

    for citation in citations:
        if not isinstance(citation, dict):
            return VerdictResult("UNCERTAIN", str(verdict), str(reason_code), "invalid_citation", payload)
        start = citation.get("start_line")
        end = citation.get("end_line")
        if not isinstance(start, int) or not isinstance(end, int) or start > end:
            return VerdictResult("UNCERTAIN", str(verdict), str(reason_code), "invalid_citation_range", payload)
        claim = citation.get("claim")
        if not isinstance(claim, str) or not claim.strip():
            return VerdictResult("UNCERTAIN", str(verdict), str(reason_code), "invalid_citation_claim", payload)
        if any(line not in allowed_lines for line in range(start, end + 1)):
            return VerdictResult("UNCERTAIN", str(verdict), str(reason_code), "citation_outside_context", payload)

    return VerdictResult(
        "SUPPRESS_CANDIDATE",
        str(verdict),
        str(reason_code),
        None,
        payload,
    )
