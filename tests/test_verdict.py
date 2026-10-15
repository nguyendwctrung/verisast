from verdict import validate_verdict


def _response(**overrides: object) -> str:
    value = {
        "schema_version": "llm-verdict-v1",
        "verdict": "SUPPRESS_CANDIDATE",
        "reason_code": "EFFECTIVE_SANITIZER",
        "source_citations": [{"start_line": 10, "end_line": 11, "claim": "validated sanitizer"}],
        "explanation": "Lines 10 through 11 apply a validated sanitizer.",
        "essential_unknowns": [],
        "confidence": 0.9,
    }
    value.update(overrides)
    import json

    return json.dumps(value)


def test_valid_suppression_requires_citations_inside_context() -> None:
    result = validate_verdict(_response(), {10, 11, 12})

    assert result.effective_verdict == "SUPPRESS_CANDIDATE"
    assert result.error is None


def test_invalid_schema_and_outside_citation_fail_open() -> None:
    wrong_schema = validate_verdict(_response(schema_version="other"), {10, 11, 12})
    outside_context = validate_verdict(_response(source_citations=[{"start_line": 9, "end_line": 10, "claim": "claim"}]), {10, 11, 12})

    assert wrong_schema.effective_verdict == "UNCERTAIN"
    assert wrong_schema.error == "invalid_schema_version"
    assert outside_context.effective_verdict == "UNCERTAIN"
    assert outside_context.error == "citation_outside_context"


def test_suppression_with_unknowns_or_missing_claim_fails_open() -> None:
    unknowns = validate_verdict(_response(essential_unknowns=["guard condition"]), {10, 11, 12})
    missing_claim = validate_verdict(_response(source_citations=[{"start_line": 10, "end_line": 11}]), {10, 11, 12})

    assert unknowns.effective_verdict == "UNCERTAIN"
    assert unknowns.error == "essential_unknown"
    assert missing_claim.effective_verdict == "UNCERTAIN"
    assert missing_claim.error == "invalid_citation_claim"
