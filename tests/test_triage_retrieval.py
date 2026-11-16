import pytest

from triage_retrieval import TriageRetrievalError, deterministic_query, validate_query_id


def test_query_is_deterministic_and_bound_to_frozen_candidate_context() -> None:
    finding = {"id": "candidate-1", "cwes": [22], "rule_id": "java/path-injection", "message": "x", "path": "A.java"}
    context = {"candidate_id": "candidate-1", "lines": [{"id": "F1:L1", "text": "entry.getName();"}]}

    assert deterministic_query(finding, context) == deterministic_query(finding, context)


def test_query_rejects_mismatched_context() -> None:
    with pytest.raises(TriageRetrievalError, match="identities"):
        deterministic_query({"id": "candidate-1"}, {"candidate_id": "candidate-2", "lines": []})


def test_contract_query_id_gate_accepts_registered_rule() -> None:
    validate_query_id({"allowed_query_ids": ["java/path-injection"]}, {"rule_id": "java/path-injection"})


def test_contract_query_id_gate_rejects_unregistered_rule() -> None:
    with pytest.raises(TriageRetrievalError, match="not permitted"):
        validate_query_id({"allowed_query_ids": ["java/path-injection"]}, {"rule_id": "java/zipslip"})


def test_contract_without_query_id_gate_remains_compatible() -> None:
    validate_query_id({}, {"rule_id": "java/zipslip"})
