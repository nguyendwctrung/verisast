import pytest

from triage_retrieval import TriageRetrievalError, deterministic_query


def test_query_is_deterministic_and_bound_to_frozen_candidate_context() -> None:
    finding = {"id": "candidate-1", "cwes": [22], "rule_id": "java/path-injection", "message": "x", "path": "A.java"}
    context = {"candidate_id": "candidate-1", "lines": [{"id": "F1:L1", "text": "entry.getName();"}]}

    assert deterministic_query(finding, context) == deterministic_query(finding, context)


def test_query_rejects_mismatched_context() -> None:
    with pytest.raises(TriageRetrievalError, match="identities"):
        deterministic_query({"id": "candidate-1"}, {"candidate_id": "candidate-2", "lines": []})
