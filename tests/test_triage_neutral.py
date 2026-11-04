from triage import _neutral_candidate_request, _retrieval_failure


def test_b_and_c_candidate_requests_share_non_knowledge_inputs() -> None:
    common = {
        "template": "{guard_packet}\n{finding}\n{context}\n{required_guard_ids}\n{retrieved_knowledge}",
        "schema": {"properties": {"knowledge_used": {"maxItems": 4}, "guard_assessments": {"items": {}}}},
        "finding": {"id": "candidate-1"},
        "context": {"candidate_id": "candidate-1"},
        "guards": {},
        "guard_packet": [],
        "inference_options": {"temperature": 0},
    }
    b_request = _neutral_candidate_request(**common, retrieved_knowledge=[])
    c_request = _neutral_candidate_request(
        **common, retrieved_knowledge=[{"knowledge_id": "chunk-v1:one"}],
    )

    assert b_request["retrieved_knowledge"] == []
    assert c_request["retrieved_knowledge"] == [{"knowledge_id": "chunk-v1:one"}]
    assert {key: value for key, value in b_request.items() if key not in {"prompt", "retrieved_knowledge"}} == {
        key: value for key, value in c_request.items() if key not in {"prompt", "retrieved_knowledge"}
    }
    assert b_request["prompt"] != c_request["prompt"]


def test_retrieval_failure_is_uncertain_and_preserves_error_evidence() -> None:
    assert _retrieval_failure("candidate-1", "digest mismatch") == {
        "candidate_id": "candidate-1",
        "effective_verdict": "UNCERTAIN",
        "error": "retrieval:digest mismatch",
        "retrieval_error": {"message": "digest mismatch"},
    }
