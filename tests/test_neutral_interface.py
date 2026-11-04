import copy
import json
from pathlib import Path

import pytest

from neutral_interface import (
    NeutralInterfaceError,
    bind_knowledge_schema,
    build_variant_request,
    render_prompt,
)


ROOT = Path(__file__).parents[1]


def _template() -> str:
    return (ROOT / "prompts" / "triage.txt").read_text(encoding="utf-8")


def _schema() -> dict[str, object]:
    return json.loads((ROOT / "schemas" / "verdict.json").read_text(encoding="utf-8"))


def _base_request() -> dict[str, object]:
    return {
        "prompt_template": _template(),
        "schema": _schema(),
        "guard_packet": [{"guard_id": "G1"}],
        "inference_options": {"temperature": 0, "num_predict": 512, "num_ctx": 3072, "keep_alive": "10m"},
    }


def test_b_and_c_render_the_same_template_except_for_knowledge_slot() -> None:
    template = _template()
    common = {
        "guard_packet": "[]",
        "finding": "{}",
        "context": "{}",
        "required_guard_ids": "[]",
    }

    b_prompt = render_prompt(template, retrieved_knowledge=[], **common)
    c_prompt = render_prompt(template, retrieved_knowledge=[{"knowledge_id": "chunk-v1:one"}], **common)

    assert "chunk-v1:one" not in b_prompt
    assert "chunk-v1:one" in c_prompt
    assert b_prompt.replace("[]", "<knowledge>", 1) != c_prompt
    assert template.count("{retrieved_knowledge}") == 1


def test_b_and_c_bind_the_same_schema_limit() -> None:
    schema = _schema()

    b_schema = bind_knowledge_schema(schema, 3)
    c_schema = bind_knowledge_schema(schema, 3)

    assert b_schema == c_schema
    assert b_schema["properties"]["knowledge_used"]["maxItems"] == 3
    assert schema["properties"]["knowledge_used"]["maxItems"] == 4


def test_b_and_c_requests_differ_only_by_knowledge_data() -> None:
    base = _base_request()
    b_request = build_variant_request(base, [], 3)
    c_knowledge = [{"knowledge_id": "chunk-v1:one", "canonical_text": "Reference"}]
    c_request = build_variant_request(base, c_knowledge, 3)

    assert b_request["retrieved_knowledge"] == []
    assert c_request["retrieved_knowledge"] == c_knowledge
    assert {
        key: value for key, value in b_request.items() if key != "retrieved_knowledge"
    } == {
        key: value for key, value in c_request.items() if key != "retrieved_knowledge"
    }
    assert base == _base_request()


def test_binding_rejects_knowledge_limit_above_contract_maximum() -> None:
    with pytest.raises(NeutralInterfaceError, match="maximum"):
        bind_knowledge_schema(_schema(), 4)


def test_rendering_rejects_a_template_without_exactly_one_knowledge_slot() -> None:
    template = _template().replace("{retrieved_knowledge}", "")

    with pytest.raises(NeutralInterfaceError, match="exactly one"):
        render_prompt(
            template,
            guard_packet="[]",
            finding="{}",
            context="{}",
            required_guard_ids="[]",
            retrieved_knowledge=[],
        )
