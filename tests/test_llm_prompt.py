import pytest

from llm_prompt import PromptError, render_prompt


def test_render_prompt_includes_serialized_metadata_and_context(tmp_path) -> None:
    template = tmp_path / "prompt.txt"
    template.write_text("Candidate: {candidate_metadata}\nContext: {source_context}\n", encoding="utf-8")

    prompt = render_prompt(
        template,
        {"finding_id": "finding-1", "cwe": "CWE-89"},
        "10: statement();",
    )

    assert '"finding_id": "finding-1"' in prompt
    assert "10: statement();" in prompt


def test_render_prompt_rejects_template_without_required_placeholders(tmp_path) -> None:
    template = tmp_path / "prompt.txt"
    template.write_text("Candidate only: {candidate_metadata}\n", encoding="utf-8")

    with pytest.raises(PromptError, match="source_context"):
        render_prompt(template, {"finding_id": "finding-1"}, "10: statement();")
