import json
from pathlib import Path


class PromptError(ValueError):
    pass


REQUIRED_PLACEHOLDERS = {"{candidate_metadata}", "{source_context}"}


def render_prompt(
    template_path: Path,
    candidate_metadata: dict[str, object],
    source_context: str,
) -> str:
    if not isinstance(candidate_metadata, dict):
        raise PromptError("candidate metadata must be an object")
    if not isinstance(source_context, str) or not source_context.strip():
        raise PromptError("source context must be non-empty")
    template = template_path.read_text(encoding="utf-8")
    missing = [placeholder for placeholder in REQUIRED_PLACEHOLDERS if placeholder not in template]
    if missing:
        raise PromptError(f"prompt template is missing {sorted(missing)[0]}")
    return template.replace(
        "{candidate_metadata}", json.dumps(candidate_metadata, ensure_ascii=False, sort_keys=True)
    ).replace("{source_context}", source_context)
