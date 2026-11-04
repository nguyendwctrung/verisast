import copy
import json


class NeutralInterfaceError(ValueError):
    pass


_KNOWLEDGE_SLOT = "{retrieved_knowledge}"
_MAXIMUM_KNOWLEDGE_ITEMS = 3


def render_prompt(
    template: str,
    *,
    guard_packet: str,
    finding: str,
    context: str,
    required_guard_ids: str,
    retrieved_knowledge: list[object],
) -> str:
    """Render the one permitted B/C difference into a neutral prompt template."""
    if not isinstance(template, str) or template.count(_KNOWLEDGE_SLOT) != 1:
        raise NeutralInterfaceError("prompt template must contain exactly one retrieved knowledge slot")
    if not isinstance(retrieved_knowledge, list) or len(retrieved_knowledge) > _MAXIMUM_KNOWLEDGE_ITEMS:
        raise NeutralInterfaceError("retrieved knowledge exceeds the contract maximum")
    replacements = {
        "{guard_packet}": guard_packet,
        "{finding}": finding,
        "{context}": context,
        "{required_guard_ids}": required_guard_ids,
        _KNOWLEDGE_SLOT: json.dumps(retrieved_knowledge, sort_keys=True),
    }
    if not all(isinstance(value, str) for value in replacements.values()):
        raise NeutralInterfaceError("prompt replacement values must be strings")
    rendered = template
    for placeholder, value in replacements.items():
        rendered = rendered.replace(placeholder, value)
    return rendered


def bind_knowledge_schema(schema: dict[str, object], maximum_items: int) -> dict[str, object]:
    """Return a shared B/C schema bound to the neutral knowledge limit."""
    if isinstance(maximum_items, bool) or not isinstance(maximum_items, int) or not 0 <= maximum_items <= _MAXIMUM_KNOWLEDGE_ITEMS:
        raise NeutralInterfaceError("knowledge maximum exceeds the contract maximum")
    bound = copy.deepcopy(schema)
    try:
        knowledge_used = bound["properties"]["knowledge_used"]
    except (KeyError, TypeError) as error:
        raise NeutralInterfaceError("schema must define knowledge_used") from error
    if not isinstance(knowledge_used, dict):
        raise NeutralInterfaceError("schema knowledge_used must be an object")
    knowledge_used["maxItems"] = maximum_items
    return bound


def build_variant_request(
    base_request: dict[str, object],
    retrieved_knowledge: list[object],
    knowledge_maximum: int,
) -> dict[str, object]:
    """Build a B or C request without mutating shared non-knowledge inputs."""
    if not isinstance(base_request, dict):
        raise NeutralInterfaceError("base request must be an object")
    if not isinstance(retrieved_knowledge, list) or len(retrieved_knowledge) > knowledge_maximum:
        raise NeutralInterfaceError("retrieved knowledge exceeds the requested maximum")
    schema = base_request.get("schema")
    if not isinstance(schema, dict):
        raise NeutralInterfaceError("base request must contain a schema")
    request = copy.deepcopy(base_request)
    request["schema"] = bind_knowledge_schema(schema, knowledge_maximum)
    request["retrieved_knowledge"] = copy.deepcopy(retrieved_knowledge)
    return request
