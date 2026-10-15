import json
import urllib.error
import urllib.request


class OllamaError(RuntimeError):
    pass


def build_payload(model: str, prompt: str) -> dict[str, object]:
    if not isinstance(model, str) or not model.strip():
        raise OllamaError("model must be non-empty")
    if not isinstance(prompt, str) or not prompt.strip():
        raise OllamaError("prompt must be non-empty")
    return {
        "model": model,
        "prompt": prompt,
        "stream": False,
        "options": {"temperature": 0},
    }


def generate(
    endpoint: str,
    model: str,
    prompt: str,
    timeout_seconds: int,
) -> tuple[dict[str, object], str]:
    if not isinstance(timeout_seconds, int) or timeout_seconds <= 0:
        raise OllamaError("timeout must be a positive integer")
    payload = build_payload(model, prompt)
    request = urllib.request.Request(
        f"{endpoint.rstrip('/')}/api/generate",
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout_seconds) as response:
            raw = response.read().decode("utf-8")
    except (urllib.error.URLError, TimeoutError, OSError) as error:
        raise OllamaError(str(error)) from error

    try:
        decoded = json.loads(raw)
    except json.JSONDecodeError as error:
        raise OllamaError("Ollama response is not JSON") from error

    if not isinstance(decoded, dict) or not isinstance(decoded.get("response"), str):
        raise OllamaError("Ollama response field is missing")

    return decoded, raw
