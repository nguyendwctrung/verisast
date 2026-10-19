import json
import urllib.error
import urllib.request


class OllamaError(RuntimeError):
    pass


def generate(endpoint: str, model: str, prompt: str, timeout: int, tokens: int, schema: dict[str, object]) -> tuple[dict[str, object], str]:
    payload = {"model": model, "prompt": prompt, "stream": False, "format": schema, "options": {"temperature": 0, "num_predict": tokens}}
    request = urllib.request.Request(f"{endpoint.rstrip('/')}/api/generate", data=json.dumps(payload).encode("utf-8"), headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            raw = response.read().decode("utf-8")
        decoded = json.loads(raw)
    except (urllib.error.URLError, TimeoutError, OSError, json.JSONDecodeError) as error:
        raise OllamaError(str(error)) from error
    if not isinstance(decoded, dict) or not isinstance(decoded.get("response"), str):
        raise OllamaError("Ollama response field is missing")
    return decoded, raw
