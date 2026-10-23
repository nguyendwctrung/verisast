import json
import urllib.error
import urllib.request


class OllamaError(RuntimeError):
    pass


def _get(endpoint: str, path: str, timeout: int) -> dict[str, object]:
    request = urllib.request.Request(f"{endpoint.rstrip('/')}{path}", method="GET")
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            decoded = json.loads(response.read().decode("utf-8"))
    except (urllib.error.URLError, TimeoutError, OSError, json.JSONDecodeError) as error:
        raise OllamaError(str(error)) from error
    if not isinstance(decoded, dict):
        raise OllamaError("Ollama metadata response must be an object")
    return decoded


def metadata(endpoint: str, model: str, timeout: int) -> dict[str, object]:
    version = _get(endpoint, "/api/version", timeout).get("version")
    models = _get(endpoint, "/api/tags", timeout).get("models")
    digest = None
    if isinstance(models, list):
        for item in models:
            if isinstance(item, dict) and item.get("name") == model and isinstance(item.get("digest"), str):
                digest = item["digest"]
                break
    return {"ollama_version": version if isinstance(version, str) else None, "requested_model": model, "model_digest": digest}


def running_model(endpoint: str, model: str, timeout: int) -> dict[str, object]:
    models = _get(endpoint, "/api/ps", timeout).get("models")
    if not isinstance(models, list):
        raise OllamaError("Ollama running-model response must contain a model list")
    for item in models:
        if not isinstance(item, dict) or model not in (item.get("name"), item.get("model")):
            continue
        size = item.get("size")
        size_vram = item.get("size_vram")
        context_length = item.get("context_length")
        return {
            "loaded": True,
            "size": size if isinstance(size, int) else None,
            "size_vram": size_vram if isinstance(size_vram, int) else None,
            "context_length": context_length if isinstance(context_length, int) else None,
            "fully_gpu_loaded": isinstance(size, int) and size > 0 and isinstance(size_vram, int) and size_vram >= size,
        }
    return {"loaded": False}


def generate(endpoint: str, model: str, prompt: str, timeout: int, tokens: int, schema: dict[str, object], temperature: float, context_tokens: int, keep_alive: str) -> tuple[dict[str, object], str]:
    payload = {
        "model": model,
        "prompt": prompt,
        "stream": False,
        "format": schema,
        "keep_alive": keep_alive,
        "options": {"temperature": temperature, "num_predict": tokens, "num_ctx": context_tokens},
    }
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
