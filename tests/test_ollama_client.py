import json

import pytest

import ollama_client
from ollama_client import OllamaError, build_payload, generate


def test_build_payload_is_deterministic_and_uses_temperature_zero() -> None:
    assert build_payload("model-a", "verify this") == {
        "model": "model-a",
        "prompt": "verify this",
        "stream": False,
        "options": {"temperature": 0},
    }


def test_generate_returns_decoded_response_and_raw_bytes(monkeypatch) -> None:
    class Response:
        def read(self) -> bytes:
            return b'{"response":"KEEP"}'

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc_value, traceback) -> None:
            return None

    captured: dict[str, object] = {}

    def fake_urlopen(request, timeout):
        captured["url"] = request.full_url
        captured["body"] = json.loads(request.data.decode("utf-8"))
        captured["timeout"] = timeout
        return Response()

    monkeypatch.setattr(ollama_client.urllib.request, "urlopen", fake_urlopen)

    decoded, raw = generate("http://127.0.0.1:11434", "model-a", "verify", 120)

    assert decoded["response"] == "KEEP"
    assert raw == '{"response":"KEEP"}'
    assert captured == {
        "url": "http://127.0.0.1:11434/api/generate",
        "body": build_payload("model-a", "verify"),
        "timeout": 120,
    }


def test_generate_rejects_non_positive_timeout() -> None:
    with pytest.raises(OllamaError, match="timeout"):
        generate("http://127.0.0.1:11434", "model-a", "verify", 0)
