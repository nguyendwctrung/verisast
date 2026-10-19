import json
from pathlib import Path

from context import build
from evaluate import score
from main import main
from ollama_client import generate
from sarif import normalize
from verdict import check


def test_normalize_keeps_code_flow_and_cwe(tmp_path: Path) -> None:
    sarif_path = tmp_path / "result.sarif"
    sarif_path.write_text(json.dumps({"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "CodeQL", "rules": [{"id": "java/sql", "properties": {"tags": ["external/cwe/cwe-89"]}}]}}, "results": [{"ruleId": "java/sql", "locations": [{"physicalLocation": {"artifactLocation": {"uri": "src/A.java"}, "region": {"startLine": 7, "endLine": 7}}}], "codeFlows": [{"threadFlows": [{"locations": [{"location": {"physicalLocation": {"artifactLocation": {"uri": "src/A.java"}, "region": {"startLine": 4}}}}]}]}]}]}]}), encoding="utf-8")
    findings = normalize(sarif_path, "abc", "pack", "suite")
    assert findings[0]["cwes"] == [89]
    assert findings[0]["flow"][0]["line"] == 4


def test_context_and_evaluation_use_frozen_candidates(tmp_path: Path) -> None:
    source = tmp_path / "src"
    source.mkdir()
    (source / "BenchmarkTest00001.java").write_text("a\nb\nc\n", encoding="utf-8")
    findings = [{"id": "one", "path": "BenchmarkTest00001.java", "start": 2, "end": 2, "cwes": [89], "flow": []}]
    contexts = build(source, findings)
    assert contexts[0]["lines"][0]["id"] == "F1:L1"
    metrics = score([{"test_id": "BenchmarkTest00001", "cwe": 89, "vulnerable": True}], findings)
    assert metrics["overall"]["tp"] == 1


def test_context_includes_code_flow_window(tmp_path: Path) -> None:
    source = tmp_path / "src"
    source.mkdir()
    (source / "A.java").write_text("".join(f"line {number}\n" for number in range(1, 41)), encoding="utf-8")
    findings = [{
        "id": "one", "path": "A.java", "start": 10, "end": 10,
        "flow": [{"path": "A.java", "line": 25, "message": "barrier"}],
    }]

    context = build(source, findings, before=1, after=1, limit=50)[0]

    assert {"F1:L24", "F1:L25", "F1:L26"}.issubset({line["id"] for line in context["lines"]})
    assert context["missing_evidence"] == []


def test_cli_normalize_dispatches_normalizer(tmp_path: Path) -> None:
    sarif_path = tmp_path / "result.sarif"
    sarif_path.write_text(
        json.dumps({"version": "2.1.0", "runs": [{"tool": {"driver": {"rules": []}}, "results": []}]}),
        encoding="utf-8",
    )
    output = tmp_path / "findings.jsonl"

    status = main([
        "normalize", "--sarif", str(sarif_path), "--source-revision", "abc",
        "--pack", "pack", "--suite", "suite", "--output", str(output),
    ])

    assert status == 0
    assert output.read_text(encoding="utf-8") == ""


def test_ollama_request_includes_verdict_schema(monkeypatch) -> None:
    captured: dict[str, object] = {}

    class Response:
        def read(self) -> bytes:
            return b'{"response":"{}"}'

        def __enter__(self):
            return self

        def __exit__(self, *args: object) -> None:
            return None

    def open_url(request, timeout: int):
        captured["body"] = json.loads(request.data.decode("utf-8"))
        captured["timeout"] = timeout
        return Response()

    monkeypatch.setattr("ollama_client.urllib.request.urlopen", open_url)
    schema = {"type": "object"}

    generate("http://localhost:11434", "model", "prompt", 12, 34, schema)

    assert captured["body"] == {
        "model": "model",
        "prompt": "prompt",
        "stream": False,
        "format": schema,
        "options": {"temperature": 0, "num_predict": 34},
    }
    assert captured["timeout"] == 12


def test_invalid_evidence_is_uncertain() -> None:
    result = check('{"schema_version":"verdict-v2","verdict":"FALSE_POSITIVE","confidence":0.9,"source":{"present":true,"evidence_lines":["F1:L9"]},"sink":{"present":true,"evidence_lines":["F1:L9"]},"dataflow":{"reaches_sink":true,"evidence_lines":["F1:L9"]},"barriers":[],"required_conditions":[],"missing_evidence":[],"knowledge_used":[],"reason":"x"}', {"F1:L1"}, set())
    assert result.effective == "UNCERTAIN"


def test_true_positive_requires_valid_evidence() -> None:
    payload = {
        "schema_version": "verdict-v2", "verdict": "TRUE_POSITIVE", "confidence": 0.9,
        "source": {"present": True, "evidence_lines": ["F1:L9"]},
        "sink": {"present": True, "evidence_lines": ["F1:L9"]},
        "dataflow": {"reaches_sink": True, "evidence_lines": ["F1:L9"]},
        "barriers": [], "required_conditions": [], "missing_evidence": [],
        "knowledge_used": [], "reason": "x",
    }

    invalid = check(json.dumps(payload), {"F1:L1"}, set())
    assert invalid.effective == "UNCERTAIN"
    assert invalid.error == "invalid_citation"

    payload["source"]["evidence_lines"] = ["F1:L1"]
    payload["sink"]["evidence_lines"] = ["F1:L1"]
    payload["dataflow"]["evidence_lines"] = ["F1:L1"]
    valid = check(json.dumps(payload), {"F1:L1"}, set())
    assert valid.effective == "TRUE_POSITIVE"


def test_false_positive_requires_cited_effective_barrier() -> None:
    payload = {
        "schema_version": "verdict-v2", "verdict": "FALSE_POSITIVE", "confidence": 0.9,
        "source": {"present": True, "evidence_lines": ["F1:L1"]},
        "sink": {"present": True, "evidence_lines": ["F1:L1"]},
        "dataflow": {"reaches_sink": True, "evidence_lines": ["F1:L1"]},
        "barriers": [], "required_conditions": [], "missing_evidence": [],
        "knowledge_used": [], "reason": "x",
    }

    missing = check(json.dumps(payload), {"F1:L1"}, set())
    assert missing.effective == "UNCERTAIN"
    assert missing.error == "missing_effective_barrier"

    payload["barriers"] = [{"kind": "PATH_PREFIX_CHECK", "effective": True, "evidence_lines": ["F1:L1", "F1:L2"], "reason": "guard"}]
    valid = check(json.dumps(payload), {"F1:L1", "F1:L2"}, set())
    assert valid.effective == "FALSE_POSITIVE"


def test_barrier_requires_typed_guard_assessment() -> None:
    payload = {
        "schema_version": "verdict-v2", "verdict": "FALSE_POSITIVE", "confidence": 0.9,
        "source": {"present": True, "evidence_lines": ["F1:L1"]},
        "sink": {"present": True, "evidence_lines": ["F1:L1"]},
        "dataflow": {"reaches_sink": True, "evidence_lines": ["F1:L1"]},
        "barriers": [{"effective": True, "evidence_lines": ["F1:L1"], "reason": "guard"}],
        "required_conditions": [], "missing_evidence": [],
        "knowledge_used": [], "reason": "x",
    }

    invalid = check(json.dumps(payload), {"F1:L1"}, set())
    assert invalid.effective == "UNCERTAIN"
    assert invalid.error == "invalid_barrier"

    payload["barriers"][0]["kind"] = "PATH_PREFIX_CHECK"
    invalid_prefix = check(json.dumps(payload), {"F1:L1"}, set())
    assert invalid_prefix.error == "incomplete_path_prefix_check"

    payload["barriers"][0]["evidence_lines"] = ["F1:L1", "F1:L2"]
    valid = check(json.dumps(payload), {"F1:L1", "F1:L2"}, set())
    assert valid.effective == "FALSE_POSITIVE"


def test_true_positive_rejects_effective_barrier_and_unprovided_knowledge() -> None:
    payload = {
        "schema_version": "verdict-v2", "verdict": "TRUE_POSITIVE", "confidence": 0.9,
        "source": {"present": True, "evidence_lines": ["F1:L1"]},
        "sink": {"present": True, "evidence_lines": ["F1:L1"]},
        "dataflow": {"reaches_sink": True, "evidence_lines": ["F1:L1"]},
        "barriers": [{"kind": "PATH_PREFIX_CHECK", "effective": True, "evidence_lines": ["F1:L1", "F1:L2"], "reason": "guard"}],
        "required_conditions": [], "missing_evidence": [],
        "knowledge_used": [], "reason": "x",
    }

    barrier = check(json.dumps(payload), {"F1:L1", "F1:L2"}, set())
    assert barrier.effective == "UNCERTAIN"
    assert barrier.error == "contradictory_effective_barrier"

    payload["barriers"] = []
    payload["knowledge_used"] = ["unprovided"]
    knowledge = check(json.dumps(payload), {"F1:L1"}, set())
    assert knowledge.effective == "UNCERTAIN"
    assert knowledge.error == "invalid_knowledge"


def test_verdict_schema_restricts_evidence_to_line_ids() -> None:
    schema = json.loads((Path(__file__).parents[1] / "schemas" / "verdict.json").read_text(encoding="utf-8"))

    references = schema["$defs"]["line_refs"]
    assert references["maxItems"] == 4
    assert references["items"]["pattern"] == "^F[1-9][0-9]*:L[1-9][0-9]*$"
    barrier = schema["$defs"]["barrier"]
    assert barrier["required"] == ["kind", "effective", "evidence_lines", "reason"]
    assert barrier["properties"]["kind"]["enum"] == ["PATH_PREFIX_CHECK", "OTHER"]
