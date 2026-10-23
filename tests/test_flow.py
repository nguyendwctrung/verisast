import json
from pathlib import Path

from context import build
from evaluate import score
from main import main
from ollama_client import generate, metadata, running_model
from sarif import normalize
from triage import _guard_contract, _guard_packet, _input_hashes, _request, _schema_for
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


def test_context_detects_path_prefix_guard(tmp_path: Path) -> None:
    source = tmp_path / "src"
    source.mkdir()
    (source / "A.java").write_text(
        "File f = resolve(dir, entry);\n"
        "if (!f.getAbsolutePath().startsWith(dir.getAbsolutePath())) {\n"
        "    throw new IOException();\n"
        "}\n",
        encoding="utf-8",
    )
    context = build(source, [{"id": "one", "path": "A.java", "start": 1, "end": 1, "flow": []}], before=0, after=3)[0]

    assert context["guards"] == [{
        "id": "G1", "kind": "PATH_PREFIX_CHECK", "condition_lines": ["F1:L2"],
        "action_lines": ["F1:L3"], "action_blocks_sink": True,
    }]


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

    generate("http://localhost:11434", "model", "prompt", 12, 34, schema, 0.25, 3072, "10m")

    assert captured["body"] == {
        "model": "model",
        "prompt": "prompt",
        "stream": False,
        "format": schema,
        "keep_alive": "10m",
        "options": {"temperature": 0.25, "num_predict": 34, "num_ctx": 3072},
    }
    assert captured["timeout"] == 12


def test_ollama_metadata_keeps_observed_model_digest(monkeypatch) -> None:
    class Response:
        def __init__(self, payload: dict[str, object]) -> None:
            self.payload = payload

        def read(self) -> bytes:
            return json.dumps(self.payload).encode("utf-8")

        def __enter__(self):
            return self

        def __exit__(self, *args: object) -> None:
            return None

    def open_url(request, timeout: int):
        if request.full_url.endswith("/api/version"):
            return Response({"version": "0.40.6"})
        return Response({"models": [{"name": "model", "digest": "sha256:abc"}]})

    monkeypatch.setattr("ollama_client.urllib.request.urlopen", open_url)

    assert metadata("http://localhost:11434", "model", 12) == {
        "ollama_version": "0.40.6", "requested_model": "model", "model_digest": "sha256:abc",
    }


def test_ollama_running_model_records_gpu_allocation(monkeypatch) -> None:
    class Response:
        def read(self) -> bytes:
            return json.dumps({"models": [{
                "name": "model", "size": 4613136710, "size_vram": 4613136710,
                "context_length": 3072,
            }]}).encode("utf-8")

        def __enter__(self):
            return self

        def __exit__(self, *args: object) -> None:
            return None

    monkeypatch.setattr("ollama_client.urllib.request.urlopen", lambda request, timeout: Response())

    assert running_model("http://localhost:11434", "model", 12) == {
        "loaded": True,
        "size": 4613136710,
        "size_vram": 4613136710,
        "context_length": 3072,
        "fully_gpu_loaded": True,
    }


def test_llm_config_records_optimized_runtime() -> None:
    config = json.loads((Path(__file__).parents[1] / "configs" / "llm.json").read_text(encoding="utf-8"))

    assert config["temperature"] == 0
    assert config["max_response_tokens"] == 512
    assert config["context_tokens"] == 3072
    assert config["keep_alive"] == "10m"
    assert config["server_environment"] == {
        "OLLAMA_NUM_PARALLEL": "1",
        "OLLAMA_CONTEXT_LENGTH": "3072",
        "OLLAMA_FLASH_ATTENTION": "1",
        "OLLAMA_KV_CACHE_TYPE": "q8_0",
        "LLAMA_ARG_FIT_TARGET": "512",
    }


def test_input_hashes_bind_triage_inputs(tmp_path: Path) -> None:
    findings = tmp_path / "findings.jsonl"
    contexts = tmp_path / "contexts.jsonl"
    prompt = tmp_path / "triage.txt"
    schema = tmp_path / "verdict.json"
    config = tmp_path / "llm.json"
    for path in (findings, contexts, prompt, schema, config):
        path.write_text(path.name, encoding="utf-8")

    hashes = _input_hashes(findings, contexts, prompt, schema, config)

    assert set(hashes) == {"findings", "contexts", "prompt", "schema", "config"}
    assert hashes["prompt"]["sha256"] == "c328b662c5f7d4c35b4bc58d856c27e504ecd698a571b72ed77a4419490c3531"


def test_invalid_evidence_is_uncertain() -> None:
    result = check('{"schema_version":"verdict-v6","verdict":"FALSE_POSITIVE","confidence":0.9,"source":{"present":true,"evidence_lines":["F1:L9"]},"sink":{"present":true,"evidence_lines":["F1:L9"]},"dataflow":{"reaches_sink":true,"evidence_lines":["F1:L9"]},"barriers":[],"guard_assessments":[],"required_conditions":[],"missing_evidence":[],"knowledge_used":[],"reason":"x"}', {"F1:L1"}, set())
    assert result.effective == "UNCERTAIN"


def test_true_positive_requires_valid_evidence() -> None:
    payload = {
        "schema_version": "verdict-v6", "verdict": "TRUE_POSITIVE", "confidence": 0.9,
        "source": {"present": True, "evidence_lines": ["F1:L9"]},
        "sink": {"present": True, "evidence_lines": ["F1:L9"]},
        "dataflow": {"reaches_sink": True, "evidence_lines": ["F1:L9"]},
        "barriers": [], "guard_assessments": [], "required_conditions": [], "missing_evidence": [],
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
        "schema_version": "verdict-v6", "verdict": "FALSE_POSITIVE", "confidence": 0.9,
        "source": {"present": True, "evidence_lines": ["F1:L1"]},
        "sink": {"present": True, "evidence_lines": ["F1:L1"]},
        "dataflow": {"reaches_sink": True, "evidence_lines": ["F1:L1"]},
        "barriers": [], "guard_assessments": [], "required_conditions": [], "missing_evidence": [],
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
        "schema_version": "verdict-v6", "verdict": "FALSE_POSITIVE", "confidence": 0.9,
        "source": {"present": True, "evidence_lines": ["F1:L1"]},
        "sink": {"present": True, "evidence_lines": ["F1:L1"]},
        "dataflow": {"reaches_sink": True, "evidence_lines": ["F1:L1"]},
        "barriers": [{"effective": True, "evidence_lines": ["F1:L1"], "reason": "guard"}], "guard_assessments": [],
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
        "schema_version": "verdict-v6", "verdict": "TRUE_POSITIVE", "confidence": 0.9,
        "source": {"present": True, "evidence_lines": ["F1:L1"]},
        "sink": {"present": True, "evidence_lines": ["F1:L1"]},
        "dataflow": {"reaches_sink": True, "evidence_lines": ["F1:L1"]},
        "barriers": [{"kind": "PATH_PREFIX_CHECK", "effective": True, "evidence_lines": ["F1:L1", "F1:L2"], "reason": "guard"}], "guard_assessments": [],
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


def test_guard_assessment_must_cover_detected_guard() -> None:
    payload = {
        "schema_version": "verdict-v6", "verdict": "FALSE_POSITIVE", "confidence": 0.9,
        "source": {"present": True, "evidence_lines": ["F1:L1"]},
        "sink": {"present": True, "evidence_lines": ["F1:L1"]},
        "dataflow": {"reaches_sink": True, "evidence_lines": ["F1:L1"]},
        "barriers": [], "guard_assessments": [], "required_conditions": [],
        "missing_evidence": [], "knowledge_used": [], "reason": "x",
    }
    guards = {"G1": {"condition_lines": ["F1:L2"], "action_lines": ["F1:L3"], "action_blocks_sink": True}}

    missing = check(json.dumps(payload), {"F1:L1", "F1:L2", "F1:L3"}, set(), guards)
    assert missing.error == "missing_guard_assessment"

    payload["guard_assessments"] = [{
        "guard_id": "G1", "condition_blocks_path": True, "effective": True,
        "reason": "guard blocks sink",
    }]
    valid = check(json.dumps(payload), {"F1:L1", "F1:L2", "F1:L3"}, set(), guards)
    assert valid.effective == "FALSE_POSITIVE"
    assert valid.payload["context_bound_evidence"] == [{
        "guard_id": "G1", "citation_source": "context_contract",
        "condition_lines": ["F1:L2"], "action_lines": ["F1:L3"], "action_blocks_sink": True,
    }]
    payload["guard_assessments"][0]["effective"] = False
    inconsistent = check(json.dumps(payload), {"F1:L1", "F1:L2", "F1:L3"}, set(), guards)
    assert inconsistent.error == "inconsistent_guard_assessment"
    payload["guard_assessments"][0]["effective"] = True
    payload["guard_assessments"][0]["action_blocks_sink"] = True
    invalid = check(json.dumps(payload), {"F1:L1", "F1:L2", "F1:L3"}, set(), guards)
    assert invalid.error == "invalid_guard_assessment"

    payload["guard_assessments"][0].pop("action_blocks_sink")
    blocked = check(json.dumps(payload), {"F1:L1", "F1:L2", "F1:L3"}, set(), {
        "G1": {"condition_lines": ["F1:L2"], "action_lines": ["F1:L3"], "action_blocks_sink": False},
    })
    assert blocked.error == "inconsistent_guard_assessment"


def test_triage_schema_requires_one_assessment_per_guard() -> None:
    schema = {"properties": {"guard_assessments": {"type": "array", "maxItems": 16, "items": {"$ref": "#/$defs/guard_assessment"}}}}
    guards = {
        "G1": {"condition_lines": ["F1:L2"], "action_lines": ["F1:L3"]},
        "G2": {"condition_lines": ["F2:L4"], "action_lines": ["F2:L5"]},
    }

    bound = _schema_for(schema, guards)

    assessments = bound["properties"]["guard_assessments"]
    assert assessments["minItems"] == 2
    assert assessments["maxItems"] == 2
    assert assessments["items"]["allOf"][1]["properties"]["guard_id"]["enum"] == ["G1", "G2"]
    assert assessments["items"]["allOf"][1]["required"] == ["guard_id", "condition_blocks_path", "effective", "reason"]
    assert "allOf" not in assessments
    assert "minItems" not in schema["properties"]["guard_assessments"]
    assert schema["properties"]["guard_assessments"]["maxItems"] == 16


def test_guard_contract_keeps_required_citations() -> None:
    contract = _guard_contract({"G1": {"condition_lines": ["F1:L2"], "action_lines": ["F1:L3"], "action_blocks_sink": True}})

    assert contract == [{"guard_id": "G1", "condition_lines": ["F1:L2"], "action_lines": ["F1:L3"], "action_blocks_sink": True}]


def test_guard_packet_binds_snippets_and_expressions_from_context() -> None:
    context = {"lines": [
        {"id": "F1:L2", "text": "if (!candidate.startsWith(base)) {"},
        {"id": "F1:L3", "text": "    throw new IOException();"},
    ]}
    guards = {"G1": {
        "id": "G1", "kind": "PATH_PREFIX_CHECK",
        "condition_lines": ["F1:L2"], "action_lines": ["F1:L3"],
        "action_blocks_sink": True,
    }}

    packet = _guard_packet(context, guards)

    assert packet == [{
        "guard_id": "G1", "kind": "PATH_PREFIX_CHECK",
        "condition": [{"line_id": "F1:L2", "snippet": "if (!candidate.startsWith(base)) {"}],
        "action": [{"line_id": "F1:L3", "snippet": "    throw new IOException();"}],
        "candidate_expression": {"status": "extracted", "value": "candidate", "line_id": "F1:L2"},
        "base_expression": {"status": "extracted", "value": "base", "line_id": "F1:L2"},
        "action_blocks_sink": True,
    }]


def test_guard_packet_records_unavailable_expression_evidence() -> None:
    context = {"lines": [
        {"id": "F1:L2", "text": "if (isOutside(candidate, base)) {"},
        {"id": "F1:L3", "text": "    throw new IOException();"},
    ]}
    guards = {"G1": {
        "id": "G1", "kind": "PATH_PREFIX_CHECK",
        "condition_lines": ["F1:L2"], "action_lines": ["F1:L3"],
        "action_blocks_sink": True,
    }}

    packet = _guard_packet(context, guards)

    assert packet[0]["candidate_expression"] == {
        "status": "missing", "reason": "not_syntactically_extractable",
    }
    assert packet[0]["base_expression"] == {
        "status": "missing", "reason": "not_syntactically_extractable",
    }


def test_guard_packet_excludes_non_context_evidence_and_is_shared_by_b_and_c() -> None:
    context = {"lines": [
        {"id": "F1:L2", "text": "if (!candidate.startsWith(base)) {"},
        {"id": "F1:L3", "text": "    throw new IOException();"},
    ]}
    guards = {"G1": {
        "id": "G1", "kind": "PATH_PREFIX_CHECK",
        "condition_lines": ["F1:L2"], "action_lines": ["F1:L3"],
        "action_blocks_sink": True,
    }}
    packet = _guard_packet(context, guards)

    inference = {"temperature": 0, "num_predict": 512, "num_ctx": 3072, "keep_alive": "10m"}
    b_request = _request("prompt", {"type": "object"}, guards, packet, [], inference)
    c_request = _request("prompt", {"type": "object"}, guards, packet, ["K1"], inference)

    assert {"label", "patch", "advisory", "knowledge"}.isdisjoint(packet[0])
    assert b_request["guard_packet"] == c_request["guard_packet"] == packet
    assert b_request["retrieved_knowledge"] == []
    assert c_request["retrieved_knowledge"] == ["K1"]


def test_triage_request_records_bound_guard_ids() -> None:
    guards = {
        "G2": {"condition_lines": ["F2:L4"], "action_lines": ["F2:L5"], "action_blocks_sink": True},
        "G1": {"condition_lines": ["F1:L2"], "action_lines": ["F1:L3"], "action_blocks_sink": False},
    }
    packet = [{"guard_id": "G1", "kind": "PATH_PREFIX_CHECK"}]
    inference = {"temperature": 0, "num_predict": 512, "num_ctx": 3072, "keep_alive": "10m"}
    request = _request("prompt", {"type": "object"}, guards, packet, [], inference)

    assert request == {
        "prompt": "prompt", "schema": {"type": "object"},
        "guard_ids": ["G1", "G2"], "guard_contract": [
            {"guard_id": "G1", "condition_lines": ["F1:L2"], "action_lines": ["F1:L3"], "action_blocks_sink": False},
            {"guard_id": "G2", "condition_lines": ["F2:L4"], "action_lines": ["F2:L5"], "action_blocks_sink": True},
        ], "guard_packet": packet, "retrieved_knowledge": [],
        "inference_options": inference,
    }


def test_prompt_treats_rejection_action_as_static_control_flow() -> None:
    prompt = (Path(__file__).parents[1] / "prompts" / "triage.txt").read_text(encoding="utf-8")

    assert "static `action_blocks_sink` fact" in prompt
    assert "Do not return `action_blocks_sink`" in prompt
    assert "exception handling quality" in prompt


def test_verdict_schema_restricts_evidence_to_line_ids() -> None:
    schema = json.loads((Path(__file__).parents[1] / "schemas" / "verdict.json").read_text(encoding="utf-8"))

    references = schema["$defs"]["line_refs"]
    assert references["maxItems"] == 4
    assert references["items"]["pattern"] == "^F[1-9][0-9]*:L[1-9][0-9]*$"
    barrier = schema["$defs"]["barrier"]
    assert barrier["required"] == ["kind", "effective", "evidence_lines", "reason"]
    assert barrier["properties"]["kind"]["enum"] == ["PATH_PREFIX_CHECK", "OTHER"]
    assessment = schema["$defs"]["guard_assessment"]
    assert assessment["required"] == ["guard_id", "condition_blocks_path", "effective", "reason"]
    assert "evidence_lines" not in assessment["properties"]
    assert schema["$id"] == "verdict-v6"
