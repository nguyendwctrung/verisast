import hashlib
import json
from pathlib import Path

import pytest

from corpus import CorpusError, ingest
from main import main


def source_record(path: Path, source_id: str = "cwe") -> dict[str, object]:
    license_snapshot = path.parent / f"{source_id}-license.txt"
    license_snapshot.write_text("Creative Commons Attribution 4.0 International\n", encoding="utf-8")
    return {
        "source_id": source_id,
        "path": str(path),
        "publisher": "Example Publisher",
        "source_url": "https://example.invalid/source",
        "source_locator": "section:mitigations",
        "source_revision_or_release": "2026.1",
        "retrieved_at_utc": "2026-10-27T00:00:00Z",
        "expected_raw_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        "license_id": "CC-BY-4.0",
        "license_url": "https://creativecommons.org/licenses/by/4.0/",
        "copyright_notice": "Example Publisher",
        "license_snapshot_reference": license_snapshot.name,
        "selection_reason": "registered CWE scope",
        "title": "Path Traversal",
        "selected_sections": [{
            "section_path": ["Mitigations"],
            "cwe_ids": [22],
            "query_ids": ["java/zipslip"],
            "programming_languages": ["Java"],
        }],
    }


def write_manifest(path: Path, records: list[dict[str, object]]) -> None:
    path.write_text("".join(json.dumps(record) + "\n" for record in records), encoding="utf-8")


def read_jsonl(path: Path) -> list[dict[str, object]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]


def section_source_record(path: Path, source_id: str = "owasp") -> dict[str, object]:
    record = source_record(path, source_id)
    record["selected_sections"] = [
        {
            "section_path": ["Path Handling"],
            "cwe_ids": [22],
            "query_ids": ["java/zipslip"],
            "programming_languages": ["Java"],
        },
        {
            "section_path": ["Archive Handling"],
            "cwe_ids": [22],
            "query_ids": ["java/zipslip"],
            "programming_languages": ["Java"],
        },
    ]
    return record


def markdown_section(text: str) -> str:
    return f"# Guidance\n\n## Mitigations\n{text}"


def test_ingest_admits_each_registered_markdown_section_once(tmp_path: Path) -> None:
    source = tmp_path / "guidance.md"
    source.write_text(
        "# Guidance\n\n## Path Handling\nReject paths outside the base directory.\n"
        "\n### Nested Detail\nCanonicalize before resolving.\n\n## Archive Handling\n"
        "Validate archive entry names before extraction.\n",
        encoding="utf-8",
    )
    manifest = tmp_path / "sources.jsonl"
    write_manifest(manifest, [section_source_record(source)])

    result = ingest(manifest, tmp_path / "corpus", {"target_identifiers": []})

    output = tmp_path / "corpus"
    sources = read_jsonl(output / "sources.jsonl")
    documents = read_jsonl(output / "documents.jsonl")
    chunks = read_jsonl(output / "chunks.jsonl")
    raw_sha256 = hashlib.sha256(source.read_bytes()).hexdigest()

    assert result["status"] == "passed"
    assert result["output"] == str(output)
    assert result["sources"] == 1
    assert result["documents"] == 2
    assert result["chunks"] == 2
    assert len(sources) == 1
    assert len(list((output / "raw").iterdir())) == 1
    assert [document["section_path"] for document in documents] == [
        ["Path Handling"],
        ["Archive Handling"],
    ]
    assert [(document["source_line_start"], document["source_line_end"]) for document in documents] == [
        (3, 7),
        (9, 10),
    ]
    assert all(document["raw_source_sha256"] == raw_sha256 for document in documents)
    assert all(document["extractor_version"] == "markdown-atx-sections-v1" for document in documents)
    assert [chunk["document_id"] for chunk in chunks] == [document["document_id"] for document in documents]
    assert len({document["document_id"] for document in documents}) == 2
    assert len({chunk["chunk_id"] for chunk in chunks}) == 2


def test_ingest_quarantines_a_missing_registered_section_path(tmp_path: Path) -> None:
    source = tmp_path / "guidance.md"
    source.write_text("# Guidance\n\n## Path Handling\nReject paths outside the base directory.\n", encoding="utf-8")
    record = section_source_record(source)
    record["selected_sections"] = [{
        "section_path": ["Missing Section"],
        "cwe_ids": [22],
        "query_ids": ["java/zipslip"],
        "programming_languages": ["Java"],
    }]
    manifest = tmp_path / "sources.jsonl"
    write_manifest(manifest, [record])

    result = ingest(manifest, tmp_path / "corpus", {"target_identifiers": []})

    output = tmp_path / "corpus"
    quarantined = read_jsonl(output / "quarantined.jsonl")
    assert result["status"] == "failed"
    assert quarantined == [{
        "source_id": "owasp",
        "reason": "section_path_not_found",
        "section_path": ["Missing Section"],
    }]
    assert not read_jsonl(output / "documents.jsonl")
    assert not read_jsonl(output / "chunks.jsonl")


def test_ingest_creates_stable_documents_chunks_and_manifest(tmp_path: Path) -> None:
    source = tmp_path / "cwe.txt"
    source.write_text(markdown_section("  Validate a canonical path.\r\n\r\nReject paths outside the base.  \r\n"), encoding="utf-8")
    manifest = tmp_path / "sources.jsonl"
    write_manifest(manifest, [source_record(source)])

    output_a = tmp_path / "corpus-a"
    output_b = tmp_path / "corpus-b"
    result_a = ingest(manifest, output_a, {"target_identifiers": []})
    result_b = ingest(manifest, output_b, {"target_identifiers": []})

    document_a = read_jsonl(output_a / "documents.jsonl")[0]
    document_b = read_jsonl(output_b / "documents.jsonl")[0]
    chunk_a = read_jsonl(output_a / "chunks.jsonl")[0]
    chunk_b = read_jsonl(output_b / "chunks.jsonl")[0]
    source_a = read_jsonl(output_a / "sources.jsonl")[0]

    assert result_a["status"] == "passed"
    assert result_b["status"] == "passed"
    assert document_a["document_id"] == document_b["document_id"]
    assert document_a["document_version_id"] == document_b["document_version_id"]
    assert chunk_a["chunk_id"] == chunk_b["chunk_id"]
    assert document_a["text"] == "## Mitigations\nValidate a canonical path.\n\nReject paths outside the base."
    assert source_a["raw_sha256"] == hashlib.sha256(source.read_bytes()).hexdigest()
    assert (output_a / source_a["raw_path"]).read_bytes() == source.read_bytes()
    assert document_a["source_locator"] == "section:mitigations"
    assert source_a["expected_raw_sha256"] == source_a["raw_sha256"]
    assert (output_a / source_a["license_snapshot_reference"]).read_text(encoding="utf-8") == "Creative Commons Attribution 4.0 International\n"


def test_changed_content_changes_version_and_chunk_identity(tmp_path: Path) -> None:
    source = tmp_path / "guidance.txt"
    manifest = tmp_path / "sources.jsonl"
    source.write_text(markdown_section("Validate the canonical path."), encoding="utf-8")
    write_manifest(manifest, [source_record(source)])
    ingest(manifest, tmp_path / "corpus-a", {"target_identifiers": []})
    source.write_text(markdown_section("Validate and reject the canonical path."), encoding="utf-8")
    write_manifest(manifest, [source_record(source)])
    ingest(manifest, tmp_path / "corpus-b", {"target_identifiers": []})

    first_document = read_jsonl(tmp_path / "corpus-a" / "documents.jsonl")[0]
    second_document = read_jsonl(tmp_path / "corpus-b" / "documents.jsonl")[0]
    first_chunk = read_jsonl(tmp_path / "corpus-a" / "chunks.jsonl")[0]
    second_chunk = read_jsonl(tmp_path / "corpus-b" / "chunks.jsonl")[0]

    assert first_document["document_id"] == second_document["document_id"]
    assert first_document["document_version_id"] != second_document["document_version_id"]
    assert first_chunk["chunk_id"] != second_chunk["chunk_id"]


def test_missing_required_provenance_is_quarantined(tmp_path: Path) -> None:
    source = tmp_path / "guidance.txt"
    source.write_text(markdown_section("Use a canonical path."), encoding="utf-8")
    record = source_record(source)
    record.pop("license_id")
    manifest = tmp_path / "sources.jsonl"
    write_manifest(manifest, [record])

    result = ingest(manifest, tmp_path / "corpus", {"target_identifiers": []})

    assert result["status"] == "failed"
    quarantine = read_jsonl(tmp_path / "corpus" / "quarantined.jsonl")
    assert quarantine[0]["reason"] == "missing_required_metadata"
    assert "license_id" in quarantine[0]["missing_fields"]
    assert not (tmp_path / "corpus" / "documents.jsonl").read_text(encoding="utf-8")


@pytest.mark.parametrize("text, identifier", [
    ("Plexus Utils validates an archive entry.", "plexus utils"),
    ("Fix for CVE-2022-4244 is available.", "cve-2022-4244"),
    ("Apply this patch to correct the vulnerable revision.", "patch"),
    ("The benchmark label marks this testcase vulnerable.", "benchmark label"),
])
def test_leakage_audit_excludes_prohibited_material(tmp_path: Path, text: str, identifier: str) -> None:
    source = tmp_path / "guidance.txt"
    source.write_text(markdown_section(text), encoding="utf-8")
    manifest = tmp_path / "sources.jsonl"
    write_manifest(manifest, [source_record(source)])

    result = ingest(manifest, tmp_path / "corpus", {"target_identifiers": ["plexus utils", "cve-2022-4244"]})

    assert result["status"] == "failed"
    excluded = read_jsonl(tmp_path / "corpus" / "excluded.jsonl")
    assert identifier in excluded[0]["matches"]
    assert not (tmp_path / "corpus" / "documents.jsonl").read_text(encoding="utf-8")


def test_general_guidance_is_admitted_without_target_overlap(tmp_path: Path) -> None:
    source = tmp_path / "guidance.txt"
    source.write_text(markdown_section("Resolve the archive entry against a base directory and reject paths outside it."), encoding="utf-8")
    manifest = tmp_path / "sources.jsonl"
    write_manifest(manifest, [source_record(source, "owasp")])

    result = ingest(manifest, tmp_path / "corpus", {"target_identifiers": ["plexus utils", "cve-2022-4244"]})

    assert result["status"] == "passed"
    assert len(read_jsonl(tmp_path / "corpus" / "documents.jsonl")) == 1


@pytest.mark.parametrize("field", [
    "retrieved_at_utc",
    "expected_raw_sha256",
    "source_locator",
    "license_snapshot_reference",
])
def test_missing_freeze_readiness_metadata_is_quarantined(tmp_path: Path, field: str) -> None:
    source = tmp_path / "guidance.txt"
    source.write_text(markdown_section("Use a canonical path."), encoding="utf-8")
    record = source_record(source)
    record.pop(field)
    manifest = tmp_path / "sources.jsonl"
    write_manifest(manifest, [record])

    result = ingest(manifest, tmp_path / "corpus", {"target_identifiers": []})

    quarantine = read_jsonl(tmp_path / "corpus" / "quarantined.jsonl")
    assert result["status"] == "failed"
    assert quarantine[0]["reason"] == "missing_required_metadata"
    assert field in quarantine[0]["missing_fields"]


@pytest.mark.parametrize(("field", "value"), [
    ("retrieved_at_utc", "2026-10-27T00:00:00+07:00"),
    ("expected_raw_sha256", "not-a-sha256"),
    ("source_locator", ["Mitigations"]),
    ("license_snapshot_reference", "missing-license.txt"),
])
def test_invalid_freeze_readiness_metadata_is_quarantined(
    tmp_path: Path,
    field: str,
    value: object,
) -> None:
    source = tmp_path / "guidance.txt"
    source.write_text(markdown_section("Use a canonical path."), encoding="utf-8")
    record = source_record(source)
    record[field] = value
    manifest = tmp_path / "sources.jsonl"
    write_manifest(manifest, [record])

    result = ingest(manifest, tmp_path / "corpus", {"target_identifiers": []})

    quarantine = read_jsonl(tmp_path / "corpus" / "quarantined.jsonl")
    assert result["status"] == "failed"
    assert quarantine[0]["reason"] == "invalid_required_metadata"
    assert field in quarantine[0]["invalid_fields"]


def test_raw_hash_mismatch_is_quarantined(tmp_path: Path) -> None:
    source = tmp_path / "guidance.txt"
    source.write_text(markdown_section("Use a canonical path."), encoding="utf-8")
    record = source_record(source)
    record["expected_raw_sha256"] = "0" * 64
    manifest = tmp_path / "sources.jsonl"
    write_manifest(manifest, [record])

    result = ingest(manifest, tmp_path / "corpus", {"target_identifiers": []})

    quarantine = read_jsonl(tmp_path / "corpus" / "quarantined.jsonl")
    assert result["status"] == "failed"
    assert quarantine[0]["reason"] == "raw_hash_mismatch"
    assert quarantine[0]["expected_raw_sha256"] == "0" * 64
    assert quarantine[0]["actual_raw_sha256"] == hashlib.sha256(source.read_bytes()).hexdigest()
    assert not (tmp_path / "corpus" / "documents.jsonl").read_text(encoding="utf-8")


def test_ingest_refuses_existing_output_directory(tmp_path: Path) -> None:
    source = tmp_path / "guidance.txt"
    source.write_text(markdown_section("Use a canonical path."), encoding="utf-8")
    manifest = tmp_path / "sources.jsonl"
    write_manifest(manifest, [source_record(source)])
    output = tmp_path / "corpus"
    ingest(manifest, output, {"target_identifiers": []})

    with pytest.raises(CorpusError, match="output already exists"):
        ingest(manifest, output, {"target_identifiers": []})


def test_cli_corpus_dispatches_ingestion(tmp_path: Path) -> None:
    source = tmp_path / "guidance.txt"
    source.write_text(markdown_section("Use a canonical path."), encoding="utf-8")
    sources = tmp_path / "sources.jsonl"
    scope = tmp_path / "scope.json"
    output = tmp_path / "corpus"
    write_manifest(sources, [source_record(source)])
    scope.write_text(json.dumps({"target_identifiers": []}), encoding="utf-8")

    status = main(["corpus", "--sources", str(sources), "--audit-scope", str(scope), "--output", str(output)])

    assert status == 0
    assert json.loads((output / "manifest.json").read_text(encoding="utf-8"))["status"] == "passed"
