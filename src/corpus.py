import hashlib
import json
import re
import shutil
from pathlib import Path


class CorpusError(ValueError):
    pass


REQUIRED_SOURCE_FIELDS = (
    "source_id", "path", "publisher", "source_url", "source_revision_or_release",
    "license_id", "license_url", "copyright_notice", "selection_reason",
    "document_id", "title", "section_path", "cwe_ids", "programming_languages",
)

DEFAULT_PROHIBITED_MARKERS = (
    "advisory", "benchmark label", "ground truth", "patch", "vulnerable revision",
    "fixed revision", "testcase answer",
)


def ingest(sources_path: Path, output: Path, audit_scope: dict[str, object]) -> dict[str, object]:
    if output.exists():
        raise CorpusError(f"output already exists: {output}")
    records = _read_jsonl(sources_path)
    if not records:
        raise CorpusError("sources manifest is empty")
    identifiers = _identifiers(audit_scope)
    output.mkdir(parents=True)
    raw = output / "raw"
    raw.mkdir()
    accepted_sources = []
    documents = []
    chunks = []
    excluded = []
    quarantined = []

    for position, record in enumerate(records, start=1):
        if not isinstance(record, dict):
            raise CorpusError(f"source manifest record {position} must be an object")
        missing = _missing_fields(record)
        source_id = record.get("source_id", f"record-{position}")
        if missing:
            quarantined.append({"source_id": source_id, "reason": "missing_required_metadata", "missing_fields": missing})
            continue
        source = _source_path(record, sources_path)
        raw_bytes = source.read_bytes()
        raw_sha256 = _hash(raw_bytes)
        raw_name = f"{position:03d}-{source.name}"
        shutil.copyfile(source, raw / raw_name)
        text = _normalize(raw_bytes, source)
        matches = _matches(text, identifiers)
        if matches:
            excluded.append({
                "source_id": source_id,
                "document_id": record["document_id"],
                "reason": "prohibited_material",
                "matches": matches,
                "source_path": str(source.resolve()),
                "raw_sha256": raw_sha256,
            })
            continue
        source_row = {
            "source_id": source_id,
            "publisher": record["publisher"],
            "source_url": record["source_url"],
            "source_revision_or_release": record["source_revision_or_release"],
            "license_id": record["license_id"],
            "license_url": record["license_url"],
            "copyright_notice": record["copyright_notice"],
            "selection_reason": record["selection_reason"],
            "raw_path": f"raw/{raw_name}",
            "raw_sha256": raw_sha256,
        }
        document = _document(record, source_row, text)
        chunk = _chunk(document)
        accepted_sources.append(source_row)
        documents.append(document)
        chunks.append(chunk)

    _write_jsonl(output / "sources.jsonl", accepted_sources)
    _write_jsonl(output / "documents.jsonl", documents)
    _write_jsonl(output / "chunks.jsonl", chunks)
    _write_jsonl(output / "excluded.jsonl", excluded)
    _write_jsonl(output / "quarantined.jsonl", quarantined)
    status = "passed" if not excluded and not quarantined else "failed"
    audit = {
        "schema_version": 1,
        "status": status,
        "target_identifiers": identifiers,
        "accepted_count": len(documents),
        "excluded_count": len(excluded),
        "quarantined_count": len(quarantined),
        "limitations": ["lexical marker and exact-content checks only; manual overlap review remains required"],
    }
    (output / "leakage-audit.json").write_text(json.dumps(audit, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    manifest = {
        "schema_version": 1,
        "status": status,
        "normalizer_version": "corpus-v1",
        "chunker_version": "corpus-v1-single-section",
        "audit_scope_sha256": _canonical_hash(audit_scope),
        "source_manifest_sha256": _hash(sources_path.read_bytes()),
        "sources_sha256": _hash((output / "sources.jsonl").read_bytes()),
        "documents_sha256": _hash((output / "documents.jsonl").read_bytes()),
        "chunks_sha256": _hash((output / "chunks.jsonl").read_bytes()),
        "excluded_sha256": _hash((output / "excluded.jsonl").read_bytes()),
        "quarantined_sha256": _hash((output / "quarantined.jsonl").read_bytes()),
        "counts": {"sources": len(accepted_sources), "documents": len(documents), "chunks": len(chunks)},
    }
    manifest["corpus_id"] = f"corpus-v1-{_canonical_hash(manifest)[:16]}"
    (output / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return {"corpus_id": manifest["corpus_id"], "status": status, "output": str(output), **manifest["counts"]}


def _read_jsonl(path: Path) -> list[object]:
    try:
        return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]
    except (OSError, json.JSONDecodeError) as error:
        raise CorpusError(f"invalid sources manifest: {error}") from error


def _source_path(record: dict[str, object], manifest: Path) -> Path:
    value = record["path"]
    if not isinstance(value, str):
        raise CorpusError("source path must be a string")
    source = Path(value)
    if not source.is_absolute():
        source = manifest.parent / source
    if not source.is_file():
        raise CorpusError(f"source file is unavailable: {source}")
    return source


def _missing_fields(record: dict[str, object]) -> list[str]:
    return [field for field in REQUIRED_SOURCE_FIELDS if record.get(field) in (None, "", [])]


def _normalize(raw: bytes, source: Path) -> str:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise CorpusError(f"source is not UTF-8: {source}") from error
    lines = [line.strip() for line in text.replace("\r\n", "\n").replace("\r", "\n").split("\n")]
    normalized = "\n".join(lines)
    normalized = re.sub(r"\n{3,}", "\n\n", normalized).strip()
    if not normalized:
        raise CorpusError(f"source has no normalized text: {source}")
    return normalized


def _identifiers(scope: dict[str, object]) -> list[str]:
    raw = scope.get("target_identifiers", [])
    if not isinstance(raw, list) or not all(isinstance(item, str) and item.strip() for item in raw):
        raise CorpusError("audit scope target_identifiers must be a list of non-empty strings")
    return sorted({item.casefold().strip() for item in [*DEFAULT_PROHIBITED_MARKERS, *raw]})


def _matches(text: str, identifiers: list[str]) -> list[str]:
    folded = text.casefold()
    return [identifier for identifier in identifiers if identifier in folded]


def _document(record: dict[str, object], source: dict[str, object], text: str) -> dict[str, object]:
    document_id = record["document_id"]
    if not isinstance(document_id, str):
        raise CorpusError("document_id must be a string")
    content_sha256 = _hash(text.encode("utf-8"))
    version_seed = {"document_id": document_id, "source_revision_or_release": source["source_revision_or_release"], "content_sha256": content_sha256}
    document_version_id = f"document-v1:{_canonical_hash(version_seed)}"
    return {
        "document_schema_version": 1,
        "document_id": document_id,
        "document_version_id": document_version_id,
        "source_id": source["source_id"],
        "title": record["title"],
        "section_path": record["section_path"],
        "source_locator": record.get("source_locator", "full_source"),
        "text": text,
        "content_sha256": content_sha256,
        "text_language": record.get("text_language", "en"),
        "programming_languages": record["programming_languages"],
        "cwe_ids": record["cwe_ids"],
        "query_ids": record.get("query_ids", []),
        "technology_or_framework": record.get("technology_or_framework", []),
        "selection_reason": source["selection_reason"],
        "normalizer_version": "corpus-v1",
        "leakage_status": "accepted",
        "audit_reference": "leakage-audit.json",
        "source": source,
    }


def _chunk(document: dict[str, object]) -> dict[str, object]:
    seed = {"document_version_id": document["document_version_id"], "section_path": document["section_path"], "content_sha256": document["content_sha256"], "chunker_version": "corpus-v1-single-section"}
    return {
        "chunk_schema_version": 1,
        "chunk_id": f"chunk-v1:{_canonical_hash(seed)}",
        "document_id": document["document_id"],
        "document_version_id": document["document_version_id"],
        "section_path": document["section_path"],
        "source_locator": document["source_locator"],
        "text": document["text"],
        "content_sha256": document["content_sha256"],
        "chunker_version": "corpus-v1-single-section",
        "source_id": document["source_id"],
        "license_id": document["source"]["license_id"],
    }


def _write_jsonl(path: Path, rows: list[dict[str, object]]) -> None:
    path.write_text("".join(json.dumps(row, sort_keys=True) + "\n" for row in rows), encoding="utf-8")


def _hash(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _canonical_hash(value: object) -> str:
    return _hash(json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8"))
