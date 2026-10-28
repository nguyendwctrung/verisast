import hashlib
import json
import re
import shutil
from datetime import datetime
from pathlib import Path


class CorpusError(ValueError):
    pass


REQUIRED_SOURCE_FIELDS = (
    "source_id", "path", "publisher", "source_url", "source_revision_or_release",
    "retrieved_at_utc", "expected_raw_sha256", "source_locator", "license_id",
    "license_url", "copyright_notice", "license_snapshot_reference",
    "selection_reason", "document_id", "title", "section_path", "cwe_ids",
    "programming_languages",
)

DEFAULT_PROHIBITED_MARKERS = (
    "advisory", "benchmark label", "ground truth", "patch", "vulnerable revision",
    "fixed revision", "testcase answer",
)


def extract_markdown_sections(
    raw_text: str,
    selected_sections: list[dict[str, object]],
) -> list[dict[str, object]]:
    """Extract pre-registered ATX Markdown sections in manifest order.

    The document-level H1 is treated as a title rather than part of an
    admission path. Each selected path must resolve to exactly one heading.
    """
    if not isinstance(raw_text, str):
        raise CorpusError("raw Markdown text must be a string")
    lines = raw_text.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    headings = _markdown_headings(lines)
    extracted = []
    for section in selected_sections:
        path = _section_path(section)
        matches = [heading for heading in headings if heading["section_path"] == path]
        label = " > ".join(path)
        if not matches:
            raise CorpusError(f"section path not found: {label}")
        if len(matches) > 1:
            raise CorpusError(f"section path is ambiguous: {label}")
        heading = matches[0]
        start = heading["source_line_start"]
        end = _section_end(headings, heading, len(lines))
        while end >= start and not lines[end - 1].strip():
            end -= 1
        extracted.append({
            "section_path": path,
            "source_line_start": start,
            "source_line_end": end,
            "text": "\n".join(lines[start - 1:end]).rstrip(),
        })
    return extracted


def _markdown_headings(lines: list[str]) -> list[dict[str, object]]:
    headings = []
    ancestry: list[tuple[int, str]] = []
    pattern = re.compile(r"^[ ]{0,3}(#{1,6})[ \t]+(.+?)[ \t]*#*[ \t]*$")
    for line_number, line in enumerate(lines, start=1):
        match = pattern.match(line)
        if match is None:
            continue
        level = len(match.group(1))
        title = match.group(2).strip()
        if not title:
            continue
        ancestry = [item for item in ancestry if item[0] < level]
        ancestry.append((level, title))
        headings.append({
            "level": level,
            "section_path": [item[1] for item in ancestry if item[0] != 1],
            "source_line_start": line_number,
        })
    return headings


def _section_path(section: dict[str, object]) -> list[str]:
    path = section.get("section_path") if isinstance(section, dict) else None
    if not isinstance(path, list) or not path or not all(
        isinstance(item, str) and item.strip() for item in path
    ):
        raise CorpusError("section_path must be a non-empty list of non-empty strings")
    return path


def _section_end(
    headings: list[dict[str, object]],
    selected: dict[str, object],
    line_count: int,
) -> int:
    selected_start = selected["source_line_start"]
    selected_level = selected["level"]
    for heading in headings:
        if heading["source_line_start"] <= selected_start:
            continue
        if heading["level"] <= selected_level:
            return heading["source_line_start"] - 1
    return line_count


def ingest(sources_path: Path, output: Path, audit_scope: dict[str, object]) -> dict[str, object]:
    if output.exists():
        raise CorpusError(f"output already exists: {output}")
    records = _read_jsonl(sources_path)
    if not records:
        raise CorpusError("sources manifest is empty")
    identifiers = _identifiers(audit_scope)
    output.mkdir(parents=True)
    raw = output / "raw"
    licenses = output / "licenses"
    raw.mkdir()
    licenses.mkdir()
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
        invalid = _invalid_fields(record, sources_path)
        if missing or invalid:
            quarantined.append({
                "source_id": source_id,
                "reason": "missing_required_metadata" if missing else "invalid_required_metadata",
                "missing_fields": missing,
                "invalid_fields": invalid,
            })
            continue
        source = _source_path(record, sources_path)
        raw_bytes = source.read_bytes()
        raw_sha256 = _hash(raw_bytes)
        if raw_sha256 != record["expected_raw_sha256"]:
            quarantined.append({
                "source_id": source_id,
                "document_id": record["document_id"],
                "reason": "raw_hash_mismatch",
                "expected_raw_sha256": record["expected_raw_sha256"],
                "actual_raw_sha256": raw_sha256,
            })
            continue
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
        license_snapshot = _license_snapshot_path(record, sources_path)
        license_name = f"{position:03d}-{license_snapshot.name}"
        copied_license = licenses / license_name
        shutil.copyfile(license_snapshot, copied_license)
        source_row = {
            "source_id": source_id,
            "publisher": record["publisher"],
            "source_url": record["source_url"],
            "source_locator": record["source_locator"],
            "source_revision_or_release": record["source_revision_or_release"],
            "retrieved_at_utc": record["retrieved_at_utc"],
            "expected_raw_sha256": record["expected_raw_sha256"],
            "license_id": record["license_id"],
            "license_url": record["license_url"],
            "copyright_notice": record["copyright_notice"],
            "license_snapshot_reference": f"licenses/{license_name}",
            "license_snapshot_sha256": _hash(copied_license.read_bytes()),
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


def _license_snapshot_path(record: dict[str, object], manifest: Path) -> Path:
    value = record["license_snapshot_reference"]
    if not isinstance(value, str) or not value.strip():
        raise CorpusError("license_snapshot_reference must be a non-empty string")
    reference = Path(value)
    if reference.is_absolute():
        raise CorpusError("license_snapshot_reference must be relative to the sources manifest")
    root = manifest.parent.resolve()
    snapshot = (root / reference).resolve()
    if root not in snapshot.parents or not snapshot.is_file():
        raise CorpusError("license_snapshot_reference must identify an available local file")
    return snapshot


def _missing_fields(record: dict[str, object]) -> list[str]:
    return [field for field in REQUIRED_SOURCE_FIELDS if record.get(field) in (None, "", [])]


def _invalid_fields(record: dict[str, object], manifest: Path) -> list[str]:
    invalid = []
    timestamp = record.get("retrieved_at_utc")
    if timestamp not in (None, "", []) and not _is_utc_timestamp(timestamp):
        invalid.append("retrieved_at_utc")
    expected_hash = record.get("expected_raw_sha256")
    if expected_hash not in (None, "", []) and (
        not isinstance(expected_hash, str)
        or re.fullmatch(r"[0-9a-f]{64}", expected_hash) is None
    ):
        invalid.append("expected_raw_sha256")
    locator = record.get("source_locator")
    if locator not in (None, "", []) and (
        not isinstance(locator, str) or not locator.strip()
    ):
        invalid.append("source_locator")
    license_reference = record.get("license_snapshot_reference")
    if license_reference not in (None, "", []):
        try:
            _license_snapshot_path(record, manifest)
        except CorpusError:
            invalid.append("license_snapshot_reference")
    return invalid


def _is_utc_timestamp(value: object) -> bool:
    if not isinstance(value, str):
        return False
    try:
        datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        return False
    return True


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
        "source_locator": record["source_locator"],
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
