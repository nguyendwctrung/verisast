import hashlib
import json
import re
import shutil
from datetime import datetime
from html.parser import HTMLParser
from pathlib import Path


class CorpusError(ValueError):
    pass


REQUIRED_SOURCE_FIELDS = (
    "source_id", "path", "publisher", "source_url", "source_revision_or_release",
    "retrieved_at_utc", "expected_raw_sha256", "source_locator", "license_id",
    "license_url", "copyright_notice", "license_snapshot_reference",
    "selection_reason", "title", "selected_sections",
)

REQUIRED_SECTION_FIELDS = (
    "section_path", "cwe_ids", "query_ids", "programming_languages",
)

EXTRACTOR_VERSION = "markdown-atx-sections-v1"
CHUNKER_VERSION = "corpus-v1-markdown-section"
HTML_EXTRACTOR_VERSION = "html-heading-sections-v1"

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


class _HtmlHeadingParser(HTMLParser):
    """Collect heading and visible-text events without rewriting raw HTML."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.events: list[dict[str, object]] = []
        self._heading_level: int | None = None
        self._heading_tag: str | None = None
        self._heading_line: int | None = None
        self._heading_parts: list[str] = []
        self._ignored_depth = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        lowered = tag.casefold()
        if lowered in {"script", "style"}:
            self._ignored_depth += 1
            return
        attributes = {name.casefold(): value for name, value in attrs}
        is_native_heading = re.fullmatch(r"h[1-6]", lowered) is not None
        is_mitre_heading = lowered == "div" and "heading" in (attributes.get("class") or "").split()
        if is_native_heading or is_mitre_heading:
            if self._heading_level is not None:
                raise CorpusError("malformed HTML has nested heading tags")
            self._heading_level = int(lowered[1]) if is_native_heading else 2
            self._heading_tag = lowered
            self._heading_line = self.getpos()[0]
            self._heading_parts = []

    def handle_endtag(self, tag: str) -> None:
        lowered = tag.casefold()
        if lowered in {"script", "style"}:
            self._ignored_depth = max(0, self._ignored_depth - 1)
            return
        if lowered == self._heading_tag and self._heading_level is not None:
            title = _html_text(" ".join(self._heading_parts))
            if title:
                self.events.append({
                    "kind": "heading",
                    "level": self._heading_level,
                    "title": title,
                    "source_line": self._heading_line,
                })
            self._heading_level = None
            self._heading_tag = None
            self._heading_line = None
            self._heading_parts = []

    def handle_data(self, data: str) -> None:
        if self._ignored_depth:
            return
        text = _html_text(data)
        if not text:
            return
        if self._heading_level is not None:
            self._heading_parts.append(text)
            return
        self.events.append({"kind": "text", "text": text, "source_line": self.getpos()[0]})

    def close(self) -> None:
        super().close()
        if self._heading_level is not None:
            raise CorpusError("malformed HTML has an unclosed heading tag")


def extract_html_sections(
    raw_text: str,
    selected_sections: list[dict[str, object]],
) -> list[dict[str, object]]:
    """Extract pre-registered HTML heading sections in manifest order."""
    if not isinstance(raw_text, str):
        raise CorpusError("raw HTML text must be a string")
    parser = _HtmlHeadingParser()
    try:
        parser.feed(raw_text)
        parser.close()
    except CorpusError:
        raise
    except Exception as error:
        raise CorpusError(f"invalid HTML: {error}") from error
    headings = _html_headings(parser.events)
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
        end = _html_section_end(headings, heading, len(parser.events))
        events = parser.events[int(heading["event_index"]):end]
        lines = []
        for event in events:
            if event["kind"] == "heading":
                lines.append(f"{'#' * int(event['level'])} {event['title']}")
            else:
                lines.append(str(event["text"]))
        text = "\n".join(lines).strip()
        if not text:
            raise CorpusError(f"section path is empty: {label}")
        end_line = max(int(event["source_line"]) for event in events)
        extracted.append({
            "section_path": path,
            "source_line_start": heading["source_line_start"],
            "source_line_end": end_line,
            "text": text,
        })
    return extracted


def _html_text(value: str) -> str:
    return re.sub(r"\s+", " ", value).strip()


def _html_headings(events: list[dict[str, object]]) -> list[dict[str, object]]:
    headings = []
    ancestry: list[tuple[int, str]] = []
    for index, event in enumerate(events):
        if event["kind"] != "heading":
            continue
        level = int(event["level"])
        title = str(event["title"])
        ancestry = [item for item in ancestry if item[0] < level]
        ancestry.append((level, title))
        headings.append({
            "level": level,
            "section_path": [item[1] for item in ancestry if item[0] != 1],
            "source_line_start": int(event["source_line"]),
            "event_index": index,
        })
    return headings


def _html_section_end(
    headings: list[dict[str, object]],
    selected: dict[str, object],
    event_count: int,
) -> int:
    selected_index = int(selected["event_index"])
    selected_level = int(selected["level"])
    for heading in headings:
        if int(heading["event_index"]) <= selected_index:
            continue
        if int(heading["level"]) <= selected_level:
            return int(heading["event_index"])
    return event_count


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
    corpus_version = _corpus_version(records)
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
                "reason": "raw_hash_mismatch",
                "expected_raw_sha256": record["expected_raw_sha256"],
                "actual_raw_sha256": raw_sha256,
            })
            continue
        raw_name = f"{position:03d}-{source.name}"
        shutil.copyfile(source, raw / raw_name)
        raw_text = _decode_utf8(raw_bytes, source)
        matches = _matches(_normalize_text(raw_text, source), identifiers)
        if matches:
            excluded.append({
                "source_id": source_id,
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
            "source_format": record.get("source_format", "markdown"),
            "raw_path": f"raw/{raw_name}",
            "raw_sha256": raw_sha256,
        }
        try:
            extracted_sections, extractor_version = _extract_sections(raw_text, record)
        except CorpusError as error:
            quarantined.append(_section_quarantine(source_id, error))
            continue
        selected = []
        section_matches = []
        for section, extracted in zip(record["selected_sections"], extracted_sections):
            text = _normalize_text(extracted["text"], source)
            section_match = _matches(text, identifiers)
            if section_match:
                section_matches.append({"section_path": extracted["section_path"], "matches": section_match})
                continue
            selected.append((section, extracted, text))
        if section_matches:
            excluded.append({
                "source_id": source_id,
                "reason": "prohibited_material_in_section",
                "matches": section_matches,
                "source_path": str(source.resolve()),
                "raw_sha256": raw_sha256,
            })
            continue
        accepted_sources.append(source_row)
        for section, extracted, text in selected:
            document = _document(
                record, source_row, section, extracted, text, corpus_version, extractor_version,
            )
            documents.append(document)
            chunks.append(_chunk(document))

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
        "normalizer_version": _normalizer_version(corpus_version),
        "extractor_version": _manifest_extractor_version(records),
        "chunker_version": _chunker_version(corpus_version),
        "audit_scope_sha256": _canonical_hash(audit_scope),
        "source_manifest_sha256": _hash(sources_path.read_bytes()),
        "sources_sha256": _hash((output / "sources.jsonl").read_bytes()),
        "documents_sha256": _hash((output / "documents.jsonl").read_bytes()),
        "chunks_sha256": _hash((output / "chunks.jsonl").read_bytes()),
        "excluded_sha256": _hash((output / "excluded.jsonl").read_bytes()),
        "quarantined_sha256": _hash((output / "quarantined.jsonl").read_bytes()),
        "counts": {"sources": len(accepted_sources), "documents": len(documents), "chunks": len(chunks)},
    }
    manifest["corpus_id"] = f"corpus-v{corpus_version}-{_canonical_hash(manifest)[:16]}"
    (output / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return {"corpus_id": manifest["corpus_id"], "status": status, "output": str(output), **manifest["counts"]}


def _corpus_version(records: list[object]) -> int:
    versions = {
        record.get("corpus_version", 1)
        for record in records
        if isinstance(record, dict)
    }
    if len(versions) != 1:
        raise CorpusError("source manifest records must use one corpus_version")
    version = next(iter(versions))
    if isinstance(version, bool) or not isinstance(version, int) or version < 1:
        raise CorpusError("corpus_version must be a positive integer")
    return version


def _manifest_extractor_version(records: list[object]) -> str:
    formats = {record.get("source_format", "markdown") for record in records if isinstance(record, dict)}
    versions = []
    if "markdown" in formats:
        versions.append(EXTRACTOR_VERSION)
    if "html" in formats:
        versions.append(HTML_EXTRACTOR_VERSION)
    return "+".join(versions)


def _normalizer_version(corpus_version: int) -> str:
    if corpus_version == 1:
        return "corpus-v1-markdown-section"
    return f"corpus-v{corpus_version}-section"


def _chunker_version(corpus_version: int) -> str:
    if corpus_version == 1:
        return CHUNKER_VERSION
    return f"corpus-v{corpus_version}-section"


def _extract_sections(
    raw_text: str,
    record: dict[str, object],
) -> tuple[list[dict[str, object]], str]:
    source_format = record.get("source_format", "markdown")
    if source_format == "markdown":
        return extract_markdown_sections(raw_text, record["selected_sections"]), EXTRACTOR_VERSION
    if source_format == "html":
        return extract_html_sections(raw_text, record["selected_sections"]), HTML_EXTRACTOR_VERSION
    raise CorpusError(f"unsupported source_format: {source_format}")


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
    sections = record.get("selected_sections")
    if sections not in (None, "", []) and not _valid_sections(sections):
        invalid.append("selected_sections")
    source_format = record.get("source_format", "markdown")
    if source_format not in {"markdown", "html"}:
        invalid.append("source_format")
    corpus_version = record.get("corpus_version", 1)
    if isinstance(corpus_version, bool) or not isinstance(corpus_version, int) or corpus_version < 1:
        invalid.append("corpus_version")
    return invalid


def _is_utc_timestamp(value: object) -> bool:
    if not isinstance(value, str):
        return False
    try:
        datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        return False
    return True


def _decode_utf8(raw: bytes, source: Path) -> str:
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise CorpusError(f"source is not UTF-8: {source}") from error


def _normalize_text(text: str, source: Path) -> str:
    lines = [line.strip() for line in text.replace("\r\n", "\n").replace("\r", "\n").split("\n")]
    normalized = "\n".join(lines)
    normalized = re.sub(r"\n{3,}", "\n\n", normalized).strip()
    if not normalized:
        raise CorpusError(f"source has no normalized text: {source}")
    return normalized


def _valid_sections(value: object) -> bool:
    if not isinstance(value, list) or not value:
        return False
    for section in value:
        if not isinstance(section, dict):
            return False
        if any(section.get(field) in (None, "", []) for field in REQUIRED_SECTION_FIELDS):
            return False
        try:
            _section_path(section)
        except CorpusError:
            return False
        cwe_ids = section["cwe_ids"]
        query_ids = section["query_ids"]
        languages = section["programming_languages"]
        if not isinstance(cwe_ids, list) or not all(isinstance(item, int) for item in cwe_ids):
            return False
        if not isinstance(query_ids, list) or not all(isinstance(item, str) and item.strip() for item in query_ids):
            return False
        if not isinstance(languages, list) or not all(isinstance(item, str) and item.strip() for item in languages):
            return False
    return True


def _identifiers(scope: dict[str, object]) -> list[str]:
    raw = scope.get("target_identifiers", [])
    if not isinstance(raw, list) or not all(isinstance(item, str) and item.strip() for item in raw):
        raise CorpusError("audit scope target_identifiers must be a list of non-empty strings")
    return sorted({item.casefold().strip() for item in [*DEFAULT_PROHIBITED_MARKERS, *raw]})


def _matches(text: str, identifiers: list[str]) -> list[str]:
    folded = text.casefold()
    return [identifier for identifier in identifiers if identifier in folded]


def _section_quarantine(source_id: object, error: CorpusError) -> dict[str, object]:
    message = str(error)
    for prefix, reason in (
        ("section path not found: ", "section_path_not_found"),
        ("section path is ambiguous: ", "section_path_ambiguous"),
    ):
        if message.startswith(prefix):
            return {
                "source_id": source_id,
                "reason": reason,
                "section_path": message.removeprefix(prefix).split(" > "),
            }
    return {"source_id": source_id, "reason": "section_extraction_error", "error": message}


def _document(
    record: dict[str, object],
    source: dict[str, object],
    section: dict[str, object],
    extracted: dict[str, object],
    text: str,
    corpus_version: int,
    extractor_version: str,
) -> dict[str, object]:
    section_path = extracted["section_path"]
    content_sha256 = _hash(text.encode("utf-8"))
    identity_seed = {
        "source_id": source["source_id"],
        "source_revision_or_release": source["source_revision_or_release"],
        "section_path": section_path,
    }
    document_id = f"document-v{corpus_version}:{_canonical_hash(identity_seed)}"
    version_seed = {**identity_seed, "content_sha256": content_sha256, "extractor_version": extractor_version}
    document_version_id = f"document-v{corpus_version}:{_canonical_hash(version_seed)}"
    return {
        "document_schema_version": 1,
        "document_id": document_id,
        "document_version_id": document_version_id,
        "source_id": source["source_id"],
        "title": record["title"],
        "section_path": section_path,
        "source_line_start": extracted["source_line_start"],
        "source_line_end": extracted["source_line_end"],
        "raw_source_sha256": source["raw_sha256"],
        "source_locator": record["source_locator"],
        "text": text,
        "content_sha256": content_sha256,
        "text_language": record.get("text_language", "en"),
        "programming_languages": section["programming_languages"],
        "cwe_ids": section["cwe_ids"],
        "query_ids": section["query_ids"],
        "technology_or_framework": section.get("technology_or_framework", []),
        "selection_reason": source["selection_reason"],
        "normalizer_version": _normalizer_version(corpus_version),
        "extractor_version": extractor_version,
        "leakage_status": "accepted",
        "audit_reference": "leakage-audit.json",
        "source": source,
    }


def _chunk(document: dict[str, object]) -> dict[str, object]:
    corpus_version = int(str(document["document_id"]).split(":", maxsplit=1)[0].removeprefix("document-v"))
    chunker_version = _chunker_version(corpus_version)
    seed = {"document_version_id": document["document_version_id"], "section_path": document["section_path"], "content_sha256": document["content_sha256"], "chunker_version": chunker_version}
    return {
        "chunk_schema_version": 1,
        "chunk_id": f"chunk-v{corpus_version}:{_canonical_hash(seed)}",
        "document_id": document["document_id"],
        "document_version_id": document["document_version_id"],
        "section_path": document["section_path"],
        "source_locator": document["source_locator"],
        "text": document["text"],
        "content_sha256": document["content_sha256"],
        "raw_source_sha256": document["raw_source_sha256"],
        "source_line_start": document["source_line_start"],
        "source_line_end": document["source_line_end"],
        "extractor_version": document["extractor_version"],
        "chunker_version": chunker_version,
        "source_id": document["source_id"],
        "license_id": document["source"]["license_id"],
    }


def _write_jsonl(path: Path, rows: list[dict[str, object]]) -> None:
    path.write_text("".join(json.dumps(row, sort_keys=True) + "\n" for row in rows), encoding="utf-8")


def _hash(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _canonical_hash(value: object) -> str:
    return _hash(json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8"))
