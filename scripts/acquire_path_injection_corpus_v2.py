"""Acquire a no-overwrite, official-source inventory for corpus v2."""

import argparse
import hashlib
import json
import shutil
import urllib.request
from datetime import UTC, datetime
from pathlib import Path


OWASP_COMMIT = "5f2a48abb76eea3544997eb5229e7cb8b7c275e3"
CODEQL_QUERY_RELATIVE_PATH = Path("Security/CWE/CWE-022/TaintedPath.md")
CODEQL_LICENSE_RELATIVE_PATH = Path("LICENSE.md")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--inventory", type=Path, required=True)
    parser.add_argument("--codeql-root", type=Path, required=True)
    args = parser.parse_args()
    acquire(args.inventory, args.codeql_root)
    return 0


def acquire(inventory: Path, codeql_root: Path) -> None:
    if inventory.exists():
        raise ValueError(f"inventory already exists: {inventory}")
    query = codeql_root / "qlpacks/codeql/java-queries/1.11.10" / CODEQL_QUERY_RELATIVE_PATH
    license_file = codeql_root / CODEQL_LICENSE_RELATIVE_PATH
    if not query.is_file() or not license_file.is_file():
        raise ValueError("CodeQL query or license snapshot is unavailable")
    inventory.mkdir(parents=True)
    sources = inventory / "sources"
    licenses = inventory / "licenses"
    provenance = inventory / "provenance"
    sources.mkdir()
    licenses.mkdir()
    provenance.mkdir()
    retrieved_at = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    downloaded = [
        _download(
            "https://cwe.mitre.org/data/definitions/22.html",
            sources / "mitre-cwe-22.html",
            provenance / "mitre-cwe-22.headers.json",
        ),
        _download(
            "https://docs.oracle.com/javase/tutorial/essential/io/pathOps.html",
            sources / "oracle-java-path-operations.html",
            provenance / "oracle-java-path-operations.headers.json",
        ),
        _download(
            f"https://raw.githubusercontent.com/OWASP/CheatSheetSeries/{OWASP_COMMIT}/cheatsheets/Input_Validation_Cheat_Sheet.md",
            sources / "owasp-input-validation.md",
            provenance / "owasp-input-validation.headers.json",
        ),
        _download(
            "https://cwe.mitre.org/about/termsofuse.html",
            licenses / "mitre-terms-of-use.html",
            provenance / "mitre-terms.headers.json",
        ),
        _download(
            "https://www.oracle.com/legal/terms.html",
            licenses / "oracle-terms-of-use.html",
            provenance / "oracle-terms.headers.json",
        ),
        _download(
            f"https://raw.githubusercontent.com/OWASP/CheatSheetSeries/{OWASP_COMMIT}/LICENSE.md",
            licenses / "owasp-cheatsheetseries-license.md",
            provenance / "owasp-license.headers.json",
        ),
    ]
    shutil.copyfile(query, sources / "codeql-tainted-path.md")
    shutil.copyfile(license_file, licenses / "codeql-license.md")
    (provenance / "codeql-local-source.json").write_text(json.dumps({
        "query_path": str(query),
        "query_sha256": _hash(query.read_bytes()),
        "license_path": str(license_file),
        "license_sha256": _hash(license_file.read_bytes()),
        "query_pack": "codeql/java-queries@1.11.10",
        "query_pack_build_sha": "c6baf479093fafc81d4655dc2014dc583360308e",
    }, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    records = _records(inventory, retrieved_at)
    (inventory / "sources.jsonl").write_text(
        "".join(json.dumps(record, sort_keys=True) + "\n" for record in records),
        encoding="utf-8",
    )
    (inventory / "audit-scope.json").write_text(
        json.dumps({"target_identifiers": []}, indent=2) + "\n",
        encoding="utf-8",
    )
    (inventory / "README.md").write_text(
        "# Java path injection corpus v2 inventory\n\n"
        "This inventory is an immutable official-source acquisition input. "
        "It does not establish Variant C or benchmark readiness.\n",
        encoding="utf-8",
    )
    if len(downloaded) != 6:
        raise AssertionError("all remote snapshots must be acquired")


def _download(url: str, destination: Path, provenance: Path) -> str:
    request = urllib.request.Request(url, headers={"User-Agent": "verisast-corpus-v2"})
    with urllib.request.urlopen(request, timeout=60) as response:
        content = response.read()
        headers = dict(response.headers.items())
        status = response.status
    destination.write_bytes(content)
    provenance.write_text(json.dumps({
        "url": url,
        "status": status,
        "headers": headers,
        "sha256": _hash(content),
    }, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return _hash(content)


def _records(inventory: Path, retrieved_at: str) -> list[dict[str, object]]:
    def record(
        source_id: str,
        filename: str,
        publisher: str,
        source_url: str,
        revision: str,
        locator: str,
        license_id: str,
        license_url: str,
        copyright_notice: str,
        license_snapshot: str,
        title: str,
        source_format: str,
        selected_sections: list[dict[str, object]],
    ) -> dict[str, object]:
        raw = inventory / "sources" / filename
        return {
            "corpus_version": 2,
            "source_id": source_id,
            "path": f"sources/{filename}",
            "source_format": source_format,
            "publisher": publisher,
            "source_url": source_url,
            "source_revision_or_release": revision,
            "retrieved_at_utc": retrieved_at,
            "expected_raw_sha256": _hash(raw.read_bytes()),
            "source_locator": locator,
            "license_id": license_id,
            "license_url": license_url,
            "copyright_notice": copyright_notice,
            "license_snapshot_reference": license_snapshot,
            "selection_reason": "General, official CWE-22 Java path-injection guidance without target-specific material.",
            "title": title,
            "selected_sections": selected_sections,
        }

    java_path_injection = {"cwe_ids": [22], "query_ids": ["java/path-injection"], "programming_languages": ["Java"]}
    return [
        record("mitre-cwe-22", "mitre-cwe-22.html", "MITRE", "https://cwe.mitre.org/data/definitions/22.html", "live official snapshot; see provenance/mitre-cwe-22.headers.json", "Potential Mitigations", "MITRE Terms of Use", "https://cwe.mitre.org/about/termsofuse.html", "MITRE CWE content; terms snapshot retained locally.", "licenses/mitre-terms-of-use.html", "CWE-22: Improper Limitation of a Pathname to a Restricted Directory", "html", [{"section_path": ["Potential Mitigations"], **java_path_injection}]),
        record("oracle-java-path-operations", "oracle-java-path-operations.html", "Oracle", "https://docs.oracle.com/javase/tutorial/essential/io/pathOps.html", "live official snapshot; see provenance/oracle-java-path-operations.headers.json", "Removing Redundancies From a Path; Converting a Path", "Oracle Terms of Use", "https://www.oracle.com/legal/terms.html", "Oracle Java documentation; terms snapshot retained locally.", "licenses/oracle-terms-of-use.html", "Java Tutorials: Path Operations", "html", [{"section_path": ["Removing Redundancies From a Path"], **java_path_injection}, {"section_path": ["Converting a Path"], **java_path_injection}]),
        record("owasp-input-validation", "owasp-input-validation.md", "OWASP Foundation", f"https://raw.githubusercontent.com/OWASP/CheatSheetSeries/{OWASP_COMMIT}/cheatsheets/Input_Validation_Cheat_Sheet.md", f"owasp-cheatsheetseries@{OWASP_COMMIT}", "Input Validation Strategies > Allowlist vs Denylist; Implementing Input Validation > Parse Safely, Then Validate", "CC-BY-SA-4.0", "https://creativecommons.org/licenses/by-sa/4.0/", "OWASP Cheat Sheet Series content is licensed under CC BY-SA 4.0.", "licenses/owasp-cheatsheetseries-license.md", "Input Validation Cheat Sheet", "markdown", [{"section_path": ["Input Validation Strategies", "Allowlist vs Denylist"], **java_path_injection}, {"section_path": ["Implementing Input Validation", "Parse Safely, Then Validate"], **java_path_injection}]),
        record("codeql-java-path-injection", "codeql-tainted-path.md", "GitHub", "https://codeql.github.com/codeql-query-help/java/java-path-injection/", "codeql/java-queries@1.11.10 build c6baf479093fafc81d4655dc2014dc583360308e", "Recommendation", "MIT", "https://github.com/github/codeql/blob/main/LICENSE.md", "CodeQL distribution license snapshot retained locally.", "licenses/codeql-license.md", "CodeQL Java path injection query help", "markdown", [{"section_path": ["Recommendation"], **java_path_injection}]),
    ]


def _hash(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


if __name__ == "__main__":
    raise SystemExit(main())
