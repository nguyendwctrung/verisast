import hashlib
import json
import re
import subprocess
from collections import Counter
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

import yaml

EXPECTED_REMOTE = "https://github.com/semgrep/semgrep-rules.git"
OWASP_CWES = frozenset({22, 78, 79, 89, 90, 327, 328, 330, 501, 614, 643})
CWE_PATTERN = re.compile(r"CWE-(\d+)", re.IGNORECASE)
INVENTORY_SCHEMA_VERSION = 1


class InventoryError(ValueError):
    """Raised when rule metadata or upstream provenance is invalid."""


@dataclass(frozen=True)
class RuleGitInfo:
    remote_url: str
    commit: str
    clean: bool
    detached: bool


@dataclass(frozen=True)
class RuleRecord:
    rule_id: str
    source_path: str
    source_sha256: str
    languages: tuple[str, ...]
    mode: str
    severity: str
    message: str
    category: str
    cwes: frozenset[int]
    confidence: str | None
    likelihood: str | None
    impact: str | None
    subcategory: tuple[str, ...]
    technology: tuple[str, ...]
    references: tuple[str, ...]


@dataclass(frozen=True)
class InventoryResult:
    status: str
    upstream_commit: str
    scanned_rule_count: int
    candidate_rule_count: int
    output_path: str


GitReader = Callable[[Path], RuleGitInfo]


def parse_cwes(value: object) -> frozenset[int]:
    values = value if isinstance(value, list) else [value]
    cwes: set[int] = set()
    for item in values:
        if not isinstance(item, str):
            continue
        cwes.update(int(match) for match in CWE_PATTERN.findall(item))
    return frozenset(cwes)


def load_rules(rules_dir: Path) -> list[RuleRecord]:
    java_dir = rules_dir / "java"
    if not java_dir.is_dir():
        raise InventoryError(f"Java rule directory not found: {java_dir}")

    records: list[RuleRecord] = []
    for path in sorted((*java_dir.rglob("*.yaml"), *java_dir.rglob("*.yml"))):
        relative_path = path.relative_to(rules_dir).as_posix()
        try:
            document = yaml.safe_load(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, yaml.YAMLError) as error:
            raise InventoryError(f"failed to parse {relative_path}: {error}") from error

        if not isinstance(document, dict) or "rules" not in document:
            continue
        raw_rules = document["rules"]
        if not isinstance(raw_rules, list):
            raise InventoryError(f"rules must be a list in {relative_path}")

        seen_in_file: set[str] = set()
        source_hash = sha256_file(path)
        for index, raw_rule in enumerate(raw_rules, start=1):
            if not isinstance(raw_rule, dict):
                raise InventoryError(
                    f"rule {index} must be an object in {relative_path}"
                )
            rule_id = raw_rule.get("id")
            if not isinstance(rule_id, str) or not rule_id.strip():
                raise InventoryError(f"rule {index} has no valid ID in {relative_path}")
            if rule_id in seen_in_file:
                raise InventoryError(
                    f"duplicate rule ID in {relative_path}: {rule_id}"
                )
            seen_in_file.add(rule_id)

            metadata = raw_rule.get("metadata") or {}
            if not isinstance(metadata, dict):
                raise InventoryError(
                    f"metadata must be an object for {rule_id} in {relative_path}"
                )
            category = _optional_text(metadata.get("category")) or ""
            cwes = parse_cwes(metadata.get("cwe"))
            if category == "security" and not cwes:
                raise InventoryError(
                    f"security rule has no valid CWE: {rule_id} in {relative_path}"
                )

            records.append(
                RuleRecord(
                    rule_id=rule_id,
                    source_path=relative_path,
                    source_sha256=source_hash,
                    languages=_text_tuple(raw_rule.get("languages")),
                    mode=_optional_text(raw_rule.get("mode")) or "search",
                    severity=_optional_text(raw_rule.get("severity")) or "",
                    message=_optional_text(raw_rule.get("message")) or "",
                    category=category,
                    cwes=cwes,
                    confidence=_optional_text(metadata.get("confidence")),
                    likelihood=_optional_text(metadata.get("likelihood")),
                    impact=_optional_text(metadata.get("impact")),
                    subcategory=_text_tuple(metadata.get("subcategory")),
                    technology=_text_tuple(metadata.get("technology")),
                    references=_text_tuple(metadata.get("references")),
                )
            )

    if not records:
        raise InventoryError(f"no Semgrep rules found under {java_dir}")
    return records


def read_git_info(rules_dir: Path) -> RuleGitInfo:
    def run_git(
        *args: str,
        allow_failure: bool = False,
    ) -> subprocess.CompletedProcess[str]:
        result = subprocess.run(
            ["git", "-C", str(rules_dir), *args],
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
        )
        if result.returncode != 0 and not allow_failure:
            detail = result.stderr.strip() or result.stdout.strip()
            raise InventoryError(f"Git command failed ({' '.join(args)}): {detail}")
        return result

    remote_url = run_git("remote", "get-url", "origin").stdout.strip()
    commit = run_git("rev-parse", "HEAD").stdout.strip()
    status = run_git("status", "--porcelain").stdout
    symbolic_ref = run_git("symbolic-ref", "-q", "HEAD", allow_failure=True)
    return RuleGitInfo(
        remote_url=remote_url,
        commit=commit,
        clean=not status.strip(),
        detached=symbolic_ref.returncode != 0,
    )


def inventory_rules(
    rules_dir: Path,
    output_path: Path,
    expected_cwes: set[int] | frozenset[int] = OWASP_CWES,
    git_reader: GitReader = read_git_info,
) -> InventoryResult:
    rules_dir = rules_dir.resolve()
    output_path = output_path.resolve()
    if not rules_dir.is_dir():
        raise InventoryError(f"rule directory not found: {rules_dir}")
    if output_path.is_relative_to(rules_dir):
        raise InventoryError("output must be outside the upstream rule checkout")

    git_info = git_reader(rules_dir)
    if _normalize_remote(git_info.remote_url) != _normalize_remote(EXPECTED_REMOTE):
        raise InventoryError(f"unexpected Git remote: {git_info.remote_url}")
    if not git_info.clean:
        raise InventoryError("rule working tree is not clean")
    if not git_info.detached:
        raise InventoryError("rule HEAD is not detached")

    rules = load_rules(rules_dir)
    expected = set(expected_cwes)
    java_rules = [rule for rule in rules if "java" in rule.languages]
    security_rules = [rule for rule in java_rules if rule.category == "security"]
    candidates = [rule for rule in security_rules if rule.cwes & expected]
    candidates.sort(key=lambda rule: (rule.rule_id, rule.source_path))

    counts = Counter()
    for rule in candidates:
        for cwe in rule.cwes & expected:
            counts[cwe] += 1

    report = {
        "schema_version": INVENTORY_SCHEMA_VERSION,
        "status": "passed",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "upstream_url": git_info.remote_url,
        "upstream_commit": git_info.commit,
        "working_tree_clean": git_info.clean,
        "head_detached": git_info.detached,
        "expected_cwes": sorted(expected),
        "scanned_rule_count": len(rules),
        "java_rule_count": len(java_rules),
        "java_security_rule_count": len(security_rules),
        "candidate_rule_count": len(candidates),
        "candidate_counts_by_cwe": {
            str(cwe): counts[cwe] for cwe in sorted(expected)
        },
        "execution_compatibility": "not_validated",
        "coverage_status": "not_validated",
        "rules": [_rule_to_dict(rule) for rule in candidates],
    }
    _write_json_atomic(output_path, report)

    return InventoryResult(
        status="passed",
        upstream_commit=git_info.commit,
        scanned_rule_count=len(rules),
        candidate_rule_count=len(candidates),
        output_path=str(output_path),
    )


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _rule_to_dict(rule: RuleRecord) -> dict[str, object]:
    return {
        "id": rule.rule_id,
        "source_path": rule.source_path,
        "source_sha256": rule.source_sha256,
        "languages": list(rule.languages),
        "mode": rule.mode,
        "severity": rule.severity,
        "message": rule.message,
        "category": rule.category,
        "cwes": sorted(rule.cwes),
        "confidence": rule.confidence,
        "likelihood": rule.likelihood,
        "impact": rule.impact,
        "subcategory": list(rule.subcategory),
        "technology": list(rule.technology),
        "references": list(rule.references),
        "execution_compatibility": "not_validated",
    }


def _text_tuple(value: object) -> tuple[str, ...]:
    values: Iterable[object] = value if isinstance(value, list) else [value]
    return tuple(item.strip() for item in values if isinstance(item, str) and item.strip())


def _optional_text(value: object) -> str | None:
    if isinstance(value, str) and value.strip():
        return value.strip()
    return None


def _normalize_remote(url: str) -> str:
    normalized = url.strip().rstrip("/")
    normalized = normalized.removesuffix(".git")
    return normalized.lower()


def _write_json_atomic(path: Path, payload: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary_path = path.with_suffix(path.suffix + ".tmp")
    temporary_path.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    temporary_path.replace(path)
