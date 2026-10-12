import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from semgrep_rules import sha256_file


class ContextError(ValueError):
    pass


@dataclass(frozen=True)
class ContextResult:
    context_count: int
    output_path: Path
    output_sha256: str


def build_contexts(
    dataset_dir: Path,
    findings_path: Path,
    output_path: Path,
    *,
    before: int = 20,
    after: int = 20,
    max_lines: int = 120,
) -> ContextResult:
    if before < 0 or after < 0 or max_lines < 1:
        raise ContextError("context bounds must be non-negative and max-lines positive")
    if output_path.exists():
        raise ContextError(f"context output already exists: {output_path}")
    dataset_dir = dataset_dir.resolve()
    findings = _read_jsonl(findings_path)
    contexts = [
        _build_context(dataset_dir, finding, before, after, max_lines)
        for finding in findings
    ]
    output_path.parent.mkdir(parents=True, exist_ok=True)
    temporary = output_path.with_suffix(output_path.suffix + ".tmp")
    try:
        temporary.write_text(
            "".join(
                json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n"
                for record in contexts
            ),
            encoding="utf-8",
        )
        temporary.replace(output_path)
    except OSError as exc:
        temporary.unlink(missing_ok=True)
        raise ContextError(f"failed to write context output: {exc}") from exc
    return ContextResult(len(contexts), output_path, sha256_file(output_path))


def validate_contexts(
    dataset_dir: Path,
    findings_path: Path,
    contexts_path: Path,
    *,
    before: int = 20,
    after: int = 20,
    max_lines: int = 120,
) -> ContextResult:
    if before < 0 or after < 0 or max_lines < 1:
        raise ContextError("context bounds must be non-negative and max-lines positive")
    dataset_dir = dataset_dir.resolve()
    findings = _read_jsonl(findings_path)
    actual = _read_jsonl(contexts_path)
    expected = [
        _build_context(dataset_dir, finding, before, after, max_lines)
        for finding in findings
    ]
    if actual != expected:
        raise ContextError("context evidence does not match normalized findings")
    return ContextResult(len(actual), contexts_path, sha256_file(contexts_path))


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise ContextError(f"failed to read findings: {exc}") from exc
    findings: list[dict[str, Any]] = []
    for index, line in enumerate(lines, 1):
        if not line.strip():
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ContextError(f"invalid finding JSON at line {index}") from exc
        if not isinstance(value, dict):
            raise ContextError(f"finding at line {index} must be an object")
        findings.append(value)
    return findings


def _build_context(
    dataset_dir: Path,
    finding: dict[str, Any],
    before: int,
    after: int,
    max_lines: int,
) -> dict[str, Any]:
    relative = finding.get("path")
    if not isinstance(relative, str) or not relative:
        raise ContextError("finding has invalid path")
    source_path = (dataset_dir / relative).resolve()
    if not source_path.is_relative_to(dataset_dir):
        raise ContextError(f"finding path is outside dataset: {relative}")
    if not source_path.is_file():
        raise ContextError(f"finding source is missing: {relative}")
    start = _line_number(finding.get("start"), "start")
    end = _line_number(finding.get("end"), "end")
    if end < start:
        raise ContextError("finding end precedes start")
    source_lines = source_path.read_text(encoding="utf-8").splitlines()
    if start > len(source_lines) or end > len(source_lines):
        raise ContextError("finding line is outside source bounds")

    context_start = max(1, start - before)
    context_end = min(len(source_lines), end + after)
    if context_end - context_start + 1 > max_lines:
        finding_lines = end - start + 1
        if finding_lines > max_lines:
            context_start = start
            context_end = start + max_lines - 1
        else:
            remaining = max_lines - finding_lines
            before_budget = min(before, remaining // 2)
            after_budget = remaining - before_budget
            context_start = max(1, start - before_budget)
            context_end = min(len(source_lines), end + after_budget)
            while context_end - context_start + 1 < max_lines and context_start > 1:
                context_start -= 1
            while context_end - context_start + 1 < max_lines and context_end < len(source_lines):
                context_end += 1

    required = {
        "candidate_id": finding.get("candidate_id"),
        "dataset_commit": finding.get("dataset_commit"),
        "rule_identity": finding.get("rule_identity"),
        "rule_id": finding.get("rule_id"),
        "rule_sha256": finding.get("rule_sha256"),
        "reviewed_cwes": finding.get("reviewed_cwes"),
    }
    if any(value is None for value in required.values()):
        raise ContextError("finding is missing provenance fields")
    return {
        **required,
        "path": relative,
        "source_sha256": sha256_file(source_path),
        "finding_start": finding["start"],
        "finding_end": finding["end"],
        "context_start_line": context_start,
        "context_end_line": context_end,
        "truncated_before": context_start > 1,
        "truncated_after": context_end < len(source_lines),
        "line_count": context_end - context_start + 1,
        "lines": [
            {"number": number, "text": source_lines[number - 1]}
            for number in range(context_start, context_end + 1)
        ],
    }


def _line_number(value: object, label: str) -> int:
    if not isinstance(value, dict):
        raise ContextError(f"finding has invalid {label} position")
    line = value.get("line")
    if not isinstance(line, int) or line < 1:
        raise ContextError(f"finding has invalid {label} line")
    return line
