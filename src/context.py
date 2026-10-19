import hashlib
from pathlib import Path


class ContextError(ValueError):
    pass


def build(source: Path, findings: list[dict[str, object]], before: int = 20, after: int = 20, limit: int = 150) -> list[dict[str, object]]:
    source = source.resolve()
    if limit < 1:
        raise ContextError("context limit must be positive")
    contexts = []
    for finding in findings:
        path = finding.get("path")
        start = finding.get("start")
        end = finding.get("end")
        if not isinstance(path, str) or not isinstance(start, int) or not isinstance(end, int):
            raise ContextError("finding lacks a valid location")
        windows = [(path, start, end)]
        for step in finding.get("flow", []):
            if isinstance(step, dict) and isinstance(step.get("path"), str) and isinstance(step.get("line"), int):
                windows.append((step["path"], step["line"], step["line"]))
        files: dict[str, tuple[Path, list[str], list[tuple[int, int]]]] = {}
        for flow_path, first, last in windows:
            file = (source / flow_path).resolve()
            if not file.is_relative_to(source) or not file.is_file():
                raise ContextError(f"finding path is outside source: {flow_path}")
            if flow_path not in files:
                files[flow_path] = (file, file.read_text(encoding="utf-8").splitlines(), [])
            content = files[flow_path][1]
            files[flow_path][2].append((max(1, first - before), min(len(content), last + after)))
        lines = []
        truncated = False
        for file_number, (_, content, ranges) in enumerate(files.values(), start=1):
            for first, last in _merge(ranges):
                for number in range(first, last + 1):
                    if len(lines) == limit:
                        truncated = True
                        break
                    lines.append({"id": f"F{file_number}:L{number}", "number": number, "text": content[number - 1]})
                if truncated:
                    break
            if truncated:
                break
        primary = files[path][0]
        contexts.append({"candidate_id": finding["id"], "path": path, "source_sha256": hashlib.sha256(primary.read_bytes()).hexdigest(), "focus": {"start": start, "end": end}, "flow": finding.get("flow", []), "lines": lines, "truncated": truncated, "missing_evidence": []})
    return contexts


def _merge(ranges: list[tuple[int, int]]) -> list[tuple[int, int]]:
    merged = []
    for first, last in sorted(ranges):
        if merged and first <= merged[-1][1] + 1:
            merged[-1] = (merged[-1][0], max(merged[-1][1], last))
        else:
            merged.append((first, last))
    return merged


def write(path: Path, contexts: list[dict[str, object]]) -> None:
    if path.exists():
        raise ContextError(f"output already exists: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    import json
    path.write_text("".join(json.dumps(item, sort_keys=True) + "\n" for item in contexts), encoding="utf-8")


def read(path: Path) -> dict[str, dict[str, object]]:
    import json
    return {item["candidate_id"]: item for item in [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]}

