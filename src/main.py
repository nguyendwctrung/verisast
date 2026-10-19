import argparse
import json
import sys
from pathlib import Path

from context import build as build_context, write as write_context
from evaluate import score
from sarif import normalize, read as read_findings, write as write_findings
from scan import ScanError, run as run_scan
from triage import TriageError, run as run_triage
from units import load as load_units, write as write_units


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="verisast")
    commands = parser.add_subparsers(dest="command", required=True)
    scan = commands.add_parser("scan")
    scan.add_argument("--source", type=Path, required=True)
    scan.add_argument("--run", type=Path, required=True)
    scan.add_argument("--codeql", default="codeql")
    scan.add_argument("--suite", required=True)
    normalize_parser = commands.add_parser("normalize")
    normalize_parser.add_argument("--sarif", type=Path, required=True)
    normalize_parser.add_argument("--source-revision", required=True)
    normalize_parser.add_argument("--pack", required=True)
    normalize_parser.add_argument("--suite", required=True)
    normalize_parser.add_argument("--output", type=Path, required=True)
    context = commands.add_parser("context")
    context.add_argument("--source", type=Path, required=True)
    context.add_argument("--findings", type=Path, required=True)
    context.add_argument("--output", type=Path, required=True)
    context.add_argument("--before", type=int, default=20)
    context.add_argument("--after", type=int, default=20)
    context.add_argument("--limit", type=int, default=150)
    evaluate = commands.add_parser("evaluate")
    evaluate.add_argument("--units", type=Path, required=True)
    evaluate.add_argument("--findings", type=Path, required=True)
    evaluate.add_argument("--output", type=Path, required=True)
    units = commands.add_parser("units")
    units.add_argument("--labels", type=Path, required=True)
    units.add_argument("--output", type=Path, required=True)
    triage = commands.add_parser("triage")
    triage.add_argument("--findings", type=Path, required=True)
    triage.add_argument("--contexts", type=Path, required=True)
    triage.add_argument("--prompt", type=Path, required=True)
    triage.add_argument("--config", type=Path, required=True)
    triage.add_argument("--run", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "scan":
            result = run_scan(args.source, args.run, args.codeql, args.suite)
        elif args.command == "normalize":
            findings = normalize(args.sarif, args.source_revision, args.pack, args.suite)
            write_findings(args.output, findings)
            result = {"finding_count": len(findings), "output": str(args.output)}
        elif args.command == "context":
            contexts = build_context(args.source, read_findings(args.findings), args.before, args.after, args.limit)
            write_context(args.output, contexts)
            result = {"context_count": len(contexts), "output": str(args.output)}
        elif args.command == "evaluate":
            result = score(json.loads(args.units.read_text(encoding="utf-8")), read_findings(args.findings))
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(json.dumps(result, indent=2), encoding="utf-8")
        elif args.command == "units":
            rows = load_units(args.labels)
            write_units(args.output, rows)
            result = {"unit_count": len(rows), "output": str(args.output)}
        else:
            result = run_triage(args.findings, args.contexts, args.prompt, args.config, args.run)
    except (ScanError, TriageError, ValueError, OSError, json.JSONDecodeError) as error:
        print(f"ERROR={error}", file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
