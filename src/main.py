import argparse
import json
import sys
from pathlib import Path

from corpus import CorpusError, ingest
from context import build as build_context, write as write_context
from evaluate import score
from retrieval_evaluate import EvaluationError, run as run_retrieval_evaluation
from sarif import normalize, read as read_findings, write as write_findings
from scan import ScanError, run as run_scan
from triage import TriageError, run_paired, validate_paired_config
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
    triage.add_argument("--variant", choices=("B", "C"), default="B")
    triage.add_argument("--retrieval-contract", type=Path)

    corpus = commands.add_parser("corpus")
    corpus.add_argument("--sources", type=Path, required=True)
    corpus.add_argument("--audit-scope", type=Path, required=True)
    corpus.add_argument("--output", type=Path, required=True)

    retrieval = commands.add_parser("retrieval")
    retrieval_commands = retrieval.add_subparsers(dest="retrieval_command", required=True)
    retrieval_evaluate = retrieval_commands.add_parser("evaluate")
    retrieval_evaluate.add_argument("--protocol", type=Path, required=True)
    retrieval_evaluate.add_argument("--run", type=Path, required=True)

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
        elif args.command == "corpus":
            audit_scope = json.loads(args.audit_scope.read_text(encoding="utf-8"))
            if not isinstance(audit_scope, dict):
                raise CorpusError("audit scope must be an object")
            result = ingest(args.sources, args.output, audit_scope)
        elif args.command == "retrieval":
            result = run_retrieval_evaluation(args.protocol, args.run)
        else:
            if args.variant == "B" and args.retrieval_contract is not None:
                raise TriageError("B does not accept a retrieval contract")
            if args.variant == "C" and args.retrieval_contract is None:
                raise TriageError("C requires --retrieval-contract")
            validate_paired_config(args.config)
            result = run_paired(
                args.findings, args.contexts, args.prompt, args.config, args.run,
                args.variant, retrieval_contract_path=args.retrieval_contract,
            )
    except (CorpusError, EvaluationError, ScanError, TriageError, ValueError, OSError, json.JSONDecodeError) as error:
        print(f"ERROR={error}", file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
