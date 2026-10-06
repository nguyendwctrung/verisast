import argparse
import sys
from pathlib import Path

from owasp_audit import AuditError, EXPECTED_CWES, audit_dataset


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="verisast")
    commands = parser.add_subparsers(dest="command", required=True)

    dataset = commands.add_parser("dataset", help="Dataset workflows")
    dataset_commands = dataset.add_subparsers(dest="dataset_command", required=True)

    audit = dataset_commands.add_parser(
        "audit-owasp",
        help="Audit a frozen OWASP Benchmark Java v1.2 checkout",
    )
    audit.add_argument("--dataset", type=Path, required=True)
    audit.add_argument("--manifest", type=Path, required=True)
    audit.add_argument("--expected-commit", required=True)
    audit.set_defaults(handler=run_owasp_audit)
    return parser


def run_owasp_audit(args: argparse.Namespace) -> int:
    result = audit_dataset(
        dataset_dir=args.dataset,
        manifest_path=args.manifest,
        expected_commit=args.expected_commit,
        expected_cwes=EXPECTED_CWES,
    )
    print(f"AUDIT_STATUS={result.audit_status}")
    print(f"DATASET_ID={result.dataset_id}")
    print(f"FROZEN_COMMIT={result.frozen_commit}")
    print(f"TESTCASES={result.testcase_count}")
    print(f"JAVA_SOURCES={result.source_file_count}")
    print(f"MANIFEST={result.manifest_path}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.handler(args)
    except AuditError as error:
        print("AUDIT_STATUS=failed", file=sys.stderr)
        print(f"ERROR={error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
