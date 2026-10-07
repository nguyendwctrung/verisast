import argparse
import sys
from pathlib import Path

from owasp_audit import EXPECTED_CWES, AuditError, audit_dataset
from semgrep_rules import InventoryError, inventory_rules


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

    rules = commands.add_parser("rules", help="Rule workflows")
    rule_commands = rules.add_subparsers(dest="rule_command", required=True)

    inventory = rule_commands.add_parser(
        "inventory-semgrep",
        help="Inventory Semgrep CE Java security rules for OWASP CWEs",
    )
    inventory.add_argument("--rules", type=Path, required=True)
    inventory.add_argument("--output", type=Path, required=True)
    inventory.set_defaults(handler=run_semgrep_inventory)
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


def run_semgrep_inventory(args: argparse.Namespace) -> int:
    result = inventory_rules(
        rules_dir=args.rules,
        output_path=args.output,
    )
    print(f"INVENTORY_STATUS={result.status}")
    print(f"UPSTREAM_COMMIT={result.upstream_commit}")
    print(f"SCANNED_RULES={result.scanned_rule_count}")
    print(f"CANDIDATE_RULES={result.candidate_rule_count}")
    print(f"OUTPUT={result.output_path}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.handler(args)
    except (AuditError, InventoryError) as error:
        status = (
            "INVENTORY_STATUS=failed"
            if getattr(args, "rule_command", None)
            else "AUDIT_STATUS=failed"
        )
        print(status, file=sys.stderr)
        print(f"ERROR={error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
