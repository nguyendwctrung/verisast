import argparse
import sys
from pathlib import Path

from baseline import (
    BaselineError,
    BaselineResult,
    run_owasp_baseline,
    validate_baseline_run,
)
from owasp_audit import EXPECTED_CWES, AuditError, audit_dataset
from owasp_cohort import CohortError, build_cohort
from semgrep_checkpoint import CheckpointError, CheckpointResult, validate_checkpoint
from semgrep_composite_smoke import CompositeSmokeError
from semgrep_compat import CompatError, validate_rules
from semgrep_controls import ControlError, validate_controls
from semgrep_fixtures import FixtureError, validate_fixtures
from semgrep_review import ReviewError, ReviewResult, init_review, validate_review
from semgrep_rules import InventoryError, inventory_rules
from semgrep_ruleset import RulesetError, build_composite_ruleset, build_ruleset
from source_context import ContextError, build_contexts, validate_contexts


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

    cohort = dataset_commands.add_parser(
        "build-owasp-cohort",
        help="Build a provenance-bound OWASP evaluation cohort",
    )
    cohort.add_argument("--dataset", type=Path, required=True)
    cohort.add_argument("--dataset-manifest", type=Path, required=True)
    cohort.add_argument("--ruleset", type=Path, required=True)
    cohort.add_argument("--output", type=Path, required=True)
    cohort.add_argument("--purpose", choices=("development", "reportable"), required=True)
    cohort.set_defaults(handler=run_owasp_cohort_build)

    rules = commands.add_parser("rules", help="Rule workflows")
    rule_commands = rules.add_subparsers(dest="rule_command", required=True)

    inventory = rule_commands.add_parser(
        "inventory-semgrep",
        help="Inventory Semgrep CE Java security rules for OWASP CWEs",
    )
    inventory.add_argument("--rules", type=Path, required=True)
    inventory.add_argument("--output", type=Path, required=True)
    inventory.set_defaults(handler=run_semgrep_inventory)

    compatibility = rule_commands.add_parser(
        "validate-semgrep",
        help="Validate inventoried rules with a pinned Semgrep CE version",
    )

    compatibility.add_argument("--rules", type=Path, required=True)
    compatibility.add_argument("--inventory", type=Path, required=True)
    compatibility.add_argument("--run-dir", type=Path, required=True)
    compatibility.add_argument("--semgrep", required=True)
    compatibility.add_argument("--expected-version", required=True)
    compatibility.set_defaults(handler=run_semgrep_compatibility)

    fixtures = rule_commands.add_parser(
        "validate-fixtures",
        help="Run pinned upstream Semgrep rule fixtures",
    )
    fixtures.add_argument("--rules", type=Path, required=True)
    fixtures.add_argument("--inventory", type=Path, required=True)
    fixtures.add_argument("--run-dir", type=Path, required=True)
    fixtures.add_argument("--semgrep", required=True)
    fixtures.add_argument("--expected-version", required=True)
    fixtures.set_defaults(handler=run_semgrep_fixtures)

    controls = rule_commands.add_parser(
        "validate-controls",
        help="Validate hash-pinned independent negative controls",
    )
    controls.add_argument("--project-root", type=Path, required=True)
    controls.add_argument("--rules", type=Path, required=True)
    controls.add_argument("--manifest", type=Path, required=True)
    controls.add_argument("--run-dir", type=Path, required=True)
    controls.add_argument("--semgrep", required=True)
    controls.add_argument("--expected-version", required=True)
    controls.set_defaults(handler=run_semgrep_controls)

    init_rule_review = rule_commands.add_parser(
        "init-review",
        help="Create a manual review worksheet from the rule inventory",
    )
    init_rule_review.add_argument("--inventory", type=Path, required=True)
    init_rule_review.add_argument("--output", type=Path, required=True)
    init_rule_review.set_defaults(handler=run_semgrep_review_init)

    validate_rule_review = rule_commands.add_parser(
        "validate-review",
        help="Validate and summarize a Semgrep rule review worksheet",
    )
    validate_rule_review.add_argument("--inventory", type=Path, required=True)
    validate_rule_review.add_argument("--review", type=Path, required=True)
    validate_rule_review.set_defaults(handler=run_semgrep_review_validation)

    validate_checkpoint_parser = rule_commands.add_parser(
        "validate-checkpoint",
        help="Validate a completed CWE rule-review checkpoint",
    )
    validate_checkpoint_parser.add_argument("--cwe", type=int, required=True)
    validate_checkpoint_parser.add_argument("--dataset", type=Path, required=True)
    validate_checkpoint_parser.add_argument("--review", type=Path, required=True)
    validate_checkpoint_parser.add_argument("--fixtures", type=Path, required=True)
    validate_checkpoint_parser.add_argument(
        "--compatibility", type=Path, required=True
    )
    validate_checkpoint_parser.set_defaults(handler=run_semgrep_checkpoint)

    catalog = rule_commands.add_parser(
        "build-catalog",
        help="Build an immutable composite catalog of upstream and project rules",
    )
    catalog.add_argument("--upstream-inventory", type=Path, required=True)
    catalog.add_argument("--project-manifest", type=Path, required=True)
    catalog.add_argument("--project-root", type=Path, required=True)
    catalog.add_argument("--output", type=Path, required=True)
    catalog.set_defaults(
        handler=lambda args: __import__("semgrep_catalog").run_catalog_command(args)
    )

    composite_ruleset = rule_commands.add_parser(
        "build-composite-ruleset",
        help="Build a composite Semgrep ruleset snapshot",
    )
    composite_ruleset.add_argument("--upstream-rules", type=Path, required=True)
    composite_ruleset.add_argument("--project-root", type=Path, required=True)
    composite_ruleset.add_argument("--catalog", type=Path, required=True)
    composite_ruleset.add_argument("--review", type=Path, required=True)
    composite_ruleset.add_argument("--output", type=Path, required=True)
    composite_ruleset.add_argument(
        "--purpose", choices=("development", "reportable"), required=True
    )
    composite_ruleset.set_defaults(handler=run_composite_ruleset_build)

    composite_smoke = rule_commands.add_parser(
        "run-composite-smoke",
        help="Run a bounded composite Semgrep smoke scan",
    )
    composite_smoke.add_argument("--run-id", required=True)
    composite_smoke.add_argument("--upstream-rules", type=Path, required=True)
    composite_smoke.add_argument("--project-root", type=Path, required=True)
    composite_smoke.add_argument("--catalog", type=Path, required=True)
    composite_smoke.add_argument("--review", type=Path, required=True)
    composite_smoke.add_argument("--ruleset", type=Path, required=True)
    composite_smoke.add_argument("--source-root", type=Path, required=True)
    composite_smoke.add_argument("--run-dir", type=Path, required=True)
    composite_smoke.add_argument("--semgrep", required=True)
    composite_smoke.add_argument("--expected-version", required=True)
    composite_smoke.set_defaults(
        handler=lambda args: __import__("semgrep_composite_smoke").run_composite_smoke_command(args)
    )

    context = commands.add_parser("context", help="Source-context workflows")
    context_commands = context.add_subparsers(dest="context_command", required=True)
    build_context = context_commands.add_parser(
        "build", help="Build bounded source contexts for normalized findings"
    )
    build_context.add_argument("--dataset", type=Path, required=True)
    build_context.add_argument("--findings", type=Path, required=True)
    build_context.add_argument("--output", type=Path, required=True)
    build_context.add_argument("--before", type=int, default=20)
    build_context.add_argument("--after", type=int, default=20)
    build_context.add_argument("--max-lines", type=int, default=120)
    build_context.set_defaults(handler=run_source_context_build)
    validate_context = context_commands.add_parser(
        "validate", help="Validate bounded source-context evidence"
    )
    validate_context.add_argument("--dataset", type=Path, required=True)
    validate_context.add_argument("--findings", type=Path, required=True)
    validate_context.add_argument("--contexts", type=Path, required=True)
    validate_context.add_argument("--before", type=int, default=20)
    validate_context.add_argument("--after", type=int, default=20)
    validate_context.add_argument("--max-lines", type=int, default=120)
    validate_context.set_defaults(handler=run_source_context_validation)

    build_rule_snapshot = rule_commands.add_parser(
        "build-ruleset",
        help="Build a reviewed Semgrep ruleset snapshot",
    )
    build_rule_snapshot.add_argument("--rules", type=Path, required=True)
    build_rule_snapshot.add_argument("--inventory", type=Path, required=True)
    build_rule_snapshot.add_argument("--review", type=Path, required=True)
    build_rule_snapshot.add_argument("--output", type=Path, required=True)
    build_rule_snapshot.add_argument("--purpose", choices=("development", "reportable"), required=True)
    build_rule_snapshot.set_defaults(handler=run_semgrep_ruleset_build)

    baseline = commands.add_parser("baseline", help="Semgrep baseline workflows")
    baseline_commands = baseline.add_subparsers(dest="baseline_command", required=True)
    run_baseline = baseline_commands.add_parser("run-owasp", help="Run the OWASP Semgrep baseline")
    run_baseline.add_argument("--run-id", required=True)
    run_baseline.add_argument("--purpose", choices=("development", "reportable"), required=True)
    run_baseline.add_argument("--dataset", type=Path, required=True)
    run_baseline.add_argument("--dataset-manifest", type=Path, required=True)
    run_baseline.add_argument("--rules", type=Path, required=True)
    run_baseline.add_argument("--project-root", type=Path)
    run_baseline.add_argument("--ruleset", type=Path, required=True)
    run_baseline.add_argument("--cohort", type=Path, required=True)
    run_baseline.add_argument("--run-dir", type=Path, required=True)
    run_baseline.add_argument("--semgrep", required=True)
    run_baseline.add_argument("--expected-version", required=True)
    run_baseline.set_defaults(handler=run_baseline_owasp)

    validate_baseline = baseline_commands.add_parser("validate-run", help="Validate an OWASP baseline run")
    validate_baseline.add_argument("--run-dir", type=Path, required=True)
    validate_baseline.add_argument("--dataset", type=Path, required=True)
    validate_baseline.add_argument("--dataset-manifest", type=Path, required=True)
    validate_baseline.add_argument("--rules", type=Path, required=True)
    validate_baseline.add_argument("--project-root", type=Path)
    validate_baseline.set_defaults(handler=run_baseline_validation)

    return parser


def run_owasp_cohort_build(args: argparse.Namespace) -> int:
    result = build_cohort(
        dataset_dir=args.dataset,
        dataset_manifest_path=args.dataset_manifest,
        ruleset_path=args.ruleset,
        output_path=args.output,
        purpose=args.purpose,
    )
    print(f"COHORT_STATUS={result.status}")
    print(f"COHORT_PURPOSE={result.purpose}")
    print(f"COHORT_REPORTABLE={str(result.reportable).lower()}")
    print(f"COHORT_UNITS={result.unit_count}")
    print(f"COHORT_CWES={','.join(str(cwe) for cwe in result.cwes)}")
    print(f"COHORT={result.output_path}")
    return 0


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


def run_semgrep_compatibility(args: argparse.Namespace) -> int:
    result = validate_rules(
        rules_dir=args.rules,
        inventory_path=args.inventory,
        run_dir=args.run_dir,
        semgrep_executable=args.semgrep,
        expected_version=args.expected_version,
    )
    print(f"COMPAT_STATUS={result.status}")
    print(f"SEMGREP_VERSION={result.semgrep_version}")
    print(f"UPSTREAM_COMMIT={result.upstream_commit}")
    print(f"RULE_FILES={result.file_count}")
    print(f"COMPATIBLE={result.compatible_count}")
    print(f"INCOMPATIBLE={result.incompatible_count}")
    print(f"REQUIRES_PRO={result.requires_pro_count}")
    print(f"ERRORS={result.error_count}")
    print(f"REPORT={result.report_path}")

    return 0


def run_semgrep_fixtures(args: argparse.Namespace) -> int:
    result = validate_fixtures(
        rules_dir=args.rules,
        inventory_path=args.inventory,
        run_dir=args.run_dir,
        semgrep_executable=args.semgrep,
        expected_version=args.expected_version,
    )
    print(f"FIXTURE_STATUS={result.status}")
    print(f"SEMGREP_VERSION={result.semgrep_version}")
    print(f"UPSTREAM_COMMIT={result.upstream_commit}")
    print(f"RULE_FILES={result.file_count}")
    print(f"PASSED={result.pass_count}")
    print(f"FAILED={result.fail_count}")
    print(f"ERRORS={result.error_count}")
    print(
        "COMPLETE_ANNOTATIONS="
        f"{result.complete_annotation_count}"
    )
    print(
        "INCOMPLETE_ANNOTATIONS="
        f"{result.incomplete_annotation_count}"
    )
    print(f"REPORT={result.report_path}")

    return 0


def run_semgrep_controls(args: argparse.Namespace) -> int:
    result = validate_controls(
        project_root=args.project_root,
        rules_dir=args.rules,
        manifest_path=args.manifest,
        run_dir=args.run_dir,
        semgrep_executable=args.semgrep,
        expected_version=args.expected_version,
    )
    print(f"CONTROL_STATUS={result.status}")
    print(f"SEMGREP_VERSION={result.semgrep_version}")
    print(f"UPSTREAM_COMMIT={result.upstream_commit}")
    print(f"CONTROLS={result.control_count}")
    print(f"PASSED={result.pass_count}")
    print(f"FALSE_POSITIVES={result.false_positive_count}")
    print(f"ERRORS={result.error_count}")
    print(f"REPORT={result.report_path}")

    return int(result.false_positive_count > 0 or result.error_count > 0)


def run_semgrep_review_init(args: argparse.Namespace) -> int:
    result = init_review(
        inventory_path=args.inventory,
        output_path=args.output,
    )
    return print_semgrep_review(result)


def run_semgrep_review_validation(args: argparse.Namespace) -> int:
    result = validate_review(
        inventory_path=args.inventory,
        review_path=args.review,
    )
    return print_semgrep_review(result)


def print_semgrep_review(result: ReviewResult) -> int:
    print(f"REVIEW_STATUS={result.status}")
    print(f"UPSTREAM_COMMIT={result.upstream_commit}")
    print(f"RULES={result.review_count}")
    print(f"INCLUDE_DEVELOPMENT={result.include_count}")
    print(f"EXCLUDE={result.exclude_count}")
    print(f"NEEDS_EVIDENCE={result.needs_evidence_count}")
    for cwe, count in result.include_counts_by_cwe.items():
        print(f"CWE_{cwe}_INCLUDE={count}")
    print(f"REVIEW={result.review_path}")
    return 0


def run_semgrep_ruleset_build(args: argparse.Namespace) -> int:
    result = build_ruleset(
        rules_dir=args.rules,
        inventory_path=args.inventory,
        review_path=args.review,
        output_path=args.output,
        purpose=args.purpose,
    )
    print(f"RULESET_STATUS={result.status}")
    print(f"RULESET_PURPOSE={result.purpose}")
    print(f"RULESET_REPORTABLE={str(result.reportable).lower()}")
    print(f"RULESET_RULES={result.rule_count}")
    print(f"RULESET_UNRESOLVED={result.unresolved_count}")
    print(f"RULESET={result.output_path}")
    return 0


def run_composite_ruleset_build(args: argparse.Namespace) -> int:
    result = build_composite_ruleset(
        upstream_rules_dir=args.upstream_rules,
        project_root=args.project_root,
        catalog_path=args.catalog,
        review_path=args.review,
        output_path=args.output,
        purpose=args.purpose,
    )
    print(f"RULESET_STATUS={result.status}")
    print(f"RULESET_PURPOSE={result.purpose}")
    print(f"RULESET_REPORTABLE={str(result.reportable).lower()}")
    print(f"RULESET_RULES={result.rule_count}")
    print(f"RULESET_UNRESOLVED={result.unresolved_count}")
    print(f"RULESET={result.output_path}")
    return 0


def run_baseline_owasp(args: argparse.Namespace) -> int:
    result = run_owasp_baseline(
        run_id=args.run_id,
        purpose=args.purpose,
        dataset_dir=args.dataset,
        dataset_manifest_path=args.dataset_manifest,
        rules_dir=args.rules,
        project_root=args.project_root,
        ruleset_path=args.ruleset,
        cohort_path=args.cohort,
        run_dir=args.run_dir,
        semgrep_executable=args.semgrep,
        expected_version=args.expected_version,
    )
    return print_baseline(result)


def run_baseline_validation(args: argparse.Namespace) -> int:
    result = validate_baseline_run(
        run_dir=args.run_dir,
        dataset_dir=args.dataset,
        dataset_manifest_path=args.dataset_manifest,
        rules_dir=args.rules,
        project_root=args.project_root,
    )
    return print_baseline(result)


def run_semgrep_checkpoint(args: argparse.Namespace) -> int:
    result = validate_checkpoint(
        cwe=args.cwe,
        dataset=args.dataset,
        review=args.review,
        fixtures=args.fixtures,
        compatibility=args.compatibility,
    )
    return print_semgrep_checkpoint(result)


def print_semgrep_checkpoint(result: CheckpointResult) -> int:
    prefix = f"CWE{result.cwe}"
    print(f"{prefix}_TOTAL={result.case_count}")
    print(f"{prefix}_TRUE={result.vulnerable_count}")
    print(f"{prefix}_FALSE={result.non_vulnerable_count}")
    print(f"{prefix}_RULES={result.rule_count}")
    for name, value in sorted(result.metrics.items()):
        print(f"{name.upper()}={value}")
    print(f"CHECKPOINT_{prefix}=PASS")
    return 0


def run_source_context_build(args: argparse.Namespace) -> int:
    result = build_contexts(
        dataset_dir=args.dataset,
        findings_path=args.findings,
        output_path=args.output,
        before=args.before,
        after=args.after,
        max_lines=args.max_lines,
    )
    print("CONTEXT_STATUS=completed")
    print(f"CONTEXTS={result.context_count}")
    print(f"OUTPUT_SHA256={result.output_sha256}")
    print(f"OUTPUT={result.output_path}")
    return 0


def run_source_context_validation(args: argparse.Namespace) -> int:
    result = validate_contexts(
        dataset_dir=args.dataset,
        findings_path=args.findings,
        contexts_path=args.contexts,
        before=args.before,
        after=args.after,
        max_lines=args.max_lines,
    )
    print("CONTEXT_STATUS=validated")
    print(f"CONTEXTS={result.context_count}")
    print(f"OUTPUT_SHA256={result.output_sha256}")
    print(f"OUTPUT={result.output_path}")
    return 0


def print_baseline(result: BaselineResult) -> int:
    print(f"BASELINE_STATUS={result.status}")
    print(f"RUN_ID={result.run_id}")
    print(f"PURPOSE={result.purpose}")
    print(f"REPORTABLE={str(result.reportable).lower()}")
    print(f"SEMGREP_VERSION={result.semgrep_version}")
    print(f"RULES={result.rule_count}")
    print(f"RAW_FINDINGS={result.raw_finding_count}")
    print(f"NORMALIZED_FINDINGS={result.normalized_finding_count}")
    print(f"PREDICTED_UNITS={result.predicted_unit_count}")
    print(f"TP={result.tp}")
    print(f"FP={result.fp}")
    print(f"TN={result.tn}")
    print(f"FN={result.fn}")
    print(f"PRECISION={_metric_text(result.precision)}")
    print(f"RECALL={_metric_text(result.recall)}")
    print(f"F1={_metric_text(result.f1)}")
    print(f"FPR={_metric_text(result.fpr)}")
    print(f"MANIFEST={result.manifest_path}")
    return 0


def _metric_text(value: float | None) -> str:
    return "null" if value is None else f"{value:.10g}"


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.handler(args)
    except (
        AuditError,
        InventoryError,
        CompatError,
        FixtureError,
        ControlError,
        ReviewError,
        RulesetError,
        CohortError,
        BaselineError,
        CheckpointError,
        ContextError,
        CompositeSmokeError,
    ) as error:
        rule_command = getattr(args, "rule_command", None)
        baseline_command = getattr(args, "baseline_command", None)
        dataset_command = getattr(args, "dataset_command", None)

        context_command = getattr(args, "context_command", None)

        if context_command:
            status = "CONTEXT_STATUS=failed"
        elif baseline_command:
            status = "BASELINE_STATUS=failed"
        elif dataset_command == "build-owasp-cohort":
            status = "COHORT_STATUS=failed"
        elif rule_command == "build-ruleset":
            status = "RULESET_STATUS=failed"
        elif rule_command == "validate-checkpoint":
            status = "CHECKPOINT_STATUS=failed"
        elif rule_command == "run-composite-smoke":
            status = "COMPOSITE_SMOKE_STATUS=failed"
        elif rule_command in {"init-review", "validate-review"}:
            status = "REVIEW_STATUS=failed"
        elif rule_command == "validate-controls":
            status = "CONTROL_STATUS=failed"
        elif rule_command == "validate-fixtures":
            status = "FIXTURE_STATUS=failed"
        elif rule_command == "validate-semgrep":
            status = "COMPAT_STATUS=failed"
        elif rule_command:
            status = "INVENTORY_STATUS=failed"
        else:
            status = "AUDIT_STATUS=failed"

        print(status, file=sys.stderr)
        print(f"ERROR={error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
