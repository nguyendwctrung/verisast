import json
from pathlib import Path

import pytest

from semgrep_rules import (
    InventoryError,
    RuleGitInfo,
    inventory_rules,
    load_rules,
    parse_cwes,
)

FROZEN_COMMIT = "b" * 40


def write_rule_file(path: Path, rules: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(f"rules:\n{rules}", encoding="utf-8")


def clean_git_info() -> RuleGitInfo:
    return RuleGitInfo(
        remote_url="https://github.com/semgrep/semgrep-rules.git",
        commit=FROZEN_COMMIT,
        clean=True,
        detached=True,
    )


def test_parse_cwes_accepts_string_and_list_metadata() -> None:
    assert parse_cwes("CWE-89: SQL Injection") == frozenset({89})
    assert parse_cwes(["CWE-78: OS Command Injection", "CWE-89"]) == frozenset(
        {78, 89}
    )


def test_load_rules_reads_java_security_metadata(tmp_path: Path) -> None:
    write_rule_file(
        tmp_path / "java" / "rule.yaml",
        """  - id: java-sqli
    languages: [java]
    severity: ERROR
    message: SQL injection
    pattern: $DB.query($SQL)
    metadata:
      category: security
      cwe: "CWE-89: SQL Injection"
      confidence: HIGH
      likelihood: HIGH
      impact: HIGH
      subcategory: [vuln]
      technology: [java]
      references: [https://example.com/rule]
""",
    )

    rules = load_rules(tmp_path)

    assert len(rules) == 1
    assert rules[0].rule_id == "java-sqli"
    assert rules[0].cwes == frozenset({89})
    assert rules[0].languages == ("java",)
    assert rules[0].mode == "search"
    assert rules[0].source_path == "java/rule.yaml"


def test_load_rules_rejects_security_rule_without_cwe(tmp_path: Path) -> None:
    write_rule_file(
        tmp_path / "java" / "missing-cwe.yaml",
        """  - id: missing-cwe
    languages: [java]
    severity: WARNING
    message: Missing CWE metadata
    pattern: bad(...)
    metadata:
      category: security
      technology: [java]
""",
    )

    with pytest.raises(InventoryError, match="security rule has no valid CWE"):
        load_rules(tmp_path)


def test_load_rules_rejects_duplicate_rule_ids(tmp_path: Path) -> None:
    rules = """  - id: duplicate-id
    languages: [java]
    severity: ERROR
    message: Duplicate
    pattern: bad(...)
    metadata:
      category: security
      cwe: CWE-78
      technology: [java]
  - id: duplicate-id
    languages: [java]
    severity: ERROR
    message: Duplicate in the same file
    pattern: worse(...)
    metadata:
      category: security
      cwe: CWE-78
      technology: [java]
"""
    write_rule_file(tmp_path / "java" / "duplicate.yaml", rules)

    with pytest.raises(InventoryError, match="duplicate rule ID in"):
        load_rules(tmp_path)


def test_inventory_filters_java_security_rules_by_owasp_cwe(tmp_path: Path) -> None:
    rules_dir = tmp_path / "upstream" / "semgrep-rules"
    write_rule_file(
        rules_dir / "java" / "mixed.yaml",
        """  - id: java-sqli
    languages: [java]
    severity: ERROR
    message: SQL injection
    mode: taint
    pattern-sources: [{pattern: source(...)}]
    pattern-sinks: [{pattern: sink(...)}]
    metadata:
      category: security
      cwe: ["CWE-89: SQL Injection"]
      confidence: HIGH
      technology: [java]
  - id: java-unrelated
    languages: [java]
    severity: WARNING
    message: Unrelated CWE
    pattern: weak(...)
    metadata:
      category: security
      cwe: CWE-200
      technology: [java]
  - id: python-cmdi
    languages: [python]
    severity: ERROR
    message: Python command injection
    pattern: os.system(...)
    metadata:
      category: security
      cwe: CWE-78
      technology: [python]
  - id: java-correctness
    languages: [java]
    severity: INFO
    message: Correctness only
    pattern: thing(...)
    metadata:
      category: correctness
      technology: [java]
""",
    )
    output_path = tmp_path / "inventory" / "report.json"

    result = inventory_rules(
        rules_dir=rules_dir,
        output_path=output_path,
        expected_cwes={78, 89},
        git_reader=lambda _: clean_git_info(),
    )

    assert result.candidate_rule_count == 1
    report = json.loads(output_path.read_text(encoding="utf-8"))
    assert report["upstream_commit"] == FROZEN_COMMIT
    assert report["candidate_rule_count"] == 1
    assert report["candidate_counts_by_cwe"] == {"78": 0, "89": 1}
    assert report["rules"][0]["id"] == "java-sqli"
    assert report["rules"][0]["mode"] == "taint"
    assert report["rules"][0]["execution_compatibility"] == "not_validated"


@pytest.mark.parametrize(
    "git_info, expected_message",
    [
        (
            RuleGitInfo("https://example.com/rules.git", FROZEN_COMMIT, True, True),
            "unexpected Git remote",
        ),
        (
            RuleGitInfo(
                "https://github.com/semgrep/semgrep-rules.git",
                FROZEN_COMMIT,
                False,
                True,
            ),
            "working tree is not clean",
        ),
        (
            RuleGitInfo(
                "https://github.com/semgrep/semgrep-rules.git",
                FROZEN_COMMIT,
                True,
                False,
            ),
            "HEAD is not detached",
        ),
    ],
)
def test_inventory_rejects_invalid_provenance(
    tmp_path: Path,
    git_info: RuleGitInfo,
    expected_message: str,
) -> None:
    rules_dir = tmp_path / "semgrep-rules"
    rules_dir.mkdir()

    with pytest.raises(InventoryError, match=expected_message):
        inventory_rules(
            rules_dir=rules_dir,
            output_path=tmp_path / "report.json",
            expected_cwes={89},
            git_reader=lambda _: git_info,
        )


def test_inventory_rejects_output_inside_upstream_checkout(tmp_path: Path) -> None:
    rules_dir = tmp_path / "semgrep-rules"
    rules_dir.mkdir()

    with pytest.raises(InventoryError, match="output must be outside"):
        inventory_rules(
            rules_dir=rules_dir,
            output_path=rules_dir / "report.json",
            expected_cwes={89},
            git_reader=lambda _: clean_git_info(),
        )
