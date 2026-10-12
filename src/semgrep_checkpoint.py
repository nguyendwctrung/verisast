import csv
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any


class CheckpointError(ValueError):
    pass


@dataclass(frozen=True)
class CheckpointResult:
    cwe: int
    case_count: int
    vulnerable_count: int
    non_vulnerable_count: int
    rule_count: int
    metrics: dict[str, int]


EXPECTED_DECISIONS = {
    327: {
        "avoid-implementing-custom-digests": ("EXCLUDE", "not_relevant"),
        "cbc-padding-oracle": ("INCLUDE_DEVELOPMENT", "relevant"),
        "ecb-cipher": ("EXCLUDE", "not_relevant"),
        "java-jwt-none-alg": ("EXCLUDE", "not_relevant"),
        "jjwt-none-alg": ("EXCLUDE", "not_relevant"),
        "md5-used-as-password": ("EXCLUDE", "not_relevant"),
        "no-null-cipher": ("EXCLUDE", "not_relevant"),
        "use-of-aes-ecb": ("EXCLUDE", "not_relevant"),
        "use-of-blowfish": ("EXCLUDE", "not_relevant"),
        "use-of-default-aes": ("EXCLUDE", "not_relevant"),
        "use-of-rc2": ("EXCLUDE", "not_relevant"),
        "use-of-rc4": ("EXCLUDE", "not_relevant"),
    },
    328: {
        "use-of-md5": ("INCLUDE_DEVELOPMENT", "relevant"),
        "use-of-md5-digest-utils": ("EXCLUDE", "not_relevant"),
        "use-of-sha1": ("INCLUDE_DEVELOPMENT", "relevant"),
        "use-of-sha224": ("EXCLUDE", "not_relevant"),
    },
    330: {
        "weak-random": ("INCLUDE_DEVELOPMENT", "relevant"),
    },
}


def _load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise CheckpointError(f"cannot read JSON evidence: {path}") from exc
    if not isinstance(value, dict):
        raise CheckpointError(f"JSON evidence must be an object: {path}")
    return value


def _load_cases(dataset: Path, cwe: int) -> list[tuple[str, bool, str]]:
    ground_truth = dataset / "expectedresults-1.2.csv"
    source_root = dataset / "src" / "main" / "java"
    if not ground_truth.is_file() or not source_root.is_dir():
        raise CheckpointError("dataset ground truth or Java source directory is missing")

    sources = {path.stem: path for path in source_root.rglob("BenchmarkTest*.java")}
    cases: list[tuple[str, bool, str]] = []
    with ground_truth.open(encoding="utf-8", newline="") as stream:
        rows = csv.reader(stream)
        for row in rows:
            if not row or row[0].startswith("#") or len(row) < 4:
                continue
            if int(row[3]) != cwe:
                continue
            test_name = row[0].strip()
            source_path = sources.get(test_name)
            if source_path is None:
                raise CheckpointError(f"missing source file for testcase: {test_name}")
            cases.append(
                (
                    test_name,
                    row[2].strip().lower() == "true",
                    source_path.read_text(encoding="utf-8"),
                )
            )
    if not cases:
        raise CheckpointError(f"no ground-truth cases found for CWE-{cwe}")
    return cases


def _validate_reports(
    cwe: int,
    review: Path,
    fixtures: Path,
    compatibility: Path,
) -> int:
    expected = EXPECTED_DECISIONS[cwe]
    review_records = _load_json(review).get("reviews", [])
    fixture_records = _load_json(fixtures).get("files", [])
    compatibility_records = _load_json(compatibility).get("files", [])

    selected = [record for record in review_records if cwe in record.get("reviewed_cwes", [])]
    if len(selected) != len(expected):
        raise CheckpointError(f"unexpected review record count for CWE-{cwe}")

    for rule_id, (decision, relevance) in expected.items():
        records = [record for record in selected if record.get("rule_id") == rule_id]
        if len(records) != 1:
            raise CheckpointError(f"missing review record: {rule_id}")
        record = records[0]
        if record.get("decision") != decision or record.get("benchmark_relevance") != relevance:
            raise CheckpointError(f"unexpected review decision: {rule_id}")

        fixture_matches = [
            item for item in fixture_records if rule_id in item.get("rule_ids", [])
        ]
        if len(fixture_matches) != 1 or fixture_matches[0].get("test_status") != "PASS":
            raise CheckpointError(f"fixture evidence failed: {rule_id}")
        if int(fixture_matches[0].get("positive_annotations", 0)) < 1:
            raise CheckpointError(f"fixture has no positive annotation: {rule_id}")

        compatibility_matches = [
            item
            for item in compatibility_records
            if rule_id in item.get("rule_ids", [])
        ]
        if (
            len(compatibility_matches) != 1
            or compatibility_matches[0].get("status") != "COMPATIBLE"
            or int(compatibility_matches[0].get("exit_code", -1)) != 0
        ):
            raise CheckpointError(f"compatibility evidence failed: {rule_id}")
    return len(selected)


def _audit_cwe328(cases: list[tuple[str, bool, str]]) -> dict[str, int]:
    metrics = {
        "message_digest_md5": 0,
        "message_digest_sha1": 0,
        "message_digest_sha256": 0,
        "message_digest_sha384": 0,
        "message_digest_sha512": 0,
        "digest_utils_files": 0,
        "sha224_files": 0,
    }
    names = {
        "MD5": "message_digest_md5",
        "SHA1": "message_digest_sha1",
        "SHA-1": "message_digest_sha1",
        "SHA-256": "message_digest_sha256",
        "SHA-384": "message_digest_sha384",
        "SHA-512": "message_digest_sha512",
    }
    for test_name, vulnerable, source in cases:
        algorithms = re.findall(
            r'MessageDigest\s*\.\s*getInstance\s*\(\s*"([^"]+)"', source
        )
        for algorithm in algorithms:
            key = names.get(algorithm.upper().replace("_", "-"))
            if key is not None:
                metrics[key] += 1
            if vulnerable and key not in {"message_digest_md5", "message_digest_sha1"}:
                raise CheckpointError("vulnerable CWE-328 case uses an unexpected algorithm")
            if not vulnerable and key in {"message_digest_md5", "message_digest_sha1"}:
                raise CheckpointError("non-vulnerable CWE-328 case uses a weak algorithm")
        if re.search(r"DigestUtils|getMd5Digest|md5Hex", source, re.IGNORECASE):
            metrics["digest_utils_files"] += 1
        if re.search(r"SHA-?224|SHA3-?224|SHA-?512/224", source, re.IGNORECASE):
            metrics["sha224_files"] += 1
    if metrics["digest_utils_files"] or metrics["sha224_files"]:
        raise CheckpointError("unexpected excluded CWE-328 API found in the corpus")
    return metrics


def _audit_cwe327(cases: list[tuple[str, bool, str]]) -> dict[str, int]:
    metrics = {
        "vulnerable_des_cbc_files": 0,
        "vulnerable_dynamic_desede_ecb_files": 0,
        "non_vulnerable_aes_ccm_files": 0,
        "non_vulnerable_aes_gcm_files": 0,
        "non_vulnerable_dynamic_aes_ecb_files": 0,
        "non_vulnerable_helper_cipher_files": 0,
        "excluded_api_files": 0,
    }
    excluded_pattern = re.compile(
        r"extends\s+MessageDigest|Algorithm\.none|Jwts\.builder|NullCipher|"
        r"Cipher\s*\.\s*getInstance\s*\(\s*\"(?:AES(?:/ECB[^\"]*)?|Blowfish|RC2|RC4)\""
    )
    for test_name, vulnerable, source in cases:
        upper_source = source.upper()
        des_cbc = "DES/CBC/PKCS5PADDING" in upper_source
        dynamic_ecb = "DESEDE/ECB/PKCS5PADDING" in upper_source
        aes_ccm = "AES/CCM/NOPADDING" in upper_source
        aes_gcm = "AES/GCM/NOPADDING" in upper_source
        dynamic_aes_ecb = "AES/ECB/PKCS5PADDING" in upper_source
        helper_cipher = "UTILS.GETCIPHER()" in upper_source
        metrics["excluded_api_files"] += int(bool(excluded_pattern.search(source)))
        if vulnerable:
            metrics["vulnerable_des_cbc_files"] += int(des_cbc)
            metrics["vulnerable_dynamic_desede_ecb_files"] += int(dynamic_ecb)
            if not (des_cbc or dynamic_ecb):
                raise CheckpointError(
                    f"vulnerable CWE-327 API profile mismatch: {test_name}"
                )
        else:
            metrics["non_vulnerable_aes_ccm_files"] += int(aes_ccm)
            metrics["non_vulnerable_aes_gcm_files"] += int(aes_gcm)
            metrics["non_vulnerable_dynamic_aes_ecb_files"] += int(dynamic_aes_ecb)
            metrics["non_vulnerable_helper_cipher_files"] += int(helper_cipher)
            if (
                not (aes_ccm or aes_gcm or dynamic_aes_ecb or helper_cipher)
                or des_cbc
                or dynamic_ecb
            ):
                raise CheckpointError(
                    f"non-vulnerable CWE-327 API profile mismatch: {test_name}"
                )
    if metrics["excluded_api_files"]:
        raise CheckpointError("excluded CWE-327 API occurs in the corpus")
    return metrics


def _audit_cwe330(cases: list[tuple[str, bool, str]]) -> dict[str, int]:
    metrics = {
        "vulnerable_math_random_files": 0,
        "vulnerable_util_random_files": 0,
        "vulnerable_secure_random_files": 0,
        "vulnerable_rule_covered_files": 0,
        "non_vulnerable_math_random_files": 0,
        "non_vulnerable_util_random_files": 0,
        "non_vulnerable_secure_random_files": 0,
        "non_vulnerable_weak_rng_files": 0,
    }
    for _, vulnerable, source in cases:
        uses_math = bool(re.search(r"java\s*\.\s*lang\s*\.\s*Math\s*\.\s*random\s*\(", source))
        uses_util = bool(
            re.search(
                r"new\s+java\s*\.\s*util\s*\.\s*Random\s*\([^)]*\)\s*\.\s*\w+\s*\(",
                source,
            )
        )
        uses_secure = bool(
            re.search(r"java\s*\.\s*security\s*\.\s*SecureRandom", source)
        )
        prefix = "vulnerable" if vulnerable else "non_vulnerable"
        metrics[f"{prefix}_math_random_files"] += int(uses_math)
        metrics[f"{prefix}_util_random_files"] += int(uses_util)
        metrics[f"{prefix}_secure_random_files"] += int(uses_secure)
        if vulnerable:
            metrics["vulnerable_rule_covered_files"] += int(uses_math or uses_util)
            if not (uses_math or uses_util) or uses_secure:
                raise CheckpointError("vulnerable CWE-330 API profile mismatch")
        else:
            metrics["non_vulnerable_weak_rng_files"] += int(uses_math or uses_util)
            if uses_math or uses_util or not uses_secure:
                raise CheckpointError("non-vulnerable CWE-330 API profile mismatch")
    return metrics


def validate_checkpoint(
    *,
    cwe: int,
    dataset: Path,
    review: Path,
    fixtures: Path,
    compatibility: Path,
) -> CheckpointResult:
    if cwe not in EXPECTED_DECISIONS:
        raise CheckpointError(f"unsupported CWE: {cwe}")
    cases = _load_cases(dataset, cwe)
    rule_count = _validate_reports(cwe, review, fixtures, compatibility)
    if cwe == 327:
        metrics = _audit_cwe327(cases)
    elif cwe == 328:
        metrics = _audit_cwe328(cases)
    else:
        metrics = _audit_cwe330(cases)
    vulnerable_count = sum(vulnerable for _, vulnerable, _ in cases)
    return CheckpointResult(
        cwe=cwe,
        case_count=len(cases),
        vulnerable_count=vulnerable_count,
        non_vulnerable_count=len(cases) - vulnerable_count,
        rule_count=rule_count,
        metrics=metrics,
    )
