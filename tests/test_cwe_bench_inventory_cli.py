from pathlib import Path

from main import main


def test_cwe_bench_inventory_cli_dispatches_paths(monkeypatch) -> None:
    captured = {}

    def discover(dataset_root: Path, protocol: Path, output: Path) -> dict[str, object]:
        captured.update(dataset_root=dataset_root, protocol=protocol, output=output)
        return {"status": "complete", "candidate_count": 1}

    monkeypatch.setattr("main.discover_cwe_bench", discover)

    result = main([
        "cwe-bench", "inventory",
        "--dataset-root", "datasets/raw/cwe-bench-java",
        "--protocol", "inventory/cwe-bench-development-v1/selection-protocol.json",
        "--output", "artifacts/cohort/discovery-01",
    ])

    assert result == 0
    assert captured == {
        "dataset_root": Path("datasets/raw/cwe-bench-java"),
        "protocol": Path("inventory/cwe-bench-development-v1/selection-protocol.json"),
        "output": Path("artifacts/cohort/discovery-01"),
    }


def test_cwe_bench_materialize_cli_dispatches_paths(monkeypatch) -> None:
    captured = {}

    def materialize(snapshot: Path, shortlist: Path, dataset_root: Path, output: Path) -> dict[str, object]:
        captured.update(snapshot=snapshot, shortlist=shortlist, dataset_root=dataset_root, output=output)
        return {"status": "complete", "materialized_count": 10}

    monkeypatch.setattr("main.materialize_cwe_bench", materialize)

    result = main([
        "cwe-bench", "materialize",
        "--snapshot", "datasets/raw/cwe-bench-java-120",
        "--shortlist", "inventory/cwe-bench-development-v1/acquisition-shortlist.json",
        "--dataset-root", "datasets/raw/cwe-bench-java",
        "--output", "artifacts/cohort/materialization-01",
    ])

    assert result == 0
    assert captured == {
        "snapshot": Path("datasets/raw/cwe-bench-java-120"),
        "shortlist": Path("inventory/cwe-bench-development-v1/acquisition-shortlist.json"),
        "dataset_root": Path("datasets/raw/cwe-bench-java"),
        "output": Path("artifacts/cohort/materialization-01"),
    }
