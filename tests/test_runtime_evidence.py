import time
import os

import pytest

from runtime_evidence import RuntimeEvidenceError, finish_measurement, start_measurement, validate_measurement


def test_measurement_records_host_wall_time_and_scan_summary() -> None:
    started = start_measurement()
    time.sleep(0.001)
    evidence = finish_measurement(started, [{"duration_ms": 12}, {"duration_ms": 8}])

    validate_measurement(evidence)
    assert evidence["wall_time_ms"] >= 0
    assert evidence["scan_duration_ms"] == 20
    assert evidence["host"]["logical_cpu_count"] is not None
    if os.name == "nt":
        assert evidence["memory_end"]["process_working_set_bytes"] > 0


def test_measurement_validation_rejects_changed_scan_total() -> None:
    evidence = finish_measurement(start_measurement(), [{"duration_ms": 12}])
    evidence["scan_duration_ms"] = 13
    with pytest.raises(RuntimeEvidenceError, match="scan duration"):
        validate_measurement(evidence)
