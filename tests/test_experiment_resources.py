from experiment_resources import ResourceMonitor


def test_resource_monitor_records_peak_and_missing_reason(monkeypatch) -> None:
    values = iter([(100.0, 20.0), (120.0, None)])
    monkeypatch.setattr("experiment_resources.sample", lambda: next(values))
    monitor = ResourceMonitor(interval_seconds=60)
    monitor.capture()
    monitor.capture()
    result = monitor.summary()
    assert result["peak_ram_mb"] == 120.0
    assert result["peak_vram_mb"] == 20.0
    assert result["resource_status"] == "partial_gpu_sample"
