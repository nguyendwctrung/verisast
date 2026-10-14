import ctypes
import os
import platform
import time
from datetime import datetime, timezone
from ctypes import wintypes


METHOD = "orchestrator-process-and-system-snapshot-v1"


class RuntimeEvidenceError(ValueError):
    pass


def start_measurement() -> dict[str, object]:
    return {
        "started_at": datetime.now(timezone.utc).isoformat(),
        "started_ns": time.perf_counter_ns(),
        "host": _host(),
        "memory_start": _memory_snapshot(),
    }


def finish_measurement(started: dict[str, object], scans: list[dict[str, object]]) -> dict[str, object]:
    started_ns = started.get("started_ns")
    if not isinstance(started_ns, int):
        raise RuntimeEvidenceError("measurement start is invalid")
    scan_durations_ms = [_scan_duration(scan) for scan in scans]
    scan_duration_ms = sum(scan_durations_ms)
    return {
        "schema_version": 1,
        "method": METHOD,
        "scope": {
            "included": ["host metadata", "orchestrator wall time", "per-rule Semgrep durations", "orchestrator process working set", "system memory snapshots"],
            "excluded": ["Semgrep child-process peak working set", "GPU utilization", "Ollama or external service resource use"],
        },
        "started_at": started["started_at"],
        "completed_at": datetime.now(timezone.utc).isoformat(),
        "wall_time_ms": (time.perf_counter_ns() - started_ns) // 1_000_000,
        "scan_duration_ms": scan_duration_ms,
        "scan_count": len(scans),
        "scan_durations_ms": scan_durations_ms,
        "host": started["host"],
        "memory_start": started["memory_start"],
        "memory_end": _memory_snapshot(),
    }


def validate_measurement(evidence: dict[str, object], scans: list[dict[str, object]] | None = None) -> None:
    if evidence.get("schema_version") != 1 or evidence.get("method") != METHOD:
        raise RuntimeEvidenceError("unsupported runtime measurement")
    if not isinstance(evidence.get("wall_time_ms"), int) or evidence["wall_time_ms"] < 0:
        raise RuntimeEvidenceError("invalid wall time")
    if not isinstance(evidence.get("scan_duration_ms"), int) or evidence["scan_duration_ms"] < 0:
        raise RuntimeEvidenceError("invalid scan duration")
    if not isinstance(evidence.get("scan_count"), int) or evidence["scan_count"] < 0:
        raise RuntimeEvidenceError("invalid scan count")
    scan_durations = evidence.get("scan_durations_ms")
    if not isinstance(scan_durations, list) or not all(isinstance(value, int) and value >= 0 for value in scan_durations):
        raise RuntimeEvidenceError("invalid scan durations")
    if evidence["scan_count"] != len(scan_durations) or evidence["scan_duration_ms"] != sum(scan_durations):
        raise RuntimeEvidenceError("scan duration does not match measurement records")
    host = evidence.get("host")
    if not isinstance(host, dict) or not isinstance(host.get("logical_cpu_count"), int):
        raise RuntimeEvidenceError("invalid host metadata")
    for name in ("memory_start", "memory_end"):
        snapshot = evidence.get(name)
        if not isinstance(snapshot, dict) or not isinstance(snapshot.get("process_working_set_bytes"), int):
            raise RuntimeEvidenceError(f"invalid {name}")
        if os.name == "nt" and snapshot["process_working_set_bytes"] <= 0:
            raise RuntimeEvidenceError(f"invalid {name} process working set")
    if scans is not None:
        expected = sum(_scan_duration(scan) for scan in scans)
        if evidence["scan_count"] != len(scans) or evidence["scan_duration_ms"] != expected:
            raise RuntimeEvidenceError("scan duration does not match scan records")


def _scan_duration(scan: dict[str, object]) -> int:
    value = scan.get("duration_ms")
    if not isinstance(value, int) or value < 0:
        raise RuntimeEvidenceError("scan record has invalid duration")
    return value


def _host() -> dict[str, object]:
    return {
        "platform": platform.platform(),
        "python_version": platform.python_version(),
        "machine": platform.machine(),
        "logical_cpu_count": os.cpu_count() or 0,
    }


def _memory_snapshot() -> dict[str, int | None]:
    process_working_set = _process_working_set_bytes()
    total, available = _system_memory_bytes()
    return {
        "process_working_set_bytes": process_working_set,
        "system_total_bytes": total,
        "system_available_bytes": available,
    }


def _process_working_set_bytes() -> int:
    class ProcessMemoryCounters(ctypes.Structure):
        _fields_ = [("cb", wintypes.DWORD), ("page_fault_count", wintypes.DWORD), ("peak_working_set_size", ctypes.c_size_t), ("working_set_size", ctypes.c_size_t), ("quota_peak_paged_pool_usage", ctypes.c_size_t), ("quota_paged_pool_usage", ctypes.c_size_t), ("quota_peak_non_paged_pool_usage", ctypes.c_size_t), ("quota_non_paged_pool_usage", ctypes.c_size_t), ("pagefile_usage", ctypes.c_size_t), ("peak_pagefile_usage", ctypes.c_size_t)]

    if os.name != "nt":
        return 0
    counters = ProcessMemoryCounters()
    counters.cb = ctypes.sizeof(counters)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    psapi = ctypes.WinDLL("psapi", use_last_error=True)
    kernel32.GetCurrentProcess.argtypes = []
    kernel32.GetCurrentProcess.restype = wintypes.HANDLE
    psapi.GetProcessMemoryInfo.argtypes = [wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD]
    psapi.GetProcessMemoryInfo.restype = wintypes.BOOL
    success = psapi.GetProcessMemoryInfo(kernel32.GetCurrentProcess(), ctypes.byref(counters), counters.cb)
    return int(counters.working_set_size) if success else 0


def _system_memory_bytes() -> tuple[int | None, int | None]:
    class MemoryStatus(ctypes.Structure):
        _fields_ = [("dwLength", ctypes.c_ulong), ("dwMemoryLoad", ctypes.c_ulong), ("ullTotalPhys", ctypes.c_ulonglong), ("ullAvailPhys", ctypes.c_ulonglong), ("ullTotalPageFile", ctypes.c_ulonglong), ("ullAvailPageFile", ctypes.c_ulonglong), ("ullTotalVirtual", ctypes.c_ulonglong), ("ullAvailVirtual", ctypes.c_ulonglong), ("ullAvailExtendedVirtual", ctypes.c_ulonglong)]

    if os.name != "nt":
        return None, None
    status = MemoryStatus()
    status.dwLength = ctypes.sizeof(status)
    success = ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(status))
    return (int(status.ullTotalPhys), int(status.ullAvailPhys)) if success else (None, None)
