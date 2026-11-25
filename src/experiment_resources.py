"""Best-effort host RAM/GPU sampling with explicit measurement scope."""

import ctypes
import subprocess
import sys
import threading


class _MemoryStatus(ctypes.Structure):
    _fields_ = [("length", ctypes.c_ulong), ("memory_load", ctypes.c_ulong),
                ("total_physical", ctypes.c_ulonglong), ("available_physical", ctypes.c_ulonglong),
                ("total_page", ctypes.c_ulonglong), ("available_page", ctypes.c_ulonglong),
                ("total_virtual", ctypes.c_ulonglong), ("available_virtual", ctypes.c_ulonglong),
                ("available_extended", ctypes.c_ulonglong)]


def sample() -> tuple[float | None, float | None]:
    """Return system RAM used and total NVIDIA GPU memory used in MiB."""
    ram_mb = None
    if sys.platform == "win32":
        memory = _MemoryStatus()
        memory.length = ctypes.sizeof(_MemoryStatus)
        if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(memory)):
            ram_mb = round((memory.total_physical - memory.available_physical) / (1024 * 1024), 3)
    try:
        result = subprocess.run(
            ["nvidia-smi", "--query-gpu=memory.used", "--format=csv,noheader,nounits"],
            text=True, capture_output=True, check=False, timeout=5,
        )
        values = [float(line.strip()) for line in result.stdout.splitlines() if line.strip()]
        vram_mb = sum(values) if result.returncode == 0 and values else None
    except (OSError, ValueError, subprocess.TimeoutExpired):
        vram_mb = None
    return ram_mb, vram_mb


class ResourceMonitor:
    def __init__(self, interval_seconds: float = 2.0) -> None:
        self.interval_seconds = interval_seconds
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._ram: list[float] = []
        self._vram: list[float] = []
        self._ram_missing = False
        self._gpu_missing = False

    def capture(self) -> None:
        ram, vram = sample()
        if ram is None:
            self._ram_missing = True
        else:
            self._ram.append(ram)
        if vram is None:
            self._gpu_missing = True
        else:
            self._vram.append(vram)

    def start(self) -> None:
        self.capture()
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def _loop(self) -> None:
        while not self._stop.wait(self.interval_seconds):
            self.capture()

    def stop(self) -> dict[str, object]:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=6)
        self.capture()
        return self.summary()

    def summary(self) -> dict[str, object]:
        return {
            "peak_ram_mb": max(self._ram) if self._ram else None,
            "peak_vram_mb": max(self._vram) if self._vram else None,
            "resource_status": "complete" if self._ram and self._vram and not self._ram_missing and not self._gpu_missing
            else "partial_gpu_sample" if self._ram and self._vram
            else "gpu_unavailable" if self._ram else "ram_unavailable",
            "measurement_scope": "host_used_ram_and_all_nvidia_gpu_used_memory",
            "sample_interval_seconds": self.interval_seconds,
        }
