"""Hardware guard polled before each run so the driver can throttle: pause +
cool down when the machine is at its limits (user instruction 2026-10-13/14).

Watches RAM%, VRAM%, GPU temp, and -- added 2026-10-14 -- CPU temp. CPU temp is
the PRIMARY signal on this machine: Qwen2.5 7B is ~58% CPU-offloaded on the 4GB
GPU, so inference load lands on the CPU. Measured live the CPU thermal zone sat
at ~94 C while the GPU stayed a cool 64 C -- a GPU-only guard would miss the real
heat entirely. CPU temp is read via the ACPI thermal zone through PDH (the same
path sysfloat uses; WMI MSAcpi_ThermalZoneTemperature is access-denied here).

Usage:
    python eval/resource_guard.py          -> prints a one-line status
    python eval/resource_guard.py --check   -> exit 1 if ANY threshold exceeded,
                                               exit 0 otherwise (no float compare
                                               needed in the calling shell)
"""
import sys

RAM_PCT_MAX = 90.0
VRAM_PCT_MAX = 90.0
GPU_TEMP_MAX = 80.0    # C
CPU_TEMP_MAX = 90.0    # C -- primary signal (CPU-heavy inference)

import psutil

ram_pct = psutil.virtual_memory().percent

vram_pct = None
gpu_temp = None
try:
    import pynvml
    pynvml.nvmlInit()
    h = pynvml.nvmlDeviceGetHandleByIndex(0)
    info = pynvml.nvmlDeviceGetMemoryInfo(h)
    vram_pct = round(100.0 * info.used / info.total, 1)
    gpu_temp = pynvml.nvmlDeviceGetTemperature(h, pynvml.NVML_TEMPERATURE_GPU)
except Exception:
    pass


def _cpu_temp():
    """Hottest ACPI thermal zone in Celsius via PDH, or None. Mirrors
    sysfloat/core/thermal.py: WMI is access-denied without admin here, PDH is not.
    """
    try:
        import ctypes
        from ctypes import wintypes

        class _U(ctypes.Union):
            _fields_ = [("longValue", ctypes.c_long), ("doubleValue", ctypes.c_double)]

        class _CV(ctypes.Structure):
            _fields_ = [("CStatus", wintypes.DWORD), ("union", _U)]

        pdh = ctypes.WinDLL("pdh")
        query = wintypes.HANDLE()
        if pdh.PdhOpenQueryW(None, 0, ctypes.byref(query)) != 0:
            return None
        # Expand every thermal zone, keep the hottest sane reading.
        pattern = r"\Thermal Zone Information(*)\Temperature"
        size = wintypes.DWORD(0)
        pdh.PdhExpandWildCardPathW(None, pattern, None, ctypes.byref(size), 0)
        buf = ctypes.create_unicode_buffer(size.value or 1)
        paths = []
        if pdh.PdhExpandWildCardPathW(None, pattern, buf, ctypes.byref(size), 0) == 0:
            paths = [p for p in buf[: size.value].split("\x00") if p.strip()]
        if not paths:
            paths = [r"\Thermal Zone Information(\_TZ.THRM)\Temperature"]
        handles = []
        for p in paths:
            hc = wintypes.HANDLE()
            if pdh.PdhAddCounterW(query, p, 0, ctypes.byref(hc)) == 0:
                handles.append(hc)
        if not handles:
            return None
        import time
        pdh.PdhCollectQueryData(query)
        time.sleep(0.2)
        pdh.PdhCollectQueryData(query)
        hottest = None
        for hc in handles:
            v = _CV()
            if pdh.PdhGetFormattedCounterValue(hc, 0x00000200, None, ctypes.byref(v)) == 0:
                c = v.union.doubleValue - 273.15
                if 20.0 < c < 120.0 and (hottest is None or c > hottest):
                    hottest = c
        return round(hottest, 1) if hottest is not None else None
    except Exception:
        return None


cpu_temp = _cpu_temp()

status = (f"RAM={ram_pct} VRAM={vram_pct if vram_pct is not None else 'NA'} "
          f"GPU_temp={gpu_temp if gpu_temp is not None else 'NA'} "
          f"CPU_temp={cpu_temp if cpu_temp is not None else 'NA'}")

if "--check" in sys.argv:
    over = (
        ram_pct >= RAM_PCT_MAX
        or (vram_pct is not None and vram_pct >= VRAM_PCT_MAX)
        or (gpu_temp is not None and gpu_temp >= GPU_TEMP_MAX)
        or (cpu_temp is not None and cpu_temp >= CPU_TEMP_MAX)
    )
    print(f"{status} over={over}")
    sys.exit(1 if over else 0)

print(status)
