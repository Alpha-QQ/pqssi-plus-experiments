"""Machine description, single-core pinning and peak-memory measurement."""
import os
import platform
import shutil
import subprocess
import sys

_MEMWRAP = (
    "import resource,subprocess,sys;"
    "r=subprocess.run(sys.argv[1:],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL);"
    "m=resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss;"
    "print(r.returncode,m)"
)


def describe():
    """Device information, stored separately from the device-independent results."""
    info = {"platform": platform.platform(), "machine": platform.machine(),
            "processor": platform.processor(), "python": sys.version.split()[0],
            "cpu_count": os.cpu_count()}
    for cmd in (["rustc", "--version"], ["cargo", "--version"]):
        try:
            info[cmd[0]] = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace").stdout.strip()
        except OSError:
            info[cmd[0]] = None
    return info


def pin_prefix(pin_core):
    """Command prefix that pins to one core (Linux taskset). Empty where taskset is unavailable
    (Windows, macOS): there the provers are only limited to one worker thread."""
    if pin_core is None or shutil.which("taskset") is None:
        return []
    return ["taskset", "-c", str(pin_core)]


def run(cmd, env):
    """Run cmd with env; return (stdout, stderr). Raises on a nonzero exit code."""
    p = subprocess.run(cmd, env=env, capture_output=True, text=True, encoding="utf-8", errors="replace")
    if p.returncode != 0:
        raise RuntimeError(f"{' '.join(cmd)} failed ({p.returncode}):\n{p.stderr[-3000:]}")
    return p.stdout, p.stderr


def _peak_memory_windows_mib(cmd, env):
    """Peak working set (MiB) of cmd on Windows, read with GetProcessMemoryInfo after it exits."""
    import ctypes
    from ctypes import wintypes

    class Counters(ctypes.Structure):
        _fields_ = [("cb", wintypes.DWORD), ("PageFaultCount", wintypes.DWORD),
                    ("PeakWorkingSetSize", ctypes.c_size_t), ("WorkingSetSize", ctypes.c_size_t),
                    ("QuotaPeakPagedPoolUsage", ctypes.c_size_t), ("QuotaPagedPoolUsage", ctypes.c_size_t),
                    ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t), ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                    ("PagefileUsage", ctypes.c_size_t), ("PeakPagefileUsage", ctypes.c_size_t)]

    p = subprocess.Popen(cmd, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    p.wait()
    if p.returncode != 0:
        raise RuntimeError(f"memory run failed: {' '.join(cmd)}")
    c = Counters()
    c.cb = ctypes.sizeof(Counters)
    psapi = ctypes.WinDLL("psapi")
    psapi.GetProcessMemoryInfo.argtypes = [wintypes.HANDLE, ctypes.POINTER(Counters), wintypes.DWORD]
    if not psapi.GetProcessMemoryInfo(wintypes.HANDLE(int(p._handle)), ctypes.byref(c), c.cb):
        return None
    return c.PeakWorkingSetSize / (1024 * 1024)


def peak_memory_mib(cmd, env):
    """Peak resident set size (MiB, 2^20 bytes) of cmd, measured in a fresh process."""
    if sys.platform == "win32":
        return _peak_memory_windows_mib(cmd, env)
    out = subprocess.run([sys.executable, "-c", _MEMWRAP] + cmd, env=env,
                         capture_output=True, text=True, encoding="utf-8", errors="replace").stdout.split()
    code, rss = int(out[0]), int(out[1])
    if code != 0:
        raise RuntimeError(f"memory run failed: {' '.join(cmd)}")
    # ru_maxrss is in bytes on macOS and in kilobytes on Linux.
    return rss / (1024 * 1024) if sys.platform == "darwin" else rss / 1024
