"""Measured Mojo-kernel throughput against portable pure-Python references."""

from __future__ import annotations

import os
import platform
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path[:0] = [os.path.join(ROOT, "python"), os.path.join(ROOT, "tests")]

import pyhash  # noqa: E402
from reference import fnv, murmur2_32, murmur3_32, xx32, xx64  # noqa: E402


CASES = [
    ("fnv1_32", lambda b: fnv(b, 0, 32)),
    ("fnv1a_32", lambda b: fnv(b, 0, 32, alternate=True)),
    ("fnv1_64", lambda b: fnv(b, 0, 64)),
    ("fnv1a_64", lambda b: fnv(b, 0, 64, alternate=True)),
    ("murmur2_32", murmur2_32),
    ("murmur3_32", murmur3_32),
    ("xx_32", xx32),
    ("xx_64", xx64),
]


def best_time(call, repeat=3):
    call()
    best = float("inf")
    for _ in range(repeat):
        start = time.perf_counter()
        call()
        best = min(best, time.perf_counter() - start)
    return best


def cpu_name():
    try:
        with open("/proc/cpuinfo", encoding="utf-8") as f:
            for line in f:
                if line.startswith("model name"):
                    return line.split(":", 1)[1].strip()
    except OSError:
        pass
    return platform.processor() or platform.machine()


def main():
    input_mib = int(os.environ.get("PYFASTHASH_BENCH_MIB", "2"))
    selected = set(filter(None, os.environ.get("PYFASTHASH_BENCH_KERNELS", "").split(",")))
    data = bytes(range(256)) * (input_mib * 4096)
    mib = len(data) / (1024 * 1024)
    print(f"Machine: {cpu_name()} ({platform.machine()}, Python {platform.python_version()})")
    print(f"Input: {mib:.1f} MiB deterministic byte buffer; best of 3 runs")
    print()
    print("| kernel | Mojo | pure Python reference | speedup |")
    print("|---|---:|---:|---:|")
    for name, reference in CASES:
        if selected and name not in selected:
            continue
        hasher = getattr(pyhash, name)()
        mojo_s = best_time(lambda: hasher(data))
        ref_s = best_time(lambda: reference(data))
        print(
            f"| {name} | {mojo_s * 1e3:.2f} ms | {ref_s * 1e3:.2f} ms | "
            f"{ref_s / mojo_s:.2f}x |"
        )


if __name__ == "__main__":
    main()
