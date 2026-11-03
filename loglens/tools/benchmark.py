"""
benchmark.py  -  WEEK 4: prove that streaming uses less memory
==================================================================
WHAT IT COMPARES
    A) "load everything"  - week2_detection/parser.py  parse_file()
    B) "stream"           - week4_optimization/parser.py iter_entries()

HOW MEMORY IS MEASURED
    tracemalloc tracks Python allocations. It under-reports C-level
    buffers, but it is perfectly good enough to show the difference
    between "3 million dicts in a list" and "one dict at a time".

HOW TO RUN
    python tools/make_large_log.py 200
    python tools/benchmark.py

Both parsers are loaded through importlib with explicit module names,
because they are both called parser.py in different folders and would
otherwise overwrite each other in sys.modules.
==================================================================
"""

import importlib.util
import sys
import time
import tracemalloc
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
LOG_FILE = PROJECT_ROOT / "demo_logs" / "large_access.log"


def load_module(name: str, path: Path):
    """Import a module from an explicit file path."""
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module          # register before exec (dataclasses need this)
    spec.loader.exec_module(module)
    return module


def measure(label: str, function) -> None:
    """Run a function and report wall time + peak Python memory."""
    # gc.collect() first so leftovers from the previous run do not skew
    # the baseline measurement.
    import gc
    gc.collect()

    tracemalloc.start()
    started = time.perf_counter()

    result = function()

    elapsed = time.perf_counter() - started
    _current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    print(f"{label:<28} {elapsed:>7.2f} s   peak {peak / (1024 * 1024):>7.1f} MB   ({result})")


def main() -> None:
    if not LOG_FILE.exists():
        print(f"[-] {LOG_FILE} not found.")
        print("    Run: python tools/make_large_log.py 200")
        sys.exit(1)

    size_mb = LOG_FILE.stat().st_size / (1024 * 1024)
    print(f"[i] File: {LOG_FILE} ({size_mb:.1f} MB)")
    print()

    week2 = load_module("week2_parser", PROJECT_ROOT / "week2_detection" / "parser.py")
    week4 = load_module("week4_parser", PROJECT_ROOT / "week4_optimization" / "parser.py")

    # A) Week 2: everything in a list.
    measure(
        "A) load all (week 2)",
        lambda: f"{len(week2.parse_file(str(LOG_FILE))['entries']):,} entries",
    )

    # B) Week 4: generator, count as we go, store nothing.
    def stream_count() -> str:
        count = 0
        for _entry in week4.iter_entries(str(LOG_FILE)):
            count += 1
        return f"{count:,} entries"

    measure("B) stream (week 4)", stream_count)

    print()
    print("[i] Same work, same result - watch the peak memory column.")


if __name__ == "__main__":
    main()
