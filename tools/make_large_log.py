"""
make_large_log.py  -  build a big log file for performance testing
==================================================================
WHY
    Week 4 claims "streaming keeps memory flat". Prove it to yourself:
    generate a 100 MB log and compare the Week-2 parser with the
    Week-4 parser (see tools/benchmark.py).

HOW TO RUN
    python tools/make_large_log.py            # ~25 MB
    python tools/make_large_log.py 200        # ~100 MB (200 x demo log)

The generated file is written to demo_logs/large_access.log and is
git-ignored, because it is big and reproducible.
==================================================================
"""

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
SOURCE = PROJECT_ROOT / "demo_logs" / "demo_attacks.log"
TARGET = PROJECT_ROOT / "demo_logs" / "large_access.log"


def main() -> None:
    # sys.argv[1] is the number of copies; default 50 (~1 MB x 50).
    copies = int(sys.argv[1]) if len(sys.argv) > 1 else 50

    base_lines = SOURCE.read_text(encoding="utf-8").splitlines()

    # Write incrementally instead of building one giant string in RAM -
    # the generator of a big file should not itself need big memory.
    with open(TARGET, "w", encoding="utf-8", newline="\n") as handle:
        for _ in range(copies):
            for line in base_lines:
                handle.write(line)
                handle.write("\n")

    size_mb = TARGET.stat().st_size / (1024 * 1024)
    print(f"[+] Wrote {copies * len(base_lines):,} lines ({size_mb:.1f} MB) to {TARGET}")


if __name__ == "__main__":
    main()
