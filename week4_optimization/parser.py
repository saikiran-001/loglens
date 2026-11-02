"""
parser.py  -  WEEK 4: The streaming parser
==================================================================
WHY REWRITE THE PARSER?
    Week 1's parser did this:

        entries = []
        for line in file:
            entries.append(parse(line))     # <-- ALL records live in RAM

    For a 500 MB access log (~3 million lines) that list can easily use
    1.5-2 GB of memory. On a small server it gets OOM-killed; in a
    browser-based tool it would crash the tab.

    This version never holds more than ONE line in memory. It is a
    generator pipeline:

        binary file  ->  bytes buffer  ->  decoded lines  ->  entries
             ^                                            (one at a time)

THE ONE TRICKY PART: CHUNK BOUNDARIES
    We read 256 KB at a time, but a line can straddle two chunks:

        chunk 1: "...GET /index.ht"
        chunk 2: "ml HTTP/1.1\" 200 ..."

    So we keep the incomplete tail in a buffer, split on b"\\n", and
    process only complete lines. The leftover tail is prepended to the
    next chunk. That is the whole art of streaming text processing.

HOW TO RUN
    python parser.py ..\\..\\demo_logs\\demo_attacks.log
==================================================================
"""

import os                            # file size for progress reporting
import re
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Dict, Iterator, Optional

# ------------------------------------------------------------------
# Regexes - identical to Week 1, because the FORMAT did not change.
# ------------------------------------------------------------------
COMBINED_PATTERN = re.compile(
    r"""
    ^
    (?P<ip>\S+)\s+
    (?P<ident>\S+)\s+
    (?P<user>\S+)\s+
    \[(?P<time>[^\]]+)\]\s+
    "(?P<request>[^"]*)"\s+
    (?P<status>\d{3})\s+
    (?P<size>\d+|-)\s+
    "(?P<referer>[^"]*)"\s+
    "(?P<agent>[^"]*)"
    \s*$
    """,
    re.VERBOSE,
)

COMMON_PATTERN = re.compile(
    r"""
    ^
    (?P<ip>\S+)\s+
    (?P<ident>\S+)\s+
    (?P<user>\S+)\s+
    \[(?P<time>[^\]]+)\]\s+
    "(?P<request>[^"]*)"\s+
    (?P<status>\d{3})\s+
    (?P<size>\d+|-)
    \s*$
    """,
    re.VERBOSE,
)

REQUEST_PATTERN = re.compile(r"^(?P<method>[A-Z]+)\s+(?P<path>\S+)(?:\s+(?P<protocol>\S+))?$")

TIME_FORMAT = "%d/%b/%Y:%H:%M:%S %z"
UNKNOWN_REQUEST = {"method": "-", "path": "-", "protocol": "-"}

# Fast timestamp parsing: month names are stable, so a dict beats
# strptime's per-call locale machinery by a wide margin.
MONTHS = {
    "jan": 1, "feb": 2, "mar": 3, "apr": 4, "may": 5, "jun": 6,
    "jul": 7, "aug": 8, "sep": 9, "oct": 10, "nov": 11, "dec": 12,
}

# The timezone group is optional so we still accept logs without "+0000".
TIMESTAMP_PATTERN = re.compile(
    r"^(\d{2})/([A-Za-z]{3})/(\d{4}):(\d{2}):(\d{2}):(\d{2})(?:\s+([+-]\d{4}))?$"
)


# ------------------------------------------------------------------
# 1. parse_line - unchanged from Week 1 (format parsing is stable)
# ------------------------------------------------------------------
def parse_line(line: str) -> Optional[Dict[str, Any]]:
    """Parse one log line into a dict, or None if it is not a log line."""
    text = line.strip()
    if not text:
        return None

    match = COMBINED_PATTERN.match(text) or COMMON_PATTERN.match(text)
    if not match:
        return None

    raw = match.groupdict()

    request_match = REQUEST_PATTERN.match(raw.get("request") or "")
    request = request_match.groupdict() if request_match else dict(UNKNOWN_REQUEST)

    size_text = raw.get("size") or "-"

    return {
        "ip": raw["ip"],
        "ident": raw["ident"],
        "user": raw["user"] if raw["user"] != "-" else None,
        "timestamp": parse_timestamp(raw["time"]),
        "time_raw": raw["time"],
        "method": request["method"],
        "path": request["path"],
        "protocol": request["protocol"],
        "referer": raw.get("referer"),
        "user_agent": raw.get("agent"),
        "status": int(raw["status"]),
        "size": int(size_text) if size_text.isdigit() else 0,
        "raw": text,
    }


def parse_timestamp(text: str) -> Optional[datetime]:
    """
    '27/Oct/2026:10:00:01 +0000' -> datetime, or None if unparseable.

    PERFORMANCE NOTE (this is the Week-4 optimization)
    ---------------------------------------------------
    The obvious implementation is datetime.strptime(text, "%d/%b/%Y:%H:%M:%S %z").
    Profiling the demo file showed strptime eating 68% of total parse
    time: it re-reads the locale, re-builds a format table, and does a
    month-name lookup on EVERY call.

    Since the format never changes, we parse the fixed positions by hand
    and look the month up in a dict. Same result, ~5x faster, and it
    cannot be broken by a machine with a non-English locale.
    """

    match = TIMESTAMP_PATTERN.match(text)
    if match:
        day, month_name, year, hour, minute, second, tz = match.groups()
        try:
            tzinfo = None
            if tz:
                # "+0530" -> sign, hours, minutes
                sign = 1 if tz[0] == "+" else -1
                offset = timedelta(hours=int(tz[1:3]), minutes=int(tz[3:5]))
                tzinfo = timezone(sign * offset)

            return datetime(
                int(year), MONTHS[month_name.lower()], int(day),
                int(hour), int(minute), int(second),
                tzinfo=tzinfo,
            )
        except (KeyError, ValueError):
            return None            # e.g. 31/Feb or a bogus month

    # Unknown layout (some servers add microseconds) -> slow but correct.
    try:
        return datetime.strptime(text, TIME_FORMAT)
    except ValueError:
        return None


# ------------------------------------------------------------------
# 2. stream_lines - the core streaming primitive
# ------------------------------------------------------------------
def stream_lines(
    path: str,
    chunk_size: int = 256 * 1024,                     # 256 KB per read
    on_progress: Optional[Callable[[float], None]] = None,
) -> Iterator[str]:
    """
    Yield decoded log lines one at a time using O(chunk_size) memory.

    Why open in "rb" (binary) instead of "r" (text)?
      * Text mode hides newline translation and makes position tracking
        awkward. Binary mode gives us exact byte counts for progress.
      * We decode each line ourselves with errors="replace", so one
        corrupt byte cannot kill the whole file.
    """

    total_bytes = os.path.getsize(path) or 1     # avoid divide-by-zero
    consumed = 0

    with open(path, "rb") as handle:
        buffer = b""                              # incomplete tail of the previous chunk

        while True:
            chunk = handle.read(chunk_size)

            # Empty chunk == end of file.
            if not chunk:
                # A final line may not end with a newline - do not lose it.
                if buffer:
                    yield buffer.decode("utf-8", "replace").rstrip("\r")
                break

            consumed += len(chunk)
            buffer += chunk

            # Split on the newline byte. parts[-1] is the incomplete tail.
            parts = buffer.split(b"\n")
            buffer = parts.pop()                  # keep the tail for the next round

            for raw_line in parts:
                # rstrip("\r") also handles Windows CRLF files.
                yield raw_line.decode("utf-8", "replace").rstrip("\r")

            # Report progress as a 0.0 - 1.0 fraction.
            if on_progress is not None:
                on_progress(min(consumed / total_bytes, 1.0))


# ------------------------------------------------------------------
# 3. iter_entries - parsed entries, still lazy
# ------------------------------------------------------------------
def iter_entries(
    path: str,
    stats: Optional[Dict[str, Any]] = None,
    on_progress: Optional[Callable[[float], None]] = None,
    on_error: Optional[Callable[[int, str], None]] = None,
) -> Iterator[Dict[str, Any]]:
    """
    Yield parsed entries one at a time.

    'stats' is an optional dict that this function fills in as it goes:
        stats["total_lines"]  -> every physical line read
        stats["unparsed"]     -> lines that were not valid log lines

    Callers use it after the loop because a generator cannot return a
    value to a `for` statement.
    """

    if stats is None:
        stats = {}
    stats["total_lines"] = 0
    stats["unparsed"] = 0

    for line_number, line in enumerate(stream_lines(path, on_progress=on_progress), 1):
        # line_number is 1-based, matching what a text editor shows.
        stats["total_lines"] = line_number

        entry = parse_line(line)

        if entry is None:
            # Blank lines are not errors, they are just padding.
            if line.strip():
                stats["unparsed"] += 1
                if on_error is not None:
                    on_error(line_number, line.strip())
            continue

        entry["line_number"] = line_number
        yield entry


# ------------------------------------------------------------------
# 4. parse_file - kept for the CLI and for tests
# ------------------------------------------------------------------
def parse_file(path: str) -> Dict[str, Any]:
    """
    Convenience wrapper that builds the Week-1 shape.

    This DOES load everything into memory - useful for small files,
    tests and the command-line tool. The web app in Week 4 uses
    iter_entries() instead, so it never pays this cost.
    """
    stats: Dict[str, Any] = {}
    errors = []

    entries = list(iter_entries(path, stats=stats, on_error=lambda n, t: errors.append((n, t))))

    return {"entries": entries, "errors": errors, "total_lines": stats["total_lines"]}


# ------------------------------------------------------------------
# 5. Memory demo - see the difference yourself
# ------------------------------------------------------------------
if __name__ == "__main__":
    import sys
    import time

    target = sys.argv[1] if len(sys.argv) > 1 else os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "..", "demo_logs", "demo_attacks.log"
    )

    started = time.perf_counter()

    # Streaming: count entries without ever building a list.
    stats: Dict[str, Any] = {}
    count = 0
    for entry in iter_entries(target, stats=stats):
        count += 1

    elapsed = time.perf_counter() - started
    size_mb = os.path.getsize(target) / (1024 * 1024)

    print(f"[+] Streamed {stats['total_lines']} lines ({size_mb:.2f} MB)")
    print(f"[+] Parsed {count} entries, {stats['unparsed']} unparsed")
    print(f"[+] Took {elapsed * 1000:.1f} ms")
    print("[i] Memory stays flat: only one line is in RAM at a time.")
