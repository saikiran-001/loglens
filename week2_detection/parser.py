"""
parser.py  -  WEEK 1: The Parser Engine   (copied unchanged into Week 2)
==================================================================
NOTE
    Week 2 only adds detection, so this file is identical to
    week1_parsing/parser.py. Read that copy for the full explanation
    of the regexes; the code here is the same.

GOAL OF THIS FILE
    Turn a plain-text Apache/Nginx log line:

        192.168.1.15 - - [27/Oct/2026:10:00:01 +0000] "GET /index.html HTTP/1.1" 200 4520 "-" "Mozilla/5.0 ..."

    ...into a Python dictionary:

        {"ip": "192.168.1.15", "method": "GET", "path": "/index.html", ...}

    That is the whole job. Everything else in the project (detection,
    charts, maps) only works because this file did its job first.

THE FORMAT WE PARSE
    "Combined Log Format" (Apache and Nginx both write it by default):

        IP  ident  user  [time]  "METHOD PATH PROTOCOL"  STATUS  BYTES  "REFERER"  "USER-AGENT"

    The older "Common Log Format" is the same but WITHOUT the last two
    quoted fields, so we keep a second regex for it.

HOW TO RUN (quick test)
    python parser.py ../../demo_logs/demo_attacks.log
==================================================================
"""

import re                                    # Python's regular-expression engine
from datetime import datetime                # needed to turn the timestamp text into a real date object
from typing import Any, Dict, Iterator, Optional   # type hints - they document the shapes of our data

# ------------------------------------------------------------------
# 1. THE REGEX
# ------------------------------------------------------------------
# re.VERBOSE lets us spread the pattern over several lines and add
# comments with '#'. Whitespace inside the pattern is ignored, so every
# literal space must be written as \s+.
#
# (?P<name>...) is a NAMED GROUP. Whatever it matches becomes
# result["name"]. This is how we avoid juggling 9 anonymous groups.
# ------------------------------------------------------------------

COMBINED_PATTERN = re.compile(
    r"""
    ^                                   # start of the line
    (?P<ip>\S+)                         # client IP address, no spaces
    \s+                                 # one or more spaces
    (?P<ident>\S+)                      # identd field, almost always "-"
    \s+
    (?P<user>\S+)                       # authenticated username, usually "-"
    \s+
    \[(?P<time>[^\]]+)\]                # [timestamp]; "[^]]+" = everything until the closing bracket
    \s+
    "(?P<request>[^"]*)"                # "GET /path HTTP/1.1"; [^"]* = everything until the next quote
    \s+
    (?P<status>\d{3})                   # exactly 3 digits: 200, 401, 404 ...
    \s+
    (?P<size>\d+|-)                     # bytes sent, or "-" when the server sent no body
    \s+
    "(?P<referer>[^"]*)"                # which page linked here
    \s+
    "(?P<agent>[^"]*)"                  # browser / scanner user-agent string
    \s*$                                # optional trailing spaces, then end of line
    """,
    re.VERBOSE,                         # allow the layout + comments above
)

# Same idea, but stops after the byte count (no referer / user-agent).
COMMON_PATTERN = re.compile(
    r"""
    ^
    (?P<ip>\S+)
    \s+
    (?P<ident>\S+)
    \s+
    (?P<user>\S+)
    \s+
    \[(?P<time>[^\]]+)\]
    \s+
    "(?P<request>[^"]*)"
    \s+
    (?P<status>\d{3})
    \s+
    (?P<size>\d+|-)
    \s*$
    """,
    re.VERBOSE,
)

# The "request" field above is itself three values glued together:
#   "GET /index.html?x=1 HTTP/1.1"
# This second regex splits it into method / path / protocol.
REQUEST_PATTERN = re.compile(r"^(?P<method>[A-Z]+)\s+(?P<path>\S+)(?:\s+(?P<protocol>\S+))?$")

# Python needs to know how the timestamp is laid out.
#   %d day, %b short month name, %Y year, %H hour, %M minute, %S second,
#   %z UTC offset (+0000).
TIME_FORMAT = "%d/%b/%Y:%H:%M:%S %z"

# Nginx/Apache sometimes log a literal "-" for a request (e.g. health checks
# or malformed traffic). We treat those as an unknown method/path instead of
# throwing them away, so nothing in the file is silently lost.
UNKNOWN_REQUEST = {"method": "-", "path": "-", "protocol": "-"}


# ------------------------------------------------------------------
# 2. PARSING ONE LINE
# ------------------------------------------------------------------
def parse_line(line: str) -> Optional[Dict[str, Any]]:
    """
    Parse ONE log line.

    Returns a dict on success, or None when the line is not a valid log
    line. Returning None (instead of raising) is deliberate: real log
    files always contain junk lines, and one bad line must never stop
    the whole analysis.
    """

    # .strip() removes the newline at the end (and any stray spaces).
    text = line.strip()

    # Skip empty lines immediately - cheaper than running the regex.
    if not text:
        return None

    # Try the Combined format first (it is what modern servers write).
    match = COMBINED_PATTERN.match(text)

    # If that failed, try the older Common format.
    if not match:
        match = COMMON_PATTERN.match(text)

    # Still nothing? This line is garbage -> tell the caller.
    if not match:
        return None

    # .groupdict() returns {"ip": "...", "status": "200", ...} with every
    # named group. This is why named groups are worth the extra typing.
    raw = match.groupdict()

    # ---- Split the request field ---------------------------------
    request_text = raw.get("request") or ""
    request_match = REQUEST_PATTERN.match(request_text)

    if request_match:
        request = request_match.groupdict()
    else:
        # Malformed request (e.g. "-") -> keep the line but mark it unknown.
        request = dict(UNKNOWN_REQUEST)

    # ---- Convert text into proper Python types -------------------
    # Numbers are stored as ints so later code can compare them
    # (status == 401) without converting every time.
    status = int(raw["status"])

    # "-" means "no size", which we record as 0 bytes.
    size_text = raw.get("size") or "-"
    size = int(size_text) if size_text.isdigit() else 0

    # Timestamps arrive as text; convert to a datetime so we can group
    # attacks by hour in Week 3.
    timestamp = parse_timestamp(raw["time"])

    # ---- Build the final, clean record ---------------------------
    return {
        "ip": raw["ip"],
        "ident": raw["ident"],
        "user": raw["user"] if raw["user"] != "-" else None,   # None is nicer than "-"
        "timestamp": timestamp,          # datetime object (or None if unparseable)
        "time_raw": raw["time"],         # keep the original text too, for display
        "method": request["method"],
        "path": request["path"],
        "protocol": request["protocol"],
        # Combined-only fields: .get() returns None for Common-format lines.
        "referer": raw.get("referer"),
        "user_agent": raw.get("agent"),
        "status": status,
        "size": size,
        # True when the URL looked suspicious enough to decode later.
        # (Detection happens in week 2; here we only store the raw values.)
        "raw": text,
    }


def parse_timestamp(text: str) -> Optional[datetime]:
    """
    Turn '27/Oct/2026:10:00:01 +0000' into a datetime object.

    Some servers use a non-English month name or a weird offset. If
    strptime raises ValueError we return None instead of crashing.
    """
    try:
        # strptime = "string parse time" - it reads text using a format.
        return datetime.strptime(text, TIME_FORMAT)
    except ValueError:
        # Recover from a missing timezone, e.g. '27/Oct/2026:10:00:01'.
        try:
            return datetime.strptime(text, "%d/%b/%Y:%H:%M:%S")
        except ValueError:
            return None   # hopeless - keep the line, just without a date


# ------------------------------------------------------------------
# 3. PARSING A WHOLE FILE
# ------------------------------------------------------------------
def parse_file(path: str) -> Dict[str, Any]:
    """
    Read a log file and return BOTH the good records and the failures.

    Week 1 loads the file into memory because it keeps the code simple
    and easy to read. Week 4 fixes this with streaming - see
    week4_optimization/parser.py for the production version.

    Return shape:
        {
          "entries": [ {...}, {...} ],     # successfully parsed lines
          "errors":  [ (line_no, text) ],  # lines we could not parse
          "total_lines": 140,
        }
    """

    entries = []          # every successfully parsed record
    errors = []           # (line number, raw text) of lines that failed
    total_lines = 0       # counts every physical line, good or bad

    # encoding="utf-8" is the norm; errors="replace" swaps undecodable
    # bytes for a placeholder instead of crashing on odd encodings.
    with open(path, "r", encoding="utf-8", errors="replace") as handle:

        # enumerate(handle, 1) gives us (1, first_line), (2, second_line) ...
        for line_number, line in enumerate(handle, 1):
            total_lines += 1

            parsed = parse_line(line)

            if parsed is None:
                # Blank lines are normal noise - do not report them as errors.
                if line.strip():
                    errors.append((line_number, line.strip()))
                continue

            # Remember where in the file this record came from.
            # Very useful when you want to open the log and look at it.
            parsed["line_number"] = line_number
            entries.append(parsed)

    return {
        "entries": entries,
        "errors": errors,
        "total_lines": total_lines,
    }


# ------------------------------------------------------------------
# 4. BONUS (week 4 preview): stream instead of loading everything
# ------------------------------------------------------------------
def iter_entries(path: str) -> Iterator[Dict[str, Any]]:
    """
    Yield one parsed record at a time instead of building a list.

    'yield' makes this a GENERATOR: it produces values lazily, so memory
    usage stays flat even for a 5 GB file. Week 4 relies on this idea.
    """
    with open(path, "r", encoding="utf-8", errors="replace") as handle:
        for line_number, line in enumerate(handle, 1):
            parsed = parse_line(line)
            if parsed is not None:
                parsed["line_number"] = line_number
                yield parsed


# ------------------------------------------------------------------
# 5. Command-line smoke test
# ------------------------------------------------------------------
if __name__ == "__main__":
    import sys
    import json

    # sys.argv[1] is whatever you typed after the file name.
    target = sys.argv[1] if len(sys.argv) > 1 else "../../demo_logs/demo_attacks.log"

    print(f"[*] Parsing {target} ...")
    result = parse_file(target)

    print(f"[+] Lines read    : {result['total_lines']}")
    print(f"[+] Parsed records: {len(result['entries'])}")
    print(f"[+] Unparsed lines: {len(result['errors'])}")

    if result["entries"]:
        print("\n[*] First parsed record:")
        # default=str makes datetime objects printable as text.
        print(json.dumps(result["entries"][0], indent=2, default=str))

    if result["errors"]:
        print("\n[!] Lines that could not be parsed:")
        for line_number, text in result["errors"]:
            print(f"    line {line_number}: {text[:80]}")
