"""
detector.py  -  WEEK 2: The Threat Detection Engine   (reused in Week 4)
==================================================================
NOTE
    Week 4 changes the PARSER and the AGGREGATOR, not the detection
    rules. `scan()` already accepted any iterable, so the streaming
    pipeline plugs into this class with zero changes - the payoff for
    writing it that way in Week 2.

    Read week2_detection/detector.py for the full explanation.

GOAL OF THIS FILE
    Take the structured records from parser.py and decide which ones
    look like an attack.

    1. Signature rules (regex) -> SQLi, XSS, traversal, scanners, ...
    2. Behaviour rules          -> brute force (many 401/403 from one IP)

    Output: a list of "incidents". Each incident says WHAT happened,
    WHO did it, WHICH line it came from, and HOW BAD it is.

KEY IDEA: THE RULES LIVE IN A DATA FILE
    The regexes are NOT hardcoded here. They live in signatures.json
    so a security analyst can add a new attack pattern without editing
    Python. That is exactly what the brief asks for ("a JSON file
    containing the attack patterns").

HOW TO RUN (CLI demo)
    python cli.py ../../demo_logs/demo_attacks.log
==================================================================
"""

import json                                     # read signatures.json
import re                                       # compile the patterns
import os                                       # build the default path to signatures.json
from collections import defaultdict             # auto-creating counters: {ip: count}
from typing import Any, Dict, Iterable, List, Optional
from urllib.parse import unquote                # decode %27 -> ' and %2e%2e -> ..

# Where the signature file lives by default: next to THIS python file.
DEFAULT_SIGNATURES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "signatures.json")

# Severity ranking. Used to sort incidents worst-first and to pick the
# "worst severity" for an attacker that used several techniques.
SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


# ------------------------------------------------------------------
# 1. LOADING THE SIGNATURE DATABASE
# ------------------------------------------------------------------
def load_signatures(path: str = DEFAULT_SIGNATURES) -> Dict[str, Any]:
    """
    Read signatures.json and pre-compile every regex.

    Why compile? re.compile() turns a pattern string into an optimised
    matcher. Compiling once and reusing it is roughly 3-10x faster than
    letting re.search() re-parse the string on every one of 1,000,000
    log lines.
    """

    # encoding="utf-8" because descriptions may contain non-ASCII text.
    with open(path, "r", encoding="utf-8") as handle:
        config = json.load(handle)

    # JSON can only store text/numbers/lists/dicts, never regex objects.
    # So we add a "_regex" key at runtime, after loading.
    for signature in config["signatures"]:
        signature["_regex"] = re.compile(signature["pattern"], re.IGNORECASE)

    # Sort so the most severe rules run first (nice when displaying).
    config["signatures"].sort(
        key=lambda sig: SEVERITY_ORDER.get(sig["severity"], 0),
        reverse=True,
    )

    return config


# ------------------------------------------------------------------
# 2. THE DETECTOR
# ------------------------------------------------------------------
class ThreatDetector:
    """
    Holds the loaded rules and scans parsed log entries.

    Typical use:
        detector = ThreatDetector()
        incidents, brute_force = detector.scan(entries)
    """

    def __init__(
        self,
        signatures_path: str = DEFAULT_SIGNATURES,
        brute_force_threshold: Optional[int] = None,
    ):
        # Load rules (and their compiled regexes).
        self.config = load_signatures(signatures_path)
        self.signatures = self.config["signatures"]

        # Brute-force settings come from the same JSON file, but the
        # caller may override the threshold from the UI/CLI.
        brute = self.config.get("brute_force", {})
        self.failed_status_codes = set(brute.get("status_codes", [401, 403]))
        self.brute_threshold = (
            brute_force_threshold
            if brute_force_threshold is not None
            else brute.get("threshold", 5)
        )
        self.window_minutes = brute.get("window_minutes", 10)

        # Stats for the dashboard: how often did each rule fire?
        self.hits_per_signature = defaultdict(int)

    # --------------------------------------------------------------
    def scan_path(self, entry: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Run every signature against ONE entry.

        Returns a list because one request can break several rules at
        once (a sqlmap request with a UNION SELECT matches both SQLI-002
        and SCAN-001).
        """
        # The raw path still contains %27 and %2e%2e. Attackers encode
        # precisely to dodge filters, so we decode BEFORE matching.
        decoded_path = unquote(entry.get("path") or "")

        # Some servers log the full URL, some just the path. Unquoting
        # is safe: a legit "%20" simply becomes a space.
        user_agent = entry.get("user_agent") or ""

        found = []

        for signature in self.signatures:

            # Which text should this rule inspect?
            target = signature.get("target", "path")
            if target == "path":
                haystack = decoded_path
            elif target == "user_agent":
                haystack = user_agent
            else:                       # "any" -> both fields
                haystack = decoded_path + " " + user_agent

            # .search() looks ANYWHERE in the string (not just the start).
            if signature["_regex"].search(haystack):
                self.hits_per_signature[signature["id"]] += 1

                found.append({
                    "signature_id": signature["id"],
                    "signature_name": signature["name"],
                    "type": signature["type"],
                    "severity": signature["severity"],
                    "cwe": signature.get("cwe"),
                    # Evidence: the decoded path for URL rules, the
                    # user-agent for agent rules. Truncated to 300 chars
                    # so one giant payload cannot bloat the report.
                    "payload": (haystack if target != "path" else decoded_path)[:300],
                })

        return found

    # --------------------------------------------------------------
    def scan(self, entries: Iterable[Dict[str, Any]], progress=None):
        """
        Scan many entries.

        'entries' is an ITERABLE, not a list - so this same method works
        in Week 2 (list from parse_file) and Week 4 (generator from a
        streaming parser) without any changes.

        Returns (incidents, brute_force_alerts).
        """
        incidents = []

        # ip -> list of entries that failed authentication.
        # defaultdict(list) creates the empty list automatically.
        failures_by_ip = defaultdict(list)

        for index, entry in enumerate(entries):

            # ---- A. signature matching ---------------------------
            for match in self.scan_path(entry):
                incidents.append({
                    "line": entry.get("line_number"),
                    "ip": entry["ip"],
                    "timestamp": entry.get("timestamp"),
                    "method": entry.get("method"),
                    "path": entry.get("path"),
                    "status": entry.get("status"),
                    **match,          # merge signature_id/type/severity/payload into this dict
                })

            # ---- B. collect failed logins -----------------------
            if entry["status"] in self.failed_status_codes:
                # Only "authentication-ish" endpoints count. Otherwise a
                # site with 500 broken links would look like a brute force.
                path_lower = (entry.get("path") or "").lower()
                if any(word in path_lower for word in ("login", "signin", "auth", "token", "admin", "wp-login")):
                    failures_by_ip[entry["ip"]].append(entry)

            # ---- C. progress callback (used by Week 4's job queue) ---
            if progress is not None and index % 500 == 0:
                progress(index, entry)

        # ---- D. turn the counters into alerts -------------------
        brute_force = []
        for ip, failed_entries in failures_by_ip.items():
            if len(failed_entries) >= self.brute_threshold:
                # Sort by time so first/last are meaningful.
                times = [e["timestamp"] for e in failed_entries if e.get("timestamp")]
                times.sort()

                brute_force.append({
                    "ip": ip,
                    "type": "brute_force",
                    "severity": "high",
                    "signature_id": "BF-001",
                    "signature_name": "Brute force authentication",
                    "failed_attempts": len(failed_entries),
                    "threshold": self.brute_threshold,
                    "first_seen": times[0] if times else None,
                    "last_seen": times[-1] if times else None,
                    "target_paths": sorted({e.get("path") for e in failed_entries})[:5],
                })

        # Worst attackers first.
        brute_force.sort(key=lambda alert: alert["failed_attempts"], reverse=True)

        return incidents, brute_force


# ------------------------------------------------------------------
# 3. Quick manual test
# ------------------------------------------------------------------
if __name__ == "__main__":
    import sys
    from parser import parse_file
    from aggregator import aggregate

    target = sys.argv[1] if len(sys.argv) > 1 else "../../demo_logs/demo_attacks.log"
    parsed = parse_file(target)
    detector = ThreatDetector()
    incidents, brute = detector.scan(parsed["entries"])
    report = aggregate(parsed, incidents, brute)

    print(f"[+] {len(incidents)} signature incidents, {len(brute)} brute-force IPs")
    print(f"[+] Top attacker: {report['top_attackers'][0] if report['top_attackers'] else 'none'}")
