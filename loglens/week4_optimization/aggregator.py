"""
aggregator.py  -  WEEK 4: Streaming aggregation
==================================================================
WHAT CHANGED SINCE WEEK 2
    Week 2's aggregate() needed the full list of parsed entries, because
    it looped over them to count requests per hour. But Week 4 streamed
    the file and threw each entry away after scanning it - so there is
    no list to loop over.

    The fix: aggregate WHILE streaming.

        Week 2:  file -> [all entries] -> aggregate -> report
        Week 4:  file -> (entry -> collector) -> report

    The collector keeps only small counters (hour -> count), which is a
    few hundred integers instead of millions of dicts.

THREE EXPORTS
    build_report(...)   pure function that assembles the final dict
    aggregate(...)      Week-2 style convenience wrapper (list in)
    StreamCollector     incremental version used by the job queue
==================================================================
"""

from collections import Counter, defaultdict
from typing import Any, Dict, List, Optional


# ------------------------------------------------------------------
# 1. build_report - the single source of truth for the output shape
# ------------------------------------------------------------------
def build_report(
    *,
    total_lines: int,
    total_requests: int,
    unparsed_count: int,
    errors: List[tuple],
    incidents: List[Dict[str, Any]],
    brute_force: List[Dict[str, Any]],
    requests_per_hour: Counter,
) -> Dict[str, Any]:
    """
    Assemble the report dictionary.

    Every argument is keyword-only (the leading '*'), because eight
    positional parameters are impossible to read at a call site:

        build_report(total_lines=79, total_requests=78, ...)
    """

    # A request can trigger several signatures. Count each LINE once.
    malicious_lines = {incident["line"] for incident in incidents}
    attack_requests = len(malicious_lines)

    by_severity = Counter(i["severity"] for i in incidents)
    by_type = Counter(i["type"] for i in incidents)

    # ---- Per-IP aggregation -------------------------------------
    per_ip = defaultdict(lambda: {
        "hits": 0,
        "types": Counter(),
        "worst": "low",
        "first_seen": None,
        "last_seen": None,
    })

    for incident in incidents:
        bucket = per_ip[incident["ip"]]
        bucket["hits"] += 1
        bucket["types"][incident["type"]] += 1

        if _rank(incident["severity"]) > _rank(bucket["worst"]):
            bucket["worst"] = incident["severity"]

        stamp = incident.get("timestamp")
        if stamp:
            if bucket["first_seen"] is None or stamp < bucket["first_seen"]:
                bucket["first_seen"] = stamp
            if bucket["last_seen"] is None or stamp > bucket["last_seen"]:
                bucket["last_seen"] = stamp

    # Pure brute force may produce no signature incident at all.
    for alert in brute_force:
        bucket = per_ip[alert["ip"]]
        bucket["hits"] += alert["failed_attempts"]
        bucket["types"]["brute_force"] += alert["failed_attempts"]
        if _rank("high") > _rank(bucket["worst"]):
            bucket["worst"] = "high"

    attacks_by_ip = [
        {
            "ip": ip,
            "hits": data["hits"],
            "worst_severity": data["worst"],
            "attack_types": dict(data["types"]),
            "first_seen": _iso(data["first_seen"]),
            "last_seen": _iso(data["last_seen"]),
        }
        for ip, data in per_ip.items()
    ]
    attacks_by_ip.sort(key=lambda row: row["hits"], reverse=True)

    # ---- Timeline ------------------------------------------------
    attacks_per_hour = Counter()
    for incident in incidents:
        if incident.get("timestamp"):
            attacks_per_hour[incident["timestamp"].strftime("%Y-%m-%d %H:00")] += 1

    for alert in brute_force:
        if alert.get("first_seen"):
            attacks_per_hour[alert["first_seen"].strftime("%Y-%m-%d %H:00")] += alert["failed_attempts"]

    # Union of both sets so the chart has no misleading gaps.
    all_hours = sorted(set(requests_per_hour) | set(attacks_per_hour))
    by_hour = [
        {"hour": hour,
         "attacks": attacks_per_hour.get(hour, 0),
         "requests": requests_per_hour.get(hour, 0)}
        for hour in all_hours
    ]

    # ---- Most targeted URLs --------------------------------------
    path_counter = Counter(incident["path"] for incident in incidents)
    most_targeted = [{"path": path, "hits": hits}
                     for path, hits in path_counter.most_common(10)]

    return {
        "summary": {
            "total_lines": total_lines,
            "parsed_records": total_requests,
            "unparsed_lines": unparsed_count,
            "attack_requests": attack_requests,
            "clean_requests": total_requests - attack_requests,
            "incidents": len(incidents),
            "brute_force_ips": len(brute_force),
            "by_severity": dict(by_severity),
            "by_type": dict(by_type),
        },
        "incidents": [_serialise_incident(i) for i in incidents],
        "brute_force": [_serialise_alert(a) for a in brute_force],
        "attacks_by_ip": attacks_by_ip,
        "top_attackers": attacks_by_ip[:10],
        "by_hour": by_hour,
        "most_targeted": most_targeted,
        "errors": [{"line": number, "text": text} for number, text in errors[:50]],
    }


# ------------------------------------------------------------------
# 2. StreamCollector - aggregate while reading
# ------------------------------------------------------------------
class StreamCollector:
    """
    Feed it one entry at a time; it keeps only counters.

        collector = StreamCollector()
        for entry in iter_entries(path):
            collector.add(entry)
        report = collector.build(incidents, brute_force)

    Memory: a Counter with one key per hour. For 24 hours that is 24
    integers - versus 3 million dicts in the Week-2 approach.
    """

    def __init__(self):
        self.total_lines = 0
        self.total_requests = 0
        self.unparsed = 0
        self.errors: List[tuple] = []
        self.requests_per_hour = Counter()

    def set_total_lines(self, value: int) -> None:
        """The parser knows the physical line count (including junk)."""
        self.total_lines = value

    def add(self, entry: Dict[str, Any]) -> None:
        """Account for one successfully parsed entry."""
        self.total_requests += 1
        if entry.get("timestamp"):
            self.requests_per_hour[entry["timestamp"].strftime("%Y-%m-%d %H:00")] += 1

    def add_error(self, line_number: int, text: str) -> None:
        """Remember a broken line (capped so a corrupt file cannot eat RAM)."""
        self.unparsed += 1
        if len(self.errors) < 50:
            self.errors.append((line_number, text))

    def build(self, incidents, brute_force) -> Dict[str, Any]:
        return build_report(
            total_lines=self.total_lines,
            total_requests=self.total_requests,
            unparsed_count=self.unparsed,
            errors=self.errors,
            incidents=incidents,
            brute_force=brute_force,
            requests_per_hour=self.requests_per_hour,
        )


# ------------------------------------------------------------------
# 3. aggregate - Week-2 compatible wrapper (small files, tests, CLI)
# ------------------------------------------------------------------
def aggregate(parsed: Dict[str, Any], incidents, brute_force) -> Dict[str, Any]:
    """Build a report from a parse_file() result (everything in memory)."""
    collector = StreamCollector()
    collector.set_total_lines(parsed["total_lines"])

    for entry in parsed["entries"]:
        collector.add(entry)

    for line_number, text in parsed["errors"]:
        collector.add_error(line_number, text)

    return collector.build(incidents, brute_force)


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------
def _rank(severity: str) -> int:
    return {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}.get(severity, 0)


def _iso(value):
    return value.isoformat() if value is not None else None


def _serialise_incident(incident: Dict[str, Any]) -> Dict[str, Any]:
    output = dict(incident)
    output["timestamp"] = _iso(output.get("timestamp"))
    return output


def _serialise_alert(alert: Dict[str, Any]) -> Dict[str, Any]:
    output = dict(alert)
    output["first_seen"] = _iso(output.get("first_seen"))
    output["last_seen"] = _iso(output.get("last_seen"))
    return output
