"""
aggregator.py  -  WEEK 2: Aggregation logic
==================================================================
GOAL OF THIS FILE
    The brief says: "Aggregation logic (count attacks by IP)".

    Raw incidents are a long flat list - one row per bad request. That
    is not what a human wants to read, and it is not what a chart needs.
    This file turns the flat list into the shapes that matter:

        attacks_by_ip     who attacked, how many times, worst severity
        by_type           how many SQLi vs XSS vs traversal
        by_severity       how many critical / high / medium / low
        by_hour           attacks per hour  -> Week 3 line chart
        top_attackers     the first 10 rows for a table
        most_targeted    which URLs were probed most

WHY A SEPARATE FILE?
    Week 3 (charts) and Week 4 (async jobs + CSV export) both need
    exactly these numbers. Keeping them in one tested place means the
    dashboard code only worries about drawing.
==================================================================
"""

from collections import Counter, defaultdict   # Counter counts things; defaultdict auto-creates buckets
from typing import Any, Dict, List


def aggregate(
    parsed: Dict[str, Any],
    incidents: List[Dict[str, Any]],
    brute_force: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """
    Build the full report dictionary.

    Parameters
    ----------
    parsed       : output of parser.parse_file() -> entries / errors / total_lines
    incidents    : output of ThreatDetector.scan()[0]
    brute_force  : output of ThreatDetector.scan()[1]

    Returns a JSON-serialisable dict. Dates are converted to ISO text so
    json.dump() and Flask can both send it to the browser.
    """

    entries = parsed["entries"]

    # ---- 1. Basic counters ------------------------------------------
    total_requests = len(entries)

    # A single request can fire several signatures. For "how many
    # REQUESTS were malicious" we only want each line once, so we use a
    # set of line numbers (a set cannot contain duplicates).
    malicious_lines = {incident["line"] for incident in incidents}
    attack_requests = len(malicious_lines)

    # ---- 2. Severity breakdown --------------------------------------
    by_severity = Counter(incident["severity"] for incident in incidents)

    # ---- 3. Attack-type breakdown -----------------------------------
    by_type = Counter(incident["type"] for incident in incidents)

    # ---- 4. Per-IP aggregation (the core Week 2 deliverable) --------
    # For every attacker IP we want: how many hits, which techniques,
    # when they started, when they stopped, and how bad it got.
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

        # Keep the most severe technique seen for this IP.
        if _rank(incident["severity"]) > _rank(bucket["worst"]):
            bucket["worst"] = incident["severity"]

        # Track the time window of the attack.
        stamp = incident.get("timestamp")
        if stamp:
            if bucket["first_seen"] is None or stamp < bucket["first_seen"]:
                bucket["first_seen"] = stamp
            if bucket["last_seen"] is None or stamp > bucket["last_seen"]:
                bucket["last_seen"] = stamp

    # Brute-force IPs may not have any signature hit at all (a pure
    # password-guessing attack looks like normal traffic). Add them so
    # "top attackers" does not miss the most dangerous actor.
    for alert in brute_force:
        bucket = per_ip[alert["ip"]]
        bucket["hits"] += alert["failed_attempts"]
        bucket["types"]["brute_force"] += alert["failed_attempts"]
        if _rank("high") > _rank(bucket["worst"]):
            bucket["worst"] = "high"

    # Convert the defaultdict into a plain sorted list (JSON-friendly).
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

    # ---- 5. Timeline: attacks (and traffic) per hour ---------------
    # We bucket by the text "2026-10-20 14:00". Using the timestamp's
    # own hour keeps the buckets local to the log's timezone.
    requests_per_hour = Counter()
    attacks_per_hour = Counter()

    for entry in entries:
        stamp = entry.get("timestamp")
        if stamp:
            requests_per_hour[stamp.strftime("%Y-%m-%d %H:00")] += 1

    for incident in incidents:
        stamp = incident.get("timestamp")
        if stamp:
            attacks_per_hour[stamp.strftime("%Y-%m-%d %H:00")] += 1

    # Brute force has no single line, so we add its volume to the hour
    # the attack started - a reasonable approximation for a chart.
    for alert in brute_force:
        stamp = alert.get("first_seen")
        if stamp:
            attacks_per_hour[stamp.strftime("%Y-%m-%d %H:00")] += alert["failed_attempts"]

    # The chart x-axis must contain every hour that had traffic, even
    # hours with zero attacks, otherwise the line jumps across gaps.
    all_hours = sorted(set(requests_per_hour) | set(attacks_per_hour))
    by_hour = [
        {
            "hour": hour,
            "attacks": attacks_per_hour.get(hour, 0),
            "requests": requests_per_hour.get(hour, 0),
        }
        for hour in all_hours
    ]

    # ---- 6. Most probed URLs ---------------------------------------
    path_counter = Counter(incident["path"] for incident in incidents)
    most_targeted = [
        {"path": path, "hits": hits}
        for path, hits in path_counter.most_common(10)
    ]

    # ---- 7. Assemble the report ------------------------------------
    return {
        "summary": {
            "total_lines": parsed["total_lines"],
            "parsed_records": total_requests,
            "unparsed_lines": len(parsed["errors"]),
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
        "errors": [
            {"line": line_number, "text": text}
            for line_number, text in parsed["errors"][:50]
        ],
    }


# ------------------------------------------------------------------
# Small helpers
# ------------------------------------------------------------------
def _rank(severity: str) -> int:
    """Turn a severity name into a number so we can compare them."""
    return {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}.get(severity, 0)


def _iso(value):
    """datetime -> '2026-10-20T14:05:00+00:00' (JSON has no date type)."""
    return value.isoformat() if value is not None else None


def _serialise_incident(incident: Dict[str, Any]) -> Dict[str, Any]:
    """Copy an incident and make its timestamp JSON-safe."""
    output = dict(incident)
    output["timestamp"] = _iso(output.get("timestamp"))
    return output


def _serialise_alert(alert: Dict[str, Any]) -> Dict[str, Any]:
    """Copy a brute-force alert and make its timestamps JSON-safe."""
    output = dict(alert)
    output["first_seen"] = _iso(output.get("first_seen"))
    output["last_seen"] = _iso(output.get("last_seen"))
    return output
