"""
cli.py  -  WEEK 2: command-line version of the full pipeline
==================================================================
WHY KEEP A CLI WHEN THERE IS A WEB UI?
    A CLI is the fastest way to test the engine. No browser, no HTML,
    no JavaScript. If the numbers here are wrong, the dashboard will
    only show wrong numbers more beautifully.

PIPELINE
    parse_file()  ->  ThreatDetector.scan()  ->  aggregate()  ->  print/JSON

HOW TO RUN
    python cli.py ../../demo_logs/demo_attacks.log
    python cli.py ../../demo_logs/demo_attacks.log --threshold 3 --output report.json
==================================================================
"""

import argparse      # turns command-line flags into Python variables
import json          # --output writes a .json report
import os            # file existence check
import sys           # sys.exit() for error codes

from parser import parse_file
from detector import ThreatDetector
from aggregator import aggregate


def print_report(report: dict) -> None:
    """Pretty-print the aggregated report to the terminal."""

    summary = report["summary"]

    print()
    print("=" * 72)
    print("  LOGLENS SECURITY REPORT")
    print("=" * 72)
    print(f"  Lines read          : {summary['total_lines']}")
    print(f"  Parsed records      : {summary['parsed_records']}")
    print(f"  Unparsed lines      : {summary['unparsed_lines']}")
    print(f"  Malicious requests  : {summary['attack_requests']}")
    print(f"  Clean requests      : {summary['clean_requests']}")
    print(f"  Signature incidents : {summary['incidents']}")
    print(f"  Brute-force IPs     : {summary['brute_force_ips']}")

    # ---- severity table ------------------------------------------
    if summary["by_severity"]:
        print("\n  Findings by severity")
        for severity in ("critical", "high", "medium", "low"):
            count = summary["by_severity"].get(severity, 0)
            if count:
                # '█' * count gives a tiny terminal bar chart.
                print(f"    {severity:<9} {count:>4}  {'█' * min(count, 40)}")

    # ---- attack type table --------------------------------------
    if summary["by_type"]:
        print("\n  Findings by attack type")
        for attack_type, count in sorted(summary["by_type"].items(), key=lambda kv: -kv[1]):
            print(f"    {attack_type:<20} {count:>4}")

    # ---- top attackers ------------------------------------------
    print("\n  Top attackers")
    if report["top_attackers"]:
        print(f"    {'IP':<18}{'HITS':>6}  {'WORST':<9} TECHNIQUES")
        for row in report["top_attackers"][:10]:
            techniques = ", ".join(row["attack_types"].keys())
            print(f"    {row['ip']:<18}{row['hits']:>6}  {row['worst_severity']:<9} {techniques}")
    else:
        print("    none - all traffic looks benign")

    # ---- brute force detail -------------------------------------
    if report["brute_force"]:
        print("\n  Brute-force details")
        for alert in report["brute_force"]:
            print(f"    {alert['ip']} -> {alert['failed_attempts']} failed logins "
                  f"({alert['first_seen']} .. {alert['last_seen']})")

    # ---- most targeted paths ------------------------------------
    if report["most_targeted"]:
        print("\n  Most targeted URLs")
        for row in report["most_targeted"][:5]:
            print(f"    {row['hits']:>4}x  {row['path'][:70]}")

    # ---- mitigation advice --------------------------------------
    blocked = [row["ip"] for row in report["top_attackers"]]
    print("\n  Recommended action")
    if blocked:
        print(f"    Block {len(blocked)} IP(s): {', '.join(blocked[:6])}")
        print("    (firewall rule, WAF, or Cloudflare rate limit)")
    else:
        print("    No action required.")

    # ---- unparsed line reminder ---------------------------------
    if summary["unparsed_lines"]:
        print(f"\n  Note: {summary['unparsed_lines']} line(s) could not be parsed "
              "- see report['errors'].")

    print("=" * 72 + "\n")


def main() -> None:
    # argparse reads flags like  --file x --threshold 5
    argument_parser = argparse.ArgumentParser(
        description="LogLens - detect attacks in Apache/Nginx access logs"
    )
    # A positional argument (no dashes) is required by default.
    argument_parser.add_argument("logfile", help="path to the access log")
    argument_parser.add_argument(
        "-t", "--threshold", type=int, default=None,
        help="failed logins per IP before it counts as brute force (default: from signatures.json)",
    )
    argument_parser.add_argument(
        "-o", "--output", default=None,
        help="optional path to write the full JSON report",
    )
    args = argument_parser.parse_args()

    # Fail early with a readable message instead of a traceback.
    if not os.path.exists(args.logfile):
        print(f"[-] File not found: {args.logfile}")
        sys.exit(1)

    print(f"[*] Parsing {args.logfile} ...")
    parsed = parse_file(args.logfile)

    if not parsed["entries"]:
        print("[-] No valid log lines found. Is this an Apache/Nginx access log?")
        sys.exit(1)

    print(f"[*] Scanning {len(parsed['entries'])} records against "
          f"{len(ThreatDetector().signatures)} signatures ...")
    detector = ThreatDetector(brute_force_threshold=args.threshold)
    incidents, brute_force = detector.scan(parsed["entries"])

    report = aggregate(parsed, incidents, brute_force)

    print_report(report)

    # Optional JSON export - the same shape the web UI receives.
    if args.output:
        with open(args.output, "w", encoding="utf-8") as handle:
            json.dump(report, handle, indent=2)
        print(f"[+] JSON report written to {args.output}")


if __name__ == "__main__":
    main()
