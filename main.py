import argparse
import json
import os
import sys
from parser import parse_log_file
from detector import ThreatDetector

def generate_text_summary(report: dict, filepath: str) -> None:
    print("\n" + "=" * 65)
    print(f" LOGLENS SECURITY AUDIT REPORT")
    print(f" Target File: {filepath}")
    print(f" Total Log Records Analyzed: {report['total_requests']}")
    print("=" * 65)

    print(f"\n[+] Detected Incidents: {len(report['incidents'])}")
    if report['incidents']:
        for inc in report['incidents']:
            print(f"  * Line {inc['line']:<3} | [{inc['severity']}] {inc['type']:<22} | IP: {inc['ip']:<15} | {inc['payload'][:45]}")
    else:
        print("  None detected.")

    print(f"\n[+] Brute-Force Authentication Alerts: {len(report['brute_force_threats'])}")
    if report['brute_force_threats']:
        for bf in report['brute_force_threats']:
            print(f"  * [{bf['severity']}] {bf['type']} from {bf['ip']} ({bf['failed_attempts']} failures)")
    else:
        print("  None detected.")

    print("\n" + "=" * 65)
    print(" MITIGATION & RECOMMENDED ACTIONS")
    print("=" * 65)
    flagged_ips = set([inc['ip'] for inc in report['incidents']] + [bf['ip'] for bf in report['brute_force_threats']])
    if flagged_ips:
        for ip in sorted(flagged_ips):
            print(f"  [!] Block IP: {ip} via firewall (iptables / UFW) or Cloudflare rate-limiting rules.")
    else:
        print("  All requests appear benign.")
    print("=" * 65 + "\n")

def main():
    parser = argparse.ArgumentParser(description="LogLens - Automated Security Log Analysis Tool")
    parser.add_argument("-f", "--file", required=True, help="Path to the Apache/Nginx access log file")
    parser.add_argument("-t", "--threshold", type=int, default=5, help="Brute force threshold (default: 5)")
    parser.add_argument("-o", "--output", help="Optional path to export findings as JSON")

    args = parser.parse_args()

    if not os.path.exists(args.file):
        print(f"[-] Error: File '{args.file}' not found.")
        sys.exit(1)

    print(f"[*] Ingesting and parsing '{args.file}'...")
    entries = parse_log_file(args.file)
    if not entries:
        print("[-] No valid log entries found.")
        sys.exit(1)

    print(f"[*] Running detection engine against {len(entries)} entries...")
    detector = ThreatDetector(brute_force_threshold=args.threshold)
    report = detector.analyze_logs(entries)

    generate_text_summary(report, args.file)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=4)
        print(f"[+] Full JSON audit report exported to: {args.output}")

if __name__ == "__main__":
    main()