import re
from urllib.parse import unquote
from collections import defaultdict
from typing import List, Dict, Any

class ThreatDetector:
    def __init__(self, brute_force_threshold: int = 5):
        self.brute_force_threshold = brute_force_threshold

        # Compile regex signatures for web attack patterns
        self.sqli_pattern = re.compile(
            r"(union(\s+all)?\s+select|select.*from|sleep\(|\b(and|or)\b\s+['\d]=['\d]|--|\bdrop\b\s+table)",
            re.IGNORECASE
        )
        
        self.traversal_pattern = re.compile(
            r"(\.\./|\.\.\\|%2e%2e%2f|%2e%2e/|/etc/passwd|/win\.ini|/boot\.ini)",
            re.IGNORECASE
        )
        
        self.scanner_pattern = re.compile(
            r"(nikto|sqlmap|nmap|acunetix|nessus|masscan|curl/|python-requests)",
            re.IGNORECASE
        )
        
        self.xss_pattern = re.compile(
            r"(<script.*?>|onerror\s*=|onload\s*=|javascript:)",
            re.IGNORECASE
        )

    def analyze_logs(self, entries: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Processes parsed log dictionaries and returns detected security incidents.
        """
        incidents = []
        failed_logins_per_ip = defaultdict(int)

        for entry in entries:
            # URL-decode URI to catch encoded attack vectors (e.g. %27 -> ')
            decoded_uri = unquote(entry['uri'])
            ip = entry['ip']
            user_agent = entry.get('user_agent', '')
            status = entry['status']
            line_no = entry.get('line_number', 0)

            # 1. SQL Injection Detection
            if self.sqli_pattern.search(decoded_uri):
                incidents.append({
                    "line": line_no,
                    "ip": ip,
                    "type": "SQL Injection",
                    "severity": "HIGH",
                    "payload": decoded_uri
                })

            # 2. Directory / Path Traversal Detection
            if self.traversal_pattern.search(decoded_uri):
                incidents.append({
                    "line": line_no,
                    "ip": ip,
                    "type": "Path Traversal",
                    "severity": "HIGH",
                    "payload": decoded_uri
                })

            # 3. Cross-Site Scripting (XSS) Detection
            if self.xss_pattern.search(decoded_uri):
                incidents.append({
                    "line": line_no,
                    "ip": ip,
                    "type": "XSS Probe",
                    "severity": "MEDIUM",
                    "payload": decoded_uri
                })

            # 4. Known Security Scanner User-Agent Detection
            if self.scanner_pattern.search(user_agent):
                incidents.append({
                    "line": line_no,
                    "ip": ip,
                    "type": "Automated Scanner",
                    "severity": "LOW",
                    "payload": user_agent
                })

            # 5. Track failed authentications for brute-force analysis
            if status in (401, 403) and ("login" in decoded_uri.lower() or "token" in decoded_uri.lower() or "auth" in decoded_uri.lower()):
                failed_logins_per_ip[ip] += 1

        # Evaluate brute force attacks against threshold
        brute_force_alerts = []
        for ip, count in failed_logins_per_ip.items():
            if count >= self.brute_force_threshold:
                brute_force_alerts.append({
                    "ip": ip,
                    "failed_attempts": count,
                    "severity": "HIGH",
                    "type": "Brute Force Authentication"
                })

        return {
            "total_requests": len(entries),
            "incidents": incidents,
            "brute_force_threats": brute_force_alerts
        }

if __name__ == "__main__":
    from parser import parse_log_file

    print("[*] Running Threat Detection Engine...")
    logs = parse_log_file("logs/sample_access.log")
    detector = ThreatDetector(brute_force_threshold=5)
    report = detector.analyze_logs(logs)

    print("\n" + "=" * 60)
    print(f" LOGLENS THREAT REPORT | Total Analyzed: {report['total_requests']}")
    print("=" * 60)

    print(f"\n[!] Flagged Pattern Incidents ({len(report['incidents'])} detected):")
    for inc in report['incidents']:
        print(f" - [Line {inc['line']}] [{inc['severity']}] {inc['type']} from {inc['ip']} -> {inc['payload'][:60]}")

    print(f"\n[!] Brute-Force Attacks ({len(report['brute_force_threats'])} detected):")
    for bf in report['brute_force_threats']:
        print(f" - [{bf['severity']}] {bf['type']} from {bf['ip']} ({bf['failed_attempts']} failed attempts)")
    print("=" * 60)