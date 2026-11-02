import re
from typing import Dict, List, Optional

# Regular expression matching standard Apache/Nginx Combined Log Format
LOG_PATTERN = re.compile(
    r'^(?P<ip>\S+)\s+'                # Client IP address
    r'\S+\s+'                         # Remote logname (identd, usually '-')
    r'(?P<user>\S+)\s+'               # Authenticated user ID (usually '-')
    r'\[(?P<timestamp>[^\]]+)\]\s+'   # Date and time enclosed in brackets
    r'"(?P<method>[A-Z]+)\s+'         # HTTP Request Method (GET, POST, etc.)
    r'(?P<uri>\S+)\s+'                # Requested URI path and query string
    r'(?P<protocol>[^"]+)"\s+'        # Protocol (e.g. HTTP/1.1)
    r'(?P<status>\d{3})\s+'           # HTTP Status Code (200, 401, 404, etc.)
    r'(?P<bytes>\S+)\s+'              # Size of object returned in bytes
    r'"(?P<referer>[^"]*)"\s+'        # Referer header
    r'"(?P<user_agent>[^"]*)"$'       # User-Agent string
)

def parse_log_line(line: str) -> Optional[Dict[str, str]]:
    """
    Parses a single line of an Apache/Nginx log into a structured dictionary.
    Returns None if the line does not match the expected format.
    """
    match = LOG_PATTERN.match(line.strip())
    if match:
        data = match.groupdict()
        data['status'] = int(data['status'])
        data['bytes'] = int(data['bytes']) if data['bytes'].isdigit() else 0
        return data
    return None

def parse_log_file(filepath: str) -> List[Dict[str, str]]:
    """
    Reads a log file and returns a list of parsed entry dictionaries.
    """
    parsed_entries = []
    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            entry = parse_log_line(line)
            if entry:
                entry['line_number'] = line_num
                parsed_entries.append(entry)
            else:
                print(f"[!] Warning: Could not parse line {line_num}: {line}")
    return parsed_entries

if __name__ == "__main__":
    import sys
    test_file = sys.argv[1] if len(sys.argv) > 1 else "logs/sample_access.log"
    print(f"[*] Reading and parsing {test_file}...")
    results = parse_log_file(test_file)
    print(f"[+] Successfully parsed {len(results)} log entries.")
    if results:
        print("[*] Sample parsed record:")
        print(results[0])