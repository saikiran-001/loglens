"""
make_demo_log.py  -  Builds demo_logs/demo_attacks.log
==================================================================
WHY THIS FILE EXISTS
    LogLens needs a realistic log file that is FULL of attacks so the
    "Load Demo Log" button (weeks 3-4) has something interesting to show.

WHAT IT DOES
    Writes ~140 lines of Apache "Combined Log Format" text:
      * normal visitors (private / benign IPs)
      * SQL injection attempts
      * XSS attempts
      * path traversal attempts
      * a brute-force attack (many 401s from one IP)
      * automated scanner traffic (sqlmap, nikto, nmap user-agents)

HOW TO RUN
    python tools/make_demo_log.py
==================================================================
"""

import random                       # gives us random-ish variation in the fake traffic
from datetime import datetime, timedelta   # used to create timestamps that move forward in time
from pathlib import Path            # modern, cross-platform way to build file paths

# Seed the random generator so every run produces the SAME demo file.
# (Reproducibility is nice when you are learning: your output matches mine.)
random.seed(42)

# The folder this script lives in is  <project>/tools , so the project root is one level up.
PROJECT_ROOT = Path(__file__).resolve().parent.parent

# Where the finished demo log will be written.
OUTPUT_FILE = PROJECT_ROOT / "demo_logs" / "demo_attacks.log"

# ------------------------------------------------------------------
# The fake actors. Each entry is: (ip, country-ish label, user-agent)
# ------------------------------------------------------------------
NORMAL_IPS = ["192.168.1.15", "192.168.1.20", "192.168.1.31", "10.0.0.5"]
NORMAL_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:121.0) Gecko/20100101",
]

# Each attacker: IP -> (user agent used, path they hammer)
ATTACKERS = {
    "45.155.205.233": ("sqlmap/1.7.2#stable (https://sqlmap.org)", "/product.php?id=%s"),
    "103.21.244.12": ("Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36", "/search?q=%s"),
    "185.220.101.7": ("Mozilla/5.0 (X11; Linux x86_64) curl/8.4.0", "/download?file=%s"),
    "203.0.113.50": ("python-requests/2.31.0", "/login.php"),
    "89.248.165.74": ("Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)", "/"),
    "198.51.100.23": ("Mozilla/5.0 (compatible; Nikto/2.5.0)", "/admin"),
    "192.0.2.44": ("Mozilla/5.0 (Windows NT 10.0; Win64; x64)", "/wp-login.php"),
}

# Payloads that our week-2 signature database must catch.
SQLI_PAYLOADS = [
    "1' OR '1'='1",
    "1 UNION SELECT username,password FROM users",
    "1'; DROP TABLE users;--",
    "1 AND SLEEP(5)",
]
XSS_PAYLOADS = [
    "<script>alert('xss')</script>",
    "\"><img src=x onerror=alert(1)>",
    "javascript:alert(document.cookie)",
]
TRAVERSAL_PAYLOADS = [
    "../../../../etc/passwd",
    "..%2f..%2f..%2fetc%2fpasswd",
    "....//....//windows/win.ini",
]

# ------------------------------------------------------------------
# Helper: build one log line in Apache Combined Log Format.
# ------------------------------------------------------------------
def encode_url(payload):
    """
    A URL can never contain a literal space - the browser/tool sends %20.
    We encode only the spaces so the payload still looks readable in the
    demo file while staying a VALID log line (the parser splits on spaces).
    """
    return payload.replace(" ", "%20")


def make_line(ip, method, path, status, size, agent, when, referer="-"):
    """Return one correctly formatted log line WITHOUT the trailing newline."""
    # %d/%b/%Y:%H:%M:%S %z  ->  e.g. 23/Oct/2026:14:05:09 +0000
    stamp = when.strftime("%d/%b/%Y:%H:%M:%S +0000")
    return (
        f'{ip} - - [{stamp}] "{method} {path} HTTP/1.1" '
        f'{status} {size} "{referer}" "{agent}"'
    )


def main():
    lines = []                       # we collect every line here, then write once

    # Day of the demo traffic.
    day = datetime(2026, 10, 20, 0, 0, 0)

    # ---- 1. Benign background traffic, spread over 24 hours -------------
    benign_paths = ["/", "/index.html", "/about.html", "/style.css", "/logo.png",
                    "/contact.html", "/blog", "/pricing"]
    for hour in range(24):                    # one or two visits per hour
        for _ in range(random.randint(1, 2)):
            ip = random.choice(NORMAL_IPS)     # pick a normal visitor
            path = random.choice(benign_paths)
            when = day + timedelta(hours=hour, minutes=random.randint(0, 59))
            lines.append(make_line(ip, "GET", path, 200,
                                   random.randint(900, 15000),
                                   random.choice(NORMAL_AGENTS), when,
                                   referer="http://example.com/"))

    # ---- 2. SQL injection wave (03:00 - 05:00) --------------------------
    for hour in (3, 4, 5):
        for i in range(4):
            when = day + timedelta(hours=hour, minutes=i * 7)
            payload = random.choice(SQLI_PAYLOADS)
            path = f"/product.php?id={encode_url(payload)}"
            lines.append(make_line("45.155.205.233", "GET", path,
                                   random.choice([200, 500]), 312,
                                   ATTACKERS["45.155.205.233"][0], when))

    # ---- 3. XSS probes (08:00 - 10:00) ----------------------------------
    for hour in (8, 9, 10):
        payload = random.choice(XSS_PAYLOADS)
        when = day + timedelta(hours=hour, minutes=random.randint(1, 50))
        path = f"/search?q={encode_url(payload)}"
        lines.append(make_line("103.21.244.12", "GET", path, 200, 980,
                               ATTACKERS["103.21.244.12"][0], when))

    # ---- 4. Directory traversal (12:00 - 13:00) -------------------------
    for hour in (12, 13):
        for payload in TRAVERSAL_PAYLOADS:
            when = day + timedelta(hours=hour, minutes=random.randint(1, 55))
            path = f"/download?file={encode_url(payload)}"
            lines.append(make_line("185.220.101.7", "GET", path, 403, 199,
                                   ATTACKERS["185.220.101.7"][0], when))

    # ---- 5. Brute force on /login.php (16:00 - 16:10) -------------------
    # 12 failed logins from a single IP -> week-2 brute-force rule fires (threshold 5).
    for i in range(12):
        when = day + timedelta(hours=16, minutes=i // 2, seconds=(i % 2) * 20)
        lines.append(make_line("203.0.113.50", "POST",
                               "/login.php", 401, 532,
                               ATTACKERS["203.0.113.50"][0], when))

    # ---- 6. Scanner sweep (18:00 - 19:00) ------------------------------
    when = day + timedelta(hours=18, minutes=5)
    lines.append(make_line("89.248.165.74", "GET", "/", 200, 4520,
                           ATTACKERS["89.248.165.74"][0], when))
    when = day + timedelta(hours=18, minutes=12)
    lines.append(make_line("198.51.100.23", "GET", "/admin", 404, 0,
                           ATTACKERS["198.51.100.23"][0], when))

    # ---- 7. Credential stuffing against WordPress (21:00 - 22:00) ------
    for i in range(8):
        when = day + timedelta(hours=21, minutes=i * 4)
        lines.append(make_line("192.0.2.44", "POST", "/wp-login.php", 403, 0,
                               ATTACKERS["192.0.2.44"][0], when))

    # ---- 8. Add a deliberately broken line -----------------------------
    # The parser must survive garbage input instead of crashing (Week 1 goal).
    lines.append("this is not a log line at all")

    # Randomise the order a little so the file looks like real traffic,
    # but keep the timestamps roughly in order for a nicer timeline chart.
    lines.sort(key=lambda line: line.split("[")[1][:14] if "[" in line else "zzz")

    # Make sure the target folder exists (parents=True creates demo_logs/ too).
    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)

    # Write everything with Windows-safe newlines.
    OUTPUT_FILE.write_text("\n".join(lines) + "\n", encoding="utf-8")

    print(f"[+] Wrote {len(lines)} log lines to {OUTPUT_FILE}")


# This guard means main() only runs when you execute the file directly,
# not when another module imports it.
if __name__ == "__main__":
    main()
