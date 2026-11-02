"""
geoip.py  -  WEEK 3: Where are the attackers?   (copied into Week 4)
==================================================================
NOTE
    Identical to week3_visualization/geoip.py. Full explanation there.

GOAL OF THIS FILE
    Turn "45.155.205.233" into "Russia (Moscow)" plus latitude/longitude
    so the dashboard can drop a marker on a map.

TWO WAYS TO DO IT
    1. REAL     - MaxMind GeoLite2 City database (free, needs a signup).
                  Download "GeoLite2-City.mmdb" into week3_visualization/data/
                  and this module finds it automatically.
    2. FALLBACK - a small built-in table covering the demo IPs, so the
                  project works offline and in a classroom.

    The fallback exists on purpose: a demo that crashes because you
    forgot a 60 MB binary file is a bad demo.

HOW IT WORKS INTERNALLY
    An IP address is just a 32-bit number. MaxMind ships ranges
    ("from this number to that number = Germany, Frankfurt"). The
    maxminddb library does a binary search in the .mmdb file.
==================================================================
"""

import ipaddress                     # stdlib: tells us if an IP is private / invalid
import os                            # join paths, check existence

# ---- Optional dependency -----------------------------------------
# We wrap the import in try/except so the whole project still runs on
# a machine that never installed maxminddb.
try:
    import maxminddb
except ImportError:
    maxminddb = None


BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# MaxMind ships .mmdb files; put yours here.
DB_PATH = os.path.join(BASE_DIR, "data", "GeoLite2-City.mmdb")

# Default answer when we know nothing about an IP.
UNKNOWN = {
    "country_code": "--",
    "country": "Unknown",
    "city": "",
    "lat": None,
    "lon": None,
}

# ------------------------------------------------------------------
# Offline fallback table.
# Coordinates are (latitude, longitude); negative = south / west.
# These are the IPs used by demo_logs/demo_attacks.log plus a few
# well-known addresses you might see in real logs.
# ------------------------------------------------------------------
DEMO_GEO = {
    "45.155.205.233": ("RU", "Russia", "Moscow", 55.7558, 37.6173),
    "103.21.244.12": ("IN", "India", "Mumbai", 19.0760, 72.8777),
    "185.220.101.7": ("NL", "Netherlands", "Amsterdam", 52.3676, 4.9041),
    "89.248.165.74": ("NL", "Netherlands", "Amsterdam", 52.3676, 4.9041),
    "198.51.100.23": ("DE", "Germany", "Frankfurt", 50.1109, 8.6821),
    "203.0.113.50": ("US", "United States", "Ashburn", 39.0438, -77.4874),
    "192.0.2.44": ("CN", "China", "Beijing", 39.9042, 116.4074),
    "8.8.8.8": ("US", "United States", "Mountain View", 37.3860, -122.0838),
    "1.1.1.1": ("AU", "Australia", "Sydney", -33.8688, 151.2093),
}

# Emoji flags make the table readable without any image assets.
FLAGS = {
    "RU": "🇷🇺", "IN": "🇮🇳", "NL": "🇳🇱", "DE": "🇩🇪", "US": "🇺🇸",
    "CN": "🇨🇳", "AU": "🇦🇺", "LAN": "🏠", "--": "❔",
}


class GeoLookup:
    """
    Wraps maxminddb (when available) and falls back to DEMO_GEO.

    Usage:
        geo = GeoLookup()
        geo.lookup("45.155.205.233") -> dict
    """

    def __init__(self, db_path: str = DB_PATH):
        self.reader = None

        # Only open the database if BOTH the library and the file exist.
        if maxminddb is not None and os.path.exists(db_path):
            # Mode "MODE_MMAP_EXT" memory-maps the file: lookups do not
            # load the whole 60 MB into RAM.
            self.reader = maxminddb.open_database(db_path)
            print(f"[+] GeoIP: using MaxMind database {db_path}")
        else:
            print("[i] GeoIP: using built-in demo table "
                  "(drop GeoLite2-City.mmdb in data/ for real lookups)")

    def lookup(self, ip: str) -> dict:
        """Return {country_code, country, city, lat, lon} for one IP."""

        # ---- 0. Is this even a valid IP? ---------------------------
        try:
            address = ipaddress.ip_address(ip)
        except ValueError:
            # Not an IP at all (e.g. "unknown") -> unknown result.
            return dict(UNKNOWN)

        # ---- 1. Real database -------------------------------------
        if self.reader is not None:
            # maxminddb returns None when the IP is not in the data.
            record = self.reader.get(ip)
            if record:
                country = record.get("country", {})
                city = record.get("city", {})
                location = record.get("location", {})
                code = country.get("iso_code", "--")
                return {
                    "country_code": code,
                    "country": country.get("names", {}).get("en", "Unknown"),
                    "city": city.get("names", {}).get("en", ""),
                    "lat": location.get("latitude"),
                    "lon": location.get("longitude"),
                }

        # ---- 2. Built-in demo table -------------------------------
        # IMPORTANT: this must run BEFORE the private-range check.
        # Python's ipaddress module treats documentation ranges like
        # 203.0.113.0/24 and 192.0.2.0/24 as "not public", so those
        # demo attackers would otherwise be mislabelled "Private network".
        if ip in DEMO_GEO:
            code, country, city, lat, lon = DEMO_GEO[ip]
            return {"country_code": code, "country": country,
                    "city": city, "lat": lat, "lon": lon}

        # ---- 3. Private / local addresses -------------------------
        # 192.168.x.x, 10.x.x.x, 127.0.0.1 etc. never appear in a
        # GeoIP database, and looking them up would raise.
        if address.is_private or address.is_loopback or address.is_link_local:
            return {
                "country_code": "LAN",
                "country": "Private network",
                "city": "Local",
                "lat": None,
                "lon": None,
            }

        # ---- 4. Nothing known -------------------------------------
        return dict(UNKNOWN)

    def close(self):
        """Release the mmap file handle (called when the app shuts down)."""
        if self.reader is not None:
            self.reader.close()


def flag(country_code: str) -> str:
    """Return the emoji flag for a country code, or a question mark."""
    return FLAGS.get(country_code, "🌐")


def enrich_report(report: dict, geo: GeoLookup) -> dict:
    """
    Add geo fields to every row of attacks_by_ip and build a
    country-level summary for the map / pie chart.

    We MUTATE the report in place (add keys) and also return it, so
    callers can do either:
        enrich_report(report, geo)
        report = enrich_report(report, geo)
    """
    # country_code -> {"country": str, "hits": int, "ips": set()}
    by_country = {}

    for row in report.get("attacks_by_ip", []):
        info = geo.lookup(row["ip"])

        # Copy geo keys straight onto the attacker row.
        row.update(info)
        row["flag"] = flag(info["country_code"])

        bucket = by_country.setdefault(
            info["country_code"],
            {"country_code": info["country_code"],
             "country": info["country"],
             "hits": 0,
             "ips": set()},
        )
        bucket["hits"] += row["hits"]
        bucket["ips"].add(row["ip"])

    # Sets are not JSON-serialisable, so convert to a count.
    country_rows = []
    for bucket in by_country.values():
        country_rows.append({
            "country_code": bucket["country_code"],
            "country": bucket["country"],
            "hits": bucket["hits"],
            "ip_count": len(bucket["ips"]),
            "flag": flag(bucket["country_code"]),
        })

    country_rows.sort(key=lambda item: item["hits"], reverse=True)
    report["by_country"] = country_rows

    # Brute-force alerts also deserve a country flag in the table.
    for alert in report.get("brute_force", []):
        info = geo.lookup(alert["ip"])
        alert.update(info)
        alert["flag"] = flag(info["country_code"])

    return report


# ------------------------------------------------------------------
# Smoke test
# ------------------------------------------------------------------
if __name__ == "__main__":
    import sys

    geo = GeoLookup()
    targets = sys.argv[1:] or ["45.155.205.233", "192.168.1.15", "8.8.8.8", "nonsense"]

    for target in targets:
        result = geo.lookup(target)
        print(f"{target:<18} {flag(result['country_code'])} "
              f"{result['country']:<16} {result['city']:<12} "
              f"{result['lat']}, {result['lon']}")
