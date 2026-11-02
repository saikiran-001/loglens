# Week 2 — Detection Logic (Identification)

> **Deadline goal:** "Build the Signature Database. Run the parsed logs against the signatures. Aggregation logic (count attacks by IP)."

---

## 1. What this week delivers

| PDF task | Where it lives |
|---|---|
| Signature database | `signatures.json` (15 rules) |
| Run logs against signatures | `detector.py` → `ThreatDetector.scan()` |
| Aggregation (count attacks by IP) | `aggregator.py` → `aggregate()` |
| Something you can demo | `cli.py` + the web app on port 5002 |

```powershell
cd week2_detection
python cli.py ..\demo_logs\demo_attacks.log      # terminal report
python app.py                                    # web UI, port 5002
```

---

## 2. The pipeline in one picture

```
parse_file()        ThreatDetector.scan()          aggregate()
raw lines  ──►  dicts  ──►  incidents + brute force  ──►  report (JSON)
                             (flat list)                  (grouped)
```

Notice the **two different shapes**:

- `incidents` is *per request* — line 42 was SQL injection.
- `report` is *per attacker / per hour / per type* — 45.155.205.233 sent 24 attacks.

Charts and tables want the second shape. That conversion is the whole point of `aggregator.py`.

---

## 3. Designing a signature rule

Each entry in `signatures.json`:

```json
{
  "id": "SQLI-002",
  "name": "SQL injection - UNION SELECT",
  "type": "sql_injection",
  "severity": "critical",
  "target": "path",
  "cwe": "CWE-89",
  "pattern": "\\bunion\\b[\\s+]+(?:all[\\s+]+)?\\bselect\\b",
  "description": "..."
}
```

Why each field exists:

| Field | Why it matters |
|---|---|
| `id` | Every finding is traceable back to one rule. Used in reports and false-positive tuning. |
| `type` | Groups findings for charts (`sql_injection`, `xss`, ...). |
| `severity` | Drives the colour and the block-list priority. |
| `target` | Should the rule inspect the URL, the User-Agent, or both? |
| `cwe` | Standard weakness ID — makes the report look professional and maps to real vuln databases. |
| `pattern` | The regex itself. **JSON has no regex type**, so it is a string that we `re.compile()` at load time. |

> **JSON escaping gotcha:** inside a JSON string a backslash must be doubled. To match a literal `.` you write `\\.` in JSON, which becomes `\.` for Python. Forgetting this is the #1 source of broken signatures.

### Why not hardcode the patterns in Python?

The brief explicitly asks for a JSON file, but there is a real engineering reason too: a security analyst can add a new attack pattern, reload, and be protected **without a code review or redeploy**. This is how real SIEM/Snort/YARA rule sets work.

---

## 4. Decode before you match (the step beginners skip)

Attackers send `%27%20OR%20%271%27%3D%271` because a naive filter looks for `' OR '1'='1` and sees nothing. So `scan_path()` does:

```python
decoded_path = unquote(entry.get("path") or "")   # %27 -> '  and %2e%2e -> ..
```

Only *after* decoding do we run the regexes. That single line is why the demo's encoded SQLi payloads are caught.

Real-world nuance: some teams decode **twice** (double-encoding) — see `TRAV-003` which detects the `%25` prefix that survives one decode.

---

## 5. One request, several incidents

A single sqlmap request can match `SQLI-002` (UNION SELECT) **and** `SCAN-001` (sqlmap User-Agent). That is correct — two independent pieces of evidence.

But then "how many requests were malicious?" would over-count if we used `len(incidents)`. Hence:

```python
malicious_lines = {incident["line"] for incident in incidents}
attack_requests = len(malicious_lines)   # unique lines only
```

A `set` is the standard way to de-duplicate. Remember this pattern; you will use it constantly.

---

## 6. Behaviour rules vs signature rules

Signatures catch *what* was sent. Brute force is about *how often*:

```python
if entry["status"] in {401, 403} and path looks like a login -> count it
...
if count >= threshold: alert
```

Two design decisions worth arguing about:

1. **We only count authentication-looking paths** (`login`, `auth`, `token`, `admin`, `wp-login`). If we counted every 401, a site with a broken `401`-heavy API would raise constant false alerts.
2. **Threshold lives in the JSON** (`brute_force.threshold`, default 5) so it is configurable, not a magic number buried in code.

The brief mentions a *window* (N failures inside X minutes). Week 2 counts the whole file; the `window_minutes` value is already in the JSON so Week 4 can enforce it. This is a known, documented simplification.

---

## 7. Severity: how we rank an attacker with several techniques

An attacker may send one XSS probe and 500 SQLi attempts. Which badge do they get? The **worst** technique seen:

```python
SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
if rank(incident) > rank(bucket["worst"]):
    bucket["worst"] = incident["severity"]
```

---

## 8. The report shape (memorise this — Weeks 3 and 4 consume it)

```json
{
  "summary": {
    "total_lines": 79, "parsed_records": 78, "unparsed_lines": 1,
    "attack_requests": 35, "clean_requests": 43,
    "incidents": 59, "brute_force_ips": 2,
    "by_severity": {"critical": 13, "high": 12, "medium": 16, "low": 18},
    "by_type": {"scanner": 32, "sql_injection": 12, "path_traversal": 12, "xss": 3}
  },
  "incidents": [ { "line": 42, "ip": "...", "type": "sql_injection", ... } ],
  "brute_force": [ { "ip": "...", "failed_attempts": 12, ... } ],
  "attacks_by_ip": [ { "ip": "...", "hits": 24, "attack_types": {...}, ... } ],
  "top_attackers": [ ... first 10 of attacks_by_ip ... ],
  "by_hour": [ { "hour": "2026-10-20 16:00", "attacks": 12, "requests": 14 } ],
  "most_targeted": [ { "path": "/login.php", "hits": 12 } ],
  "errors": [ { "line": 79, "text": "this is not a log line at all" } ]
}
```

Keep this contract stable and every later feature is easy.

---

## 9. Checkpoint

- [ ] `python cli.py ..\demo_logs\demo_attacks.log` reports **59 incidents** and **2 brute-force IPs**
- [ ] The terminal report lists `45.155.205.233` with `sql_injection`
- [ ] You can add a new rule to `signatures.json` and see it fire without touching Python
- [ ] You can explain why `unquote()` is called before matching
- [ ] You can explain the difference between `len(incidents)` and `attack_requests`

---

## 10. Practice

- Add a rule for `xmlrpc.php` abuse (WordPress) with `"target": "path"`.
- Add a `headers` target so a rule can scan the Referer too. *(Hint: parser already keeps `referer`.)*
- Make `brute_force` enforce `window_minutes` using timestamps.
- Break something on purpose: remove the double backslashes in `SQLI-002` and see the JSON/regex error. That memory will save you an hour someday.

---

**Next:** [`week3_visualization/README.md`](../week3_visualization/README.md) — charts, GeoIP and the real dashboard.
