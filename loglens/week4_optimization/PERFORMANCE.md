# Performance Note

> Week 4 deliverable: *"Explain how you handled large files (streaming vs loading)."*

---

## 1. The problem, measured

`tools/benchmark.py` runs both parsers over the same file and reports wall time plus **peak Python memory** (`tracemalloc`).

Generate the test file, then run it:

```powershell
python tools\make_large_log.py 300      # ~3.4 MB, 23,700 lines
python tools\benchmark.py
```

Measured on this machine (Python 3.15, Windows):

| Approach | Time | Peak memory | Entries |
|---|---:|---:|---:|
| **A. Load everything** (`week2_detection/parser.py`) | 11.53 s | **26.1 MB** | 23,400 |
| **B. Stream** (`week4_optimization/parser.py`) | 2.90 s | **1.3 MB** | 23,400 |

Same result, **20× less memory and 4× faster**.

Extrapolate to a 500 MB log:

| | A. Load all | B. Stream |
|---|---:|---:|
| Peak memory | ~3.8 GB | ~1.3 MB |
| Feasible on a $5 VPS | ❌ OOM kill | ✅ |

Memory for approach A grows **linearly** with file size. Memory for B is **flat** — it is bounded by `chunk_size`, not by the log.

---

## 2. Why loading everything is dangerous

```python
entries = [parse(line) for line in file]   # 3 million dicts
```

Each record is a dict with ~13 keys. Python dicts are heavy: roughly **1 KB per record** once strings, key tables and object headers are counted. 3 million × ~1.2 KB ≈ **3.5 GB**.

Two more hidden costs:

1. `file.readlines()` / `list(f)` doubles the peak (text + list + dicts coexist).
2. A web request holding that list blocks the whole process, and the browser request times out long before the analysis ends.

---

## 3. What "streaming" actually means here

`week4_optimization/parser.py` → `stream_lines()`

```python
with open(path, "rb") as handle:
    buffer = b""
    while True:
        chunk = handle.read(256 * 1024)      # 256 KB, always
        if not chunk:
            break
        buffer += chunk
        parts = buffer.split(b"\n")
        buffer = parts.pop()                 # keep the unfinished tail
        for raw_line in parts:
            yield raw_line.decode("utf-8", "replace").rstrip("\r")
```

The three details that make it correct:

| Detail | Why it matters |
|---|---|
| Keep `parts.pop()` as the new buffer | A line can straddle two reads. Dropping the tail would corrupt one line per chunk. |
| Read **binary** (`"rb"`) | Exact byte counts for progress; no OS newline translation; we control decoding. |
| `errors="replace"` | One corrupt byte must not kill a 500 MB analysis. |

The final flush (`if buffer: yield ...`) handles a file whose last line has no trailing newline.

### Nothing accumulates

`iter_entries()` yields one dict; the detector consumes it and forgets it. The only things kept are **counters**: attacks per hour, per IP, per severity. For a 24-hour log that is a few dozen integers.

`week4_optimization/aggregator.py` makes this explicit with `StreamCollector`:

```python
for entry in entries:
    collector.add(entry)      # counters only
```

---

## 4. The timestamp optimization (a real 4× win)

Profiling with `cProfile` showed:

```
23,400 calls to parse_timestamp -> 2.69 s  (68% of total run time)
  └── datetime.strptime        -> 2.62 s
```

`strptime` rebuilds its format table and does a locale lookup **on every call**. The log format never changes, so Week 4 parses fixed positions instead:

```python
MONTHS = {"jan": 1, "feb": 2, ...}
TIMESTAMP_PATTERN = re.compile(r"^(\d{2})/([A-Za-z]{3})/(\d{4}):(\d{2}):(\d{2}):(\d{2})(?:\s+([+-]\d{4}))?$")
```

Result: **11.53 s → 2.90 s** on the same file, with an identical output. It also removes a subtle bug: `strptime("%b")` depends on the system locale, so a server with a non-English locale would fail to parse `Oct`.

Two general lessons:

1. **Profile before optimizing.** Everyone assumes the regex is the bottleneck; it was 10% of the time.
2. **Constant formats should not be re-parsed.** Cache, or hand-parse.

---

## 5. The rest of the pipeline

| Stage | Cost | How it stays cheap |
|---|---|---|
| Parse | ~0.12 ms/line (after optimization) | one regex, two small matches |
| Detect | 15 compiled regexes/line | compiled once at startup, not per line |
| Aggregate | O(1) per entry | `Counter` updates only |
| GeoIP | O(log n) per **unique IP** | one lookup per attacker, never per request |
| Report JSON | O(incidents) | only matches, not all requests |

That last row matters: a 500 MB file with 3 million requests typically produces a few thousand incidents. The report is small even when the input is huge.

---

## 6. Upload handling

```python
uploaded.save(saved_path)     # Werkzeug streams the body to disk
```

- Flask/Werkzeug write the request body in chunks; a 500 MB upload does **not** become a 500 MB Python object.
- `MAX_CONTENT_LENGTH` (default 512 MB, `MAX_UPLOAD_MB` env var) rejects oversized files at the HTTP layer with 413 **before** they fill the disk.
- Uploaded files are named `<random>_<safe_name>` so two people uploading `access.log` cannot overwrite each other.
- Files are deleted after analysis (`delete_source=True`). The demo log is never deleted.

---

## 7. Async: why the job queue is a performance feature

A fast parser is not enough if the HTTP request still waits for it. Week 4's flow:

```
upload (seconds)  ->  202 + job id (milliseconds)  ->  poll  ->  report
```

- The upload finishes as fast as the network allows.
- Analysis happens in a worker thread; the UI shows real progress.
- `ThreadPoolExecutor(max_workers=2)` bounds CPU use, so three simultaneous uploads cannot starve the server.
- Results are written to `reports/<job_id>.json`, so the dashboard, JSON export and CSV export all read the same file.

**Known limit:** the job registry is in memory. Restart the server and in-flight jobs are lost (finished reports survive on disk). Running multiple worker processes would need a shared store — see `DEPLOYMENT.md`.

---

## 8. When this design stops being enough

| Symptom | Next step |
|---|---|
| > 5 GB files | pre-split by hour; process files in parallel |
| Many concurrent users | Celery/RQ + Redis, or a queue service (SQS) |
| Need history/search | write incidents to PostgreSQL, not JSON files |
| CPU saturated by regexes | combine signatures into one alternation, or use Hyperscan |
| Multi-worker deployment | shared job store + object storage for reports |

Being able to say **where** your design breaks is more valuable than pretending it does not.
