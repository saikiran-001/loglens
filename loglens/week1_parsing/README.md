# Week 1 — Parsing (Structure)

> **Deadline goal:** "Build the File Upload API. Write the Regex to parse Apache/Nginx logs into JSON objects."

---

## 1. What this week delivers

| PDF task | Where it lives |
|---|---|
| File Upload API | `app.py` → `POST /upload` |
| Regex that parses logs into JSON objects | `parser.py` → `parse_line()` |
| A way to check it worked | the web page + `python parser.py <file>` |

Run it:

```powershell
cd week1_parsing
python app.py
```

Then open **http://127.0.0.1:5001** and upload `demo_logs/demo_attacks.log`.

---

## 2. What a log line actually is

Apache and Nginx write one line per HTTP request. The default is **Combined Log Format**:

```
192.168.1.15 - - [27/Oct/2026:10:00:01 +0000] "GET /index.html HTTP/1.1" 200 4520 "-" "Mozilla/5.0 ..."
└──────┬───┘ │ │ └────────────┬──────────────┘ └──────────┬─────────┘ └┬┘ └─┬┘ └┬┘ └──────┬──────┘
       IP    │ │          timestamp                   request line     status │ referer   user-agent
          ident│                                                        bytes
             user
```

There is no JSON, no commas, no schema — just spaces and quotes. That is exactly why a **regular expression** is the right tool: it describes the *shape* of the text.

---

## 3. The regex, group by group

```python
(?P<ip>\S+)        # \S+ = one or more NON-space characters
\s+                # one or more spaces
\[(?P<time>[^\]]+)\]   # literal [ ... ] around everything that is not ]
"(?P<request>[^"]*)"   # literal " ... " around everything that is not "
(?P<status>\d{3})  # exactly three digits
(?P<size>\d+|-)    # digits OR a single dash
```

Key ideas to remember:

1. **`(?P<name>...)` is a named group.** `match.groupdict()` then gives you a ready-made dictionary — no positional indexing.
2. **`[^"]*` (a negated character class) is the trick for quoted fields.** `.*` would happily eat your closing quote and break everything.
3. **`re.VERBOSE`** lets you write the pattern across multiple lines with `#` comments. Do this for any pattern longer than ~40 characters; future-you will thank you.
4. **The second pass.** The request field is three values glued together, so `REQUEST_PATTERN` splits `"GET /path HTTP/1.1"` into `method`, `path`, `protocol`. Two small regexes are easier to maintain than one giant one.

---

## 4. Why `parse_line()` returns `None` instead of raising

Real log files always contain junk: truncated writes, a stray "this is not a log line", health-check noise. If one bad line raised an exception, the whole 500 MB analysis would die at byte 40.

So the contract is:

```python
parsed = parse_line(line)
if parsed is None:
    # count it as an error, keep going
```

This "**never crash on bad input**" habit is the single most important thing in this project. The demo log deliberately includes one broken line so you can see it handled.

---

## 5. Upload security — three things to notice in `app.py`

1. **`secure_filename()`** — an attacker can name a file `..\..\..\Windows\System32\evil.dll`. `secure_filename` strips directories and weird characters, so it can only ever land inside `uploads/`.
2. **`ALLOWED_EXTENSIONS`** — reject anything that is not `.log` / `.txt` *before* saving it.
3. **`MAX_CONTENT_LENGTH`** — Flask refuses uploads above 32 MB with HTTP 413. Without it, one person can fill your disk.

Also: the form **must** have `enctype="multipart/form-data"`. Without it the browser sends only the filename and `request.files` is empty — the classic first-upload bug.

---

## 6. Deliberate limitation (fixed in Week 4)

`parse_file()` reads the whole file into a list. For this week's goal that is fine and keeps the code readable — but a 500 MB log would eat hundreds of MB of RAM.

`parser.py` already contains `iter_entries()`, a **generator** version that yields one record at a time. Compare:

```python
def parse_file(path):      # builds a list -> all records in RAM
    entries = []
    ...
    return entries

def iter_entries(path):    # yields one by one -> constant memory
    ...
    yield parsed
```

Week 4 replaces the list with this pattern. Nothing else has to change.

---

## 7. Checkpoint — you are done with Week 1 when…

- [ ] `python parser.py ..\demo_logs\demo_attacks.log` prints **78 parsed / 1 unparsed**
- [ ] Uploading that file in the browser shows the stats + a 78-row table
- [ ] Uploading a `.png` is refused
- [ ] You can explain what `(?P<status>\d{3})` matches without looking it up
- [ ] You can explain why the file input needs `enctype="multipart/form-data"`

---

## 8. Practice (do at least one)

- Add `country` detection for private IPs (`192.168.*`, `10.*`, `172.16-31.*`) — *hint: `ipaddress.ip_address(ip).is_private`*.
- Add a `duration` field: some Nginx logs put response time at the end of the line.
- Change the preview to 25 rows and add a "Download parsed JSON" button.

---

**Next:** [`week2_detection/README.md`](../week2_detection/README.md) — turn these structured records into actual threat findings.
