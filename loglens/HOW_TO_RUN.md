# How to run LogLens (from zero)

Written for someone who has never started a web app before. Follow it top to bottom; every command is copy-pasteable in **PowerShell** on Windows.

---

## 0. Check that Python works

Open **PowerShell** (press `Win`, type `powershell`, press Enter) and run:

```powershell
python --version
```

You should see something like `Python 3.12.x`.

<details>
<summary><b>If it says "Python was not found" / opens the Microsoft Store</b></summary>

Install Python from <https://python.org/downloads> and **tick "Add python.exe to PATH"** on the first screen of the installer. Then close and reopen PowerShell and try again.

</details>

---

## 1. Go to the project folder

```powershell
cd "$env:USERPROFILE\OneDrive\Desktop\loglens"
```

`pwd` should now print `...\Desktop\loglens`. Everything below assumes you are here.

---

## 2. Create a virtual environment (recommended, one time)

A **virtual environment** is a private box of packages for this project, so LogLens cannot break other Python projects on your machine.

```powershell
python -m venv .venv
```

Activate it:

```powershell
.\.venv\Scripts\Activate.ps1
```

Your prompt now starts with `(.venv)`.

<details>
<summary><b>If PowerShell blocks the activate script</b></summary>

```powershell
Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
```

Type `Y`, press Enter, then run the activate command again.

</details>

> You must activate the venv **every time** you open a new terminal. If `python app.py` later says `ModuleNotFoundError: No module named 'flask'`, you forgot this step.

---

## 3. Install the dependencies (one time)

```powershell
python -m pip install -r requirements.txt
```

That installs Flask (and optionally `maxminddb`). Takes ~20 seconds.

---

## 4. Run a week

Pick a week. Each runs on its own port, so you can run all four at once.

### Week 1 — Parser (port 5001)

```powershell
cd week1_parsing
python app.py
```

```
 * Running on http://127.0.0.1:5001
```

Open <http://127.0.0.1:5001>, click the dashed box, choose
`loglens\demo_logs\demo_attacks.log`, press **Parse file**.

You should see **79 lines read, 78 parsed, 1 failed** and a table of 78 rows.

### Week 2 — Detection (port 5002)

```powershell
cd ..
cd week2_detection
python app.py
```

Open <http://127.0.0.1:5002> and click **Load demo log**.
Expected: **35 malicious requests**, **59 incidents**, **2 brute-force IPs**.

### Week 3 — Dashboard (port 5003)

```powershell
cd ..
cd week3_visualization
python app.py
```

Open <http://127.0.0.1:5003> → **Load demo log**.
You should land on a report page with a red timeline, a doughnut, a country chart and a world map.

> The charts need internet (they load Chart.js/Leaflet from a CDN). Without internet the tables still appear and the chart boxes explain why they are empty.

### Week 4 — Final (port 5004)

```powershell
cd ..
cd week4_optimization
python app.py
```

Open <http://127.0.0.1:5004> → **Load demo log**.
A progress bar appears, then the report opens automatically. Try **Export CSV** in the top-right of the report.

---

## 5. Stop a server

Click the terminal window and press **Ctrl + C**. The server stops; the port is free again.

If you closed the window and the port is stuck:

```powershell
# see what is using port 5004
Get-NetTCPConnection -LocalPort 5004 | Select-Object OwningProcess
# then stop it (replace 12345 with the number above)
Stop-Process -Id 12345
```

---

## 6. What "open the app" actually means

`python app.py` starts a **local web server** — a small program listening on a port of your own computer. It is not a website on the internet; only your machine can reach `127.0.0.1`.

- `127.0.0.1` = "this computer"
- `:5001` = the port (like a door number)
- The browser asks the server for a page, the server runs Python and sends HTML back

Close the terminal → the server dies → the URL stops working. That is normal.

---

## 7. Use the command line instead (no browser)

Week 2 ships a terminal version:

```powershell
cd week2_detection
python cli.py ..\demo_logs\demo_attacks.log
```

You get a printable report in the console. Add `-t 3` to change the brute-force threshold, `-o report.json` to save the full JSON.

---

## 8. Test the performance claim yourself

```powershell
cd ..
python tools\make_large_log.py 300      # builds a ~3.4 MB log
python tools\benchmark.py
```

Expected output shape:

```
A) load all (week 2)   11.5 s   peak 26.1 MB
B) stream (week 4)     2.9 s    peak  1.3 MB
```

Same result, far less memory.

---

## 9. Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `ModuleNotFoundError: No module named 'flask'` | venv not active | `.\.venv\Scripts\Activate.ps1` then reinstall |
| `Address already in use` | an older server is still running | Ctrl+C in that terminal, or kill the port (§5) |
| Page loads but CSS is unstyled | you opened `templates/index.html` directly | open `http://127.0.0.1:500x`, never the file |
| Charts are empty boxes | no internet / CDN blocked | tables still work; connect or vendor the JS locally |
| `413 Request Entity Too Large` | file above the limit | Week 1/2: 32/64 MB, Week 4: `MAX_UPLOAD_MB` env var |
| "Load demo log" says the file is missing | demo log not generated | `python tools\make_demo_log.py` |
| `[i] GeoIP: using built-in demo table` | no MaxMind DB | expected — it is a fallback, not an error |
| PowerShell says "running scripts is disabled" | execution policy | see §2 |

---

## 10. Reading order (to actually learn it)

1. `week1_parsing/parser.py` — start at `COMBINED_PATTERN`, then `parse_line()`
2. `week1_parsing/app.py` — how a file becomes records on a page
3. `week2_detection/signatures.json` — read the regex of `SQLI-002` out loud
4. `week2_detection/detector.py` — `scan_path()` then `scan()`
5. `week2_detection/aggregator.py` — how a flat list becomes per-IP totals
6. `week3_visualization/geoip.py` — the two-backend lookup
7. `week3_visualization/static/dashboard.js` — `buildTimeline()` first
8. `week4_optimization/parser.py` — `stream_lines()` (the chunk buffer is the trick)
9. `week4_optimization/jobs.py` — `submit()` then `_run()`
10. `week4_optimization/app.py` — the `/analyze` → `/api/jobs` → `/report` loop

Each README ends with a **checkpoint list** and **practice exercises** — do them; reading alone will not stick.
