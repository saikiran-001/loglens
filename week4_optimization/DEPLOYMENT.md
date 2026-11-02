# Deployment Guide

> Week 4 deliverable: *"Final Deployment."*

Two honest options are below. **Render** is the easiest free route because it runs a Python process directly. You can also run it locally behind a real WSGI server, which is a legitimate "deployed" demo for a class.

---

## 0. Before anything: requirements

```
Flask>=3.0
maxminddb>=2.5      # optional; app works without it
```

No database, no Redis, no Node build step. `week4_optimization/` is the deployable app.

---

## 1. Local production-style run (5 minutes)

```powershell
cd week4_optimization
python -m pip install -r ..\requirements.txt
python -m pip install waitress
waitress-serve --listen=0.0.0.0:8000 app:app
```

Open <http://127.0.0.1:8000>.

Why not `python app.py`? That is Flask's **development** server: single-threaded-ish, no timeouts, and `debug=True` exposes an interactive debugger to anyone who can reach the port. Use `waitress` (Windows) or `gunicorn` (Linux) for a real demo.

Linux equivalent:

```bash
pip install gunicorn
gunicorn -w 1 -b 0.0.0.0:8000 app:app
```

> **Use `-w 1`.** The job store is in-process memory. With two workers, an upload handled by worker A cannot be polled from worker B — you would see random 404s. One worker + two threads (inside `JobStore`) is the correct configuration for this design.

---

## 2. Deploy to Render (free tier)

1. Push the project to GitHub (see §4).
2. On <https://render.com> → **New → Web Service** → connect the repo.
3. Settings:

| Field | Value |
|---|---|
| Root Directory | `week4_optimization` |
| Runtime | Python 3 |
| Build Command | `pip install -r ../requirements.txt` |
| Start Command | `gunicorn -w 1 --threads 4 -b 0.0.0.0:$PORT app:app` |
| Health Check Path | `/healthz` |

4. Environment variables:

| Key | Value |
|---|---|
| `SECRET_KEY` | a long random string (**required**) |
| `MAX_UPLOAD_MB` | `100` (free tier has limited RAM) |
| `PYTHON_VERSION` | `3.12.0` |

5. Deploy. Your URL looks like `https://loglens-xxxx.onrender.com`.

### Free-tier gotchas (real ones)

- **Cold starts:** the service sleeps after ~15 min idle; the first request takes ~30–60 s.
- **Ephemeral disk:** `reports/*.json` is lost on every redeploy/restart. That is fine for a demo (regenerate), not for audit history.
- **Upload size:** Render's proxy allows large bodies but the free instance has ~512 MB RAM. Keep `MAX_UPLOAD_MB` at 100.
- **No persistent job queue:** a restart kills running jobs. Documented in `PERFORMANCE.md`.

---

## 3. Docker alternative

`week4_optimization/Dockerfile`:

```dockerfile
FROM python:3.12-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt gunicorn

COPY week4_optimization/ ./week4_optimization/
COPY demo_logs/ ./demo_logs/

WORKDIR /app/week4_optimization
ENV MAX_UPLOAD_MB=100
EXPOSE 8000

# -w 1: single worker, because the job store lives in memory
CMD ["gunicorn", "-w", "1", "--threads", "4", "-b", "0.0.0.0:8000", "app:app"]
```

Build and run from the project root:

```bash
docker build -f week4_optimization/Dockerfile -t loglens .
docker run -p 8000:8000 -e SECRET_KEY=change-me loglens
```

---

## 4. Publish the repository (deliverable #1)

```powershell
cd ..\            # project root
git init
git add .
git commit -m "LogLens: streaming log analysis with detection, dashboard and job queue"
git branch -M main
git remote add origin https://github.com/<you>/loglens.git
git push -u origin main
```

`.gitignore` already excludes `uploads/`, `reports/`, `*.mmdb`, `__pycache__` and `demo_logs/large_access.log`.

Repository checklist from the brief:

- [x] Parser module — `week4_optimization/parser.py` (+ earlier weeks)
- [x] Signature database — `week4_optimization/signatures.json`
- [x] README with run instructions — root `README.md`
- [x] Performance note — `week4_optimization/PERFORMANCE.md`
- [x] Live app — the Render/local URL
- [x] "Load demo log" button — index page of week 4 (and 2, 3)

---

## 5. Post-deploy smoke test

Run through this list on the deployed URL:

1. `GET /healthz` → `{"status": "ok"}`
2. Click **Load demo log** → progress bar moves → dashboard appears
3. Dashboard shows: red line at 16:00, 5 country bars, map circles
4. Download **Export CSV** → opens in Excel with 59 incident rows
5. Upload a text file renamed to `.png` → rejected with a clear message
6. `GET /report/doesnotexist` → 404, not a stack trace

If step 2 hangs at "Queued", the worker never started — check the logs for a traceback from `jobs.py`.

---

## 6. If you need real production

| Concern | Fix |
|---|---|
| Jobs lost on restart | Redis + Celery/RQ, or a DB-backed job table |
| Multi-worker | shared job store (Redis/Postgres) + S3 for reports |
| Auth | Flask-Login + per-user quotas |
| Big files | presigned S3 upload → worker pulls from S3 |
| Retention | cron job deleting `reports/` older than N days |
| TLS / rate limiting | put it behind Cloudflare or nginx |

None of these change the application logic — only where state lives.
