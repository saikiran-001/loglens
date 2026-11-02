"""
app.py  -  WEEK 4: The final application
==================================================================
WHAT THIS FILE ADDS OVER WEEK 3
    * asynchronous job queue      -> upload returns instantly
    * progress polling endpoint   -> live progress bar
    * reports persisted to disk   -> survive a restart
    * Export report (JSON + CSV)  -> the last Week-4 deliverable
    * "Load demo log" button      -> required for the evaluator
    * /healthz                    -> deployment health check
    * environment-variable config -> same code runs locally and on Render

ENDPOINTS
    GET  /                     upload page + recent reports
    POST /analyze              save file -> create job -> {job_id}
    POST /demo                 create job for the bundled demo log
    GET  /api/jobs/<id>        job status (polled every 500 ms)
    GET  /job/<id>             no-JS fallback progress page
    GET  /report/<id>          dashboard
    GET  /api/report/<id>      report as JSON
    GET  /export/<id>.json     download JSON
    GET  /export/<id>.csv      download incidents as CSV
    GET  /healthz              "ok"

HOW TO RUN
    cd week4_optimization
    python app.py
    then open  http://127.0.0.1:5004
==================================================================
"""

import csv
import io
import os

from flask import (
    Flask, render_template, request, redirect, url_for,
    flash, jsonify, abort, Response, send_file,
)
from werkzeug.utils import secure_filename

from geoip import GeoLookup
from jobs import JobStore

# ------------------------------------------------------------------
# Configuration (environment variables with sensible defaults)
# ------------------------------------------------------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# int(os.environ.get("PORT", 5004)) lets a host like Render assign a port.
PORT = int(os.environ.get("PORT", 5004))

# Upload cap in megabytes, configurable per deployment.
MAX_UPLOAD_MB = int(os.environ.get("MAX_UPLOAD_MB", 512))

ALLOWED_EXTENSIONS = {".log", ".txt"}

UPLOAD_DIR = os.path.join(BASE_DIR, "uploads")
REPORT_DIR = os.path.join(BASE_DIR, "reports")
DEMO_LOG = os.path.join(BASE_DIR, "..", "demo_logs", "demo_attacks.log")

os.makedirs(UPLOAD_DIR, exist_ok=True)

app = Flask(__name__)

# Read the secret from the environment in production.
# The fallback keeps local development frictionless.
app.secret_key = os.environ.get("SECRET_KEY", "loglens-dev-secret-change-me")

app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD_MB * 1024 * 1024


# ------------------------------------------------------------------
# Singletons created once at import time
# ------------------------------------------------------------------
GEO = GeoLookup()

# max_workers=2 -> at most two analyses run at once; extra uploads queue.
# keep_jobs=50  -> only the 50 newest job records are remembered.
STORE = JobStore(report_dir=REPORT_DIR, geo=GEO, max_workers=2, keep_jobs=50)


def allowed_file(filename: str) -> bool:
    """Only .log and .txt are accepted."""
    return os.path.splitext(filename)[1].lower() in ALLOWED_EXTENSIONS


def get_report(report_id: str):
    """Fetch a report from memory (job summary) or from disk."""
    if not report_id.isalnum():
        # Blocks path traversal like ../../etc/passwd in the URL.
        return None
    return STORE.load_report(report_id)


# ------------------------------------------------------------------
# Pages
# ------------------------------------------------------------------
@app.route("/")
def index():
    """Upload page. Renders instantly - no analysis happens here."""
    return render_template(
        "index.html",
        recent=STORE.recent(),
        max_upload_mb=MAX_UPLOAD_MB,
    )


@app.route("/analyze", methods=["POST"])
def analyze():
    """
    Save the upload, create a job, return its id as JSON.

    The browser's fetch() reads {"job_id": "..."} and starts polling.
    We return 202 Accepted - the correct status for "accepted, not done".
    """
    uploaded = request.files.get("logfile")

    if uploaded is None or uploaded.filename == "":
        return jsonify({"error": "No file selected."}), 400

    if not allowed_file(uploaded.filename):
        return jsonify({"error": "Only .log and .txt files are supported."}), 400

    safe_name = secure_filename(uploaded.filename)

    # Prefix with a random token so two people uploading "access.log"
    # never overwrite each other.
    stored_name = f"{os.urandom(6).hex()}_{safe_name}"
    saved_path = os.path.join(UPLOAD_DIR, stored_name)

    # Werkzeug streams the body to disk in chunks - it does not load a
    # 500 MB upload into RAM.
    uploaded.save(saved_path)

    raw_threshold = request.form.get("threshold", "").strip()
    threshold = int(raw_threshold) if raw_threshold.isdigit() else None

    job_id = STORE.submit(
        filename=safe_name,
        source_path=saved_path,
        threshold=threshold,
        delete_source=True,       # uploaded logs are temporary
    )

    return jsonify({"job_id": job_id, "status_url": url_for("job_status", job_id=job_id)}), 202


@app.route("/demo", methods=["POST"])
def demo():
    """Queue an analysis of the bundled demo log (no upload needed)."""
    if not os.path.exists(DEMO_LOG):
        return jsonify({"error": "Demo log missing. Run: python tools/make_demo_log.py"}), 404

    job_id = STORE.submit(
        filename="demo_attacks.log (bundled)",
        source_path=DEMO_LOG,
        delete_source=False,      # never delete the demo file
    )
    return jsonify({"job_id": job_id, "status_url": url_for("job_status", job_id=job_id)}), 202


# ------------------------------------------------------------------
# Job status
# ------------------------------------------------------------------
@app.route("/api/jobs/<job_id>")
def job_status(job_id):
    """Polled by app.js. Tiny payload on purpose - it runs twice a second."""
    job = STORE.get(job_id)
    if job is None:
        return jsonify({"error": "Unknown job"}), 404
    return jsonify(job)


@app.route("/job/<job_id>")
def job_page(job_id):
    """No-JavaScript fallback: a page that refreshes itself."""
    job = STORE.get(job_id)
    if job is None:
        abort(404)
    if job["status"] == "done":
        return redirect(url_for("report_view", report_id=job_id))
    return render_template("job.html", job=job)


# ------------------------------------------------------------------
# Report views
# ------------------------------------------------------------------
@app.route("/report/<report_id>")
def report_view(report_id):
    report = get_report(report_id)
    if report is None:
        abort(404)
    return render_template("dashboard.html", report=report)


@app.route("/api/report/<report_id>")
def report_json(report_id):
    report = get_report(report_id)
    if report is None:
        abort(404)
    return jsonify(report)


# ------------------------------------------------------------------
# Export (Week 4 deliverable)
# ------------------------------------------------------------------
@app.route("/export/<report_id>.json")
def export_json(report_id):
    """Download the exact report file the dashboard used."""
    path = os.path.join(REPORT_DIR, f"{report_id}.json")
    if not report_id.isalnum() or not os.path.exists(path):
        abort(404)

    # as_attachment=True adds Content-Disposition: attachment, which
    # makes the browser download instead of display.
    return send_file(path, mimetype="application/json",
                     as_attachment=True, download_name=f"loglens_{report_id}.json")


@app.route("/export/<report_id>.csv")
def export_csv(report_id):
    """
    Build a CSV of every incident.

    CSV is what a ticketing system / spreadsheet wants. We build it in
    memory (StringIO) because even a huge log produces a manageable
    incident list - only matches, not every request.
    """
    report = get_report(report_id)
    if report is None:
        abort(404)

    buffer = io.StringIO()

    # newline="" + QUOTE_MINIMAL is the safe combination: it prevents
    # the classic "extra blank line in Excel" problem and quotes any
    # payload that contains a comma or quote.
    writer = csv.writer(buffer, quoting=csv.QUOTE_MINIMAL, lineterminator="\n")

    writer.writerow(["line", "timestamp", "ip", "method", "path",
                     "status", "signature_id", "type", "severity", "payload"])

    for incident in report["incidents"]:
        writer.writerow([
            incident.get("line"),
            incident.get("timestamp"),
            incident.get("ip"),
            incident.get("method"),
            incident.get("path"),
            incident.get("status"),
            incident.get("signature_id"),
            incident.get("type"),
            incident.get("severity"),
            incident.get("payload"),
        ])

    # A second block for brute force keeps everything in one download.
    writer.writerow([])
    writer.writerow(["brute_force_ip", "failed_attempts", "first_seen", "last_seen"])
    for alert in report["brute_force"]:
        writer.writerow([alert["ip"], alert["failed_attempts"],
                         alert["first_seen"], alert["last_seen"]])

    return Response(
        buffer.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment; filename=loglens_{report_id}.csv"},
    )


# ------------------------------------------------------------------
# Operations
# ------------------------------------------------------------------
@app.route("/healthz")
def healthz():
    """Hosts call this to check the app is alive."""
    return jsonify({"status": "ok"})


@app.errorhandler(413)
def too_large(_error):
    return jsonify({
        "error": f"File is larger than the {MAX_UPLOAD_MB} MB limit."
    }), 413


if __name__ == "__main__":
    # threaded=True lets /api/jobs answer while a worker thread is busy.
    # debug must be OFF in production - use `flask run` or gunicorn there.
    app.run(host="0.0.0.0", port=PORT, debug=True, threaded=True)
