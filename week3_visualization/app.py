"""
app.py  -  WEEK 3: Analysis dashboard
==================================================================
WHAT CHANGED SINCE WEEK 2
    Findings used to be printed as tables on the upload page. Now the
    analysis is stored and the user is redirected to a real dashboard:

        POST /analyze  -> analyse, store report, 302 -> /report/<id>
        GET  /report/<id> -> HTML dashboard (charts + map)

    Still synchronous: the POST waits for the whole file. Week 4 fixes
    that with a job queue.

HOW TO RUN
    cd week3_visualization
    python app.py
    then open  http://127.0.0.1:5003

CHARTS
    Chart.js (line/doughnut/bar) and Leaflet (map) are loaded from a
    CDN in the template. Internet is needed for the charts; every table
    still works offline.
==================================================================
"""

import os
import uuid                          # makes a unique id for every report

from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, abort
from werkzeug.utils import secure_filename

from parser import parse_file
from detector import ThreatDetector
from aggregator import aggregate
from geoip import GeoLookup, enrich_report

# ------------------------------------------------------------------
# Configuration
# ------------------------------------------------------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

app = Flask(__name__)
app.secret_key = "loglens-dev-secret-change-me"

UPLOAD_DIR = os.path.join(BASE_DIR, "uploads")
os.makedirs(UPLOAD_DIR, exist_ok=True)
app.config["MAX_CONTENT_LENGTH"] = 128 * 1024 * 1024

ALLOWED_EXTENSIONS = {".log", ".txt"}
DEMO_LOG = os.path.join(BASE_DIR, "..", "demo_logs", "demo_attacks.log")

DETECTOR = ThreatDetector()
GEO = GeoLookup()

# In-memory report store: {report_id: report_dict}
# Works great for a demo. It is lost on restart and NOT shared between
# multiple server processes - exactly why Week 4 introduces a job store.
REPORTS = {}

# Keep memory bounded: remember only the 20 newest reports.
MAX_REPORTS = 20


def allowed_file(filename: str) -> bool:
    return os.path.splitext(filename)[1].lower() in ALLOWED_EXTENSIONS


def store_report(report: dict) -> str:
    """Save a report and return its short id."""
    report_id = uuid.uuid4().hex[:10]     # 10 hex chars is plenty for a demo

    REPORTS[report_id] = report

    # Drop the oldest entries when the dict grows too large.
    while len(REPORTS) > MAX_REPORTS:
        # dicts remember insertion order, so the first key is the oldest.
        oldest = next(iter(REPORTS))
        REPORTS.pop(oldest, None)

    return report_id


def analyse(path: str, display_name: str, threshold=None) -> tuple:
    """Run parse -> detect -> aggregate -> geo. Returns (report_id, report)."""
    parsed = parse_file(path)

    detector = DETECTOR if threshold is None else ThreatDetector(brute_force_threshold=threshold)
    incidents, brute_force = detector.scan(parsed["entries"])

    report = aggregate(parsed, incidents, brute_force)

    # Week 3 addition: attach country / city / lat / lon to each attacker.
    enrich_report(report, GEO)

    # Metadata the dashboard header shows.
    report["meta"] = {
        "filename": display_name,
        "report_id": None,                # filled in just below
    }

    report_id = store_report(report)
    report["meta"]["report_id"] = report_id

    return report_id, report


# ------------------------------------------------------------------
# Routes
# ------------------------------------------------------------------
@app.route("/")
def index():
    """Upload page + a list of recently generated reports."""
    recent = [
        {"id": report_id,
         "filename": report.get("meta", {}).get("filename", "?"),
         "incidents": report["summary"]["incidents"],
         "attacks": report["summary"]["attack_requests"]}
        for report_id, report in reversed(list(REPORTS.items()))
    ]
    return render_template("index.html", recent=recent)


@app.route("/analyze", methods=["POST"])
def analyze():
    uploaded = request.files.get("logfile")

    if uploaded is None or uploaded.filename == "":
        flash("Please choose a .log file first.")
        return redirect(url_for("index"))

    if not allowed_file(uploaded.filename):
        flash("Only .log and .txt files are supported.")
        return redirect(url_for("index"))

    safe_name = secure_filename(uploaded.filename)
    saved_path = os.path.join(UPLOAD_DIR, safe_name)
    uploaded.save(saved_path)

    raw_threshold = request.form.get("threshold", "").strip()
    threshold = int(raw_threshold) if raw_threshold.isdigit() else None

    report_id, _report = analyse(saved_path, safe_name, threshold)

    # Redirect (not render) so refreshing the dashboard does not re-run
    # the analysis or re-post the file.
    return redirect(url_for("report_view", report_id=report_id))


@app.route("/demo")
def demo():
    if not os.path.exists(DEMO_LOG):
        flash("Demo log missing. Run: python tools/make_demo_log.py")
        return redirect(url_for("index"))

    report_id, _report = analyse(DEMO_LOG, "demo_attacks.log (bundled)")
    return redirect(url_for("report_view", report_id=report_id))


@app.route("/report/<report_id>")
def report_view(report_id):
    """Render the dashboard for one stored report."""
    report = REPORTS.get(report_id)
    if report is None:
        abort(404)                       # Flask's built-in "not found" page
    return render_template("dashboard.html", report=report)


@app.route("/api/report/<report_id>")
def report_json(report_id):
    """
    The same data as JSON.

    The dashboard template embeds the report directly, but this endpoint
    is what a mobile app / React frontend would call. jsonify turns the
    dict into a JSON response with the right Content-Type.
    """
    report = REPORTS.get(report_id)
    if report is None:
        abort(404)
    return jsonify(report)


@app.errorhandler(413)
def too_large(_error):
    flash("File too large for the synchronous pipeline. Use Week 4's job queue.")
    return redirect(url_for("index"))


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5003, debug=True)
