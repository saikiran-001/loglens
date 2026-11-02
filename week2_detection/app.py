"""
app.py  -  WEEK 2: Detection web app
==================================================================
WHAT CHANGED SINCE WEEK 1
    Week 1 only showed the parser output. Now we run the detection
    engine and show FINDINGS instead of raw rows:

        upload -> parse -> scan signatures -> aggregate -> report

    Still fully synchronous: the request waits until analysis finishes.
    That is fine for a few MB and becomes a problem in Week 4.

HOW TO RUN
    cd week2_detection
    python app.py
    then open  http://127.0.0.1:5002

    Click "Load demo log" to analyse demo_logs/demo_attacks.log
    without picking a file.
==================================================================
"""

import os
from flask import Flask, render_template, request, redirect, url_for, flash

from werkzeug.utils import secure_filename

from parser import parse_file
from detector import ThreatDetector
from aggregator import aggregate

# ------------------------------------------------------------------
# Configuration
# ------------------------------------------------------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

app = Flask(__name__)
app.secret_key = "loglens-dev-secret-change-me"

UPLOAD_DIR = os.path.join(BASE_DIR, "uploads")
os.makedirs(UPLOAD_DIR, exist_ok=True)

# 64 MB - bigger than Week 1 because detection is the point now.
app.config["MAX_CONTENT_LENGTH"] = 64 * 1024 * 1024

ALLOWED_EXTENSIONS = {".log", ".txt"}

# The demo log lives at <project root>/demo_logs/demo_attacks.log
DEMO_LOG = os.path.join(BASE_DIR, "..", "demo_logs", "demo_attacks.log")

# One detector is created at import time and reused by every request.
# It holds the compiled regexes, so we do not pay that cost per upload.
DETECTOR = ThreatDetector()


def allowed_file(filename: str) -> bool:
    return os.path.splitext(filename)[1].lower() in ALLOWED_EXTENSIONS


def analyse(path: str, display_name: str, threshold=None):
    """
    Run the whole pipeline on one file and return (report, result_dict).

    Keeping this in a function means /analyze and /demo share the exact
    same code path - no "works on demo, breaks on upload" surprises.
    """
    parsed = parse_file(path)

    # Allow the form to override the brute-force threshold.
    detector = DETECTOR if threshold is None else ThreatDetector(brute_force_threshold=threshold)

    incidents, brute_force = detector.scan(parsed["entries"])
    report = aggregate(parsed, incidents, brute_force)

    result = {
        "filename": display_name,
        "report": report,
    }
    return result


# ------------------------------------------------------------------
# Routes
# ------------------------------------------------------------------
@app.route("/")
def index():
    """Empty upload page."""
    return render_template("index.html", result=None, threshold=DETECTOR.brute_threshold)


@app.route("/analyze", methods=["POST"])
def analyze():
    """Handle a real file upload."""
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

    # Read the optional threshold field from the form ("" -> use default).
    raw_threshold = request.form.get("threshold", "").strip()
    threshold = int(raw_threshold) if raw_threshold.isdigit() else None

    result = analyse(saved_path, safe_name, threshold)
    return render_template("index.html", result=result, threshold=threshold or DETECTOR.brute_threshold)


@app.route("/demo")
def demo():
    """Analyse the bundled demo log - no file picker needed."""
    if not os.path.exists(DEMO_LOG):
        flash("Demo log missing. Run: python tools/make_demo_log.py")
        return redirect(url_for("index"))

    result = analyse(DEMO_LOG, "demo_attacks.log (bundled)")
    return render_template("index.html", result=result, threshold=DETECTOR.brute_threshold)


@app.errorhandler(413)
def too_large(_error):
    flash("File larger than 64 MB. Week 4 handles big files with a job queue.")
    return redirect(url_for("index"))


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5002, debug=True)
