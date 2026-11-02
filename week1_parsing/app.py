"""
app.py  -  WEEK 1: File Upload API + Parser demo
==================================================================
GOAL OF THIS FILE
    Week 1 deliverable #1 is "Build the File Upload API". This is that.
    The browser sends a .log file, Flask saves it, parser.py turns it
    into records, and the page shows what was found.

    No detection, no charts yet - this week is only about STRUCTURE.

HOW TO RUN
    cd week1_parsing
    python app.py
    then open  http://127.0.0.1:5001

WHAT TO LOOK AT
    1. The form uses enctype="multipart/form-data" - without it the file
       is not sent at all.
    2. request.files is where Flask puts uploaded files.
    3. file.save(path) streams the upload to disk for us.
    4. We never trust the uploaded file name - see secure_filename().
==================================================================
"""

import os                        # path building + makedirs
from collections import Counter  # counting how many of each status code appeared

from flask import Flask, render_template, request, redirect, url_for, flash
# Flask            -> the web framework itself
# render_template  -> fills an HTML file in templates/ with data
# request          -> everything the browser sent us
# redirect/url_for -> send the user to another page
# flash            -> one-time message shown on the next page

from werkzeug.utils import secure_filename   # sanitises "..\..\evil.log" into "evil.log"

from parser import parse_file                # our Week-1 parser

# ------------------------------------------------------------------
# App configuration
# ------------------------------------------------------------------
app = Flask(__name__)      # __name__ tells Flask where to look for templates/ and static/

# Flask uses this secret to sign the "flash" message cookie.
# In a real deployment it must come from an environment variable, never
# be committed to GitHub. For local learning a constant is fine.
app.secret_key = "loglens-dev-secret-change-me"

# Folder where uploaded files are stored, next to this script.
UPLOAD_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "uploads")
os.makedirs(UPLOAD_DIR, exist_ok=True)      # exist_ok=True -> no error if it already exists

# Hard limit on upload size (32 MB). Flask returns HTTP 413 above this,
# which protects the server from someone posting a 10 GB file.
app.config["MAX_CONTENT_LENGTH"] = 32 * 1024 * 1024

# Which extensions do we accept? Anything else is rejected politely.
ALLOWED_EXTENSIONS = {".log", ".txt"}

# The bundled demo log lives at <project root>/demo_logs/demo_attacks.log
DEMO_LOG = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "demo_logs", "demo_attacks.log")


def build_result(path: str, display_name: str) -> dict:
    """
    Parse a file and package everything the template needs.

    Both /upload and /demo call this, so the two paths can never drift
    apart (a classic source of "works on demo, breaks on upload" bugs).
    """
    parsed = parse_file(path)
    entries = parsed["entries"]

    # Counter makes a frequency table: {200: 74, 401: 12, 404: 1, ...}
    status_counts = Counter(entry["status"] for entry in entries)

    return {
        "filename": display_name,
        "total_lines": parsed["total_lines"],
        "parsed": len(entries),
        "failed": len(parsed["errors"]),
        "status_counts": dict(sorted(status_counts.items())),
        # Only send the first 100 rows to the browser. Sending 500,000
        # rows would freeze the page - a preview is enough for Week 1.
        "preview": entries[:100],
        "errors": parsed["errors"][:10],   # show at most 10 bad lines
    }


def allowed_file(filename: str) -> bool:
    """Return True only for .log / .txt files."""
    # os.path.splitext("server.log") -> ("server", ".log")
    extension = os.path.splitext(filename)[1].lower()   # .lower() so ".LOG" works too
    return extension in ALLOWED_EXTENSIONS


# ------------------------------------------------------------------
# Route 1: the upload page
# ------------------------------------------------------------------
@app.route("/")
def index():
    """
    @app.route("/") ties this function to the site root.

    On a GET we just render the empty page.  On a POST (after the form
    is submitted) we would not be here - see /upload below.
    """
    return render_template("index.html", result=None)


# ------------------------------------------------------------------
# Route 2: receive the file
# ------------------------------------------------------------------
@app.route("/upload", methods=["POST"])
def upload():
    """
    Handle the multipart form post coming from index.html.

    Steps: validate -> save -> parse -> render results.
    """
    # request.files["logfile"] is the file input named "logfile" in the HTML.
    # .get() avoids a KeyError when the user submits an empty form.
    uploaded = request.files.get("logfile")

    # Case 1: nothing chosen, or an empty file input.
    if uploaded is None or uploaded.filename == "":
        flash("Please choose a .log file first.")
        return redirect(url_for("index"))     # url_for("index") == "/"

    # Case 2: wrong extension -> refuse before touching the disk.
    if not allowed_file(uploaded.filename):
        flash("Only .log and .txt files are supported.")
        return redirect(url_for("index"))

    # secure_filename strips directory parts and dangerous characters.
    # Example: "../../etc/passwd" becomes "etc_passwd".
    safe_name = secure_filename(uploaded.filename)

    # Build the absolute path where the file will live.
    saved_path = os.path.join(UPLOAD_DIR, safe_name)

    # Write the incoming bytes to disk.
    uploaded.save(saved_path)

    # Parse it and render the results.
    return render_template("index.html", result=build_result(saved_path, safe_name))


@app.route("/demo")
def demo():
    """Parse the bundled demo log - no file picker needed."""
    if not os.path.exists(DEMO_LOG):
        flash("Demo log missing. Run: python tools/make_demo_log.py")
        return redirect(url_for("index"))
    return render_template("index.html", result=build_result(DEMO_LOG, "demo_attacks.log (bundled)"))


# ------------------------------------------------------------------
# Friendly error page for oversized uploads
# ------------------------------------------------------------------
@app.errorhandler(413)
def too_large(_error):
    """Flask calls this automatically when MAX_CONTENT_LENGTH is exceeded."""
    flash("That file is larger than 32 MB. Try a smaller log for Week 1.")
    return redirect(url_for("index"))


# ------------------------------------------------------------------
# Start the development server
# ------------------------------------------------------------------
if __name__ == "__main__":
    # debug=True gives auto-reload on save + a readable traceback.
    # NEVER use debug=True on a public server.
    # port=5001 so it does not clash with weeks 2-4 if you run them together.
    app.run(host="127.0.0.1", port=5001, debug=True)
