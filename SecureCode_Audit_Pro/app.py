
import json
import os
import subprocess
import sys
import tempfile
from datetime import datetime
from io import BytesIO
from pathlib import Path

from flask import (
    Flask, flash, redirect, render_template,
    request, send_file, session, url_for
)
from werkzeug.utils import secure_filename

BASE_DIR = Path(__file__).resolve().parent
MAX_SOURCE_BYTES = 512 * 1024

app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.environ.get("APP_SECRET_KEY") or os.urandom(32).hex(),
    MAX_CONTENT_LENGTH=MAX_SOURCE_BYTES + 16384,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
)


def severity_rank(value):
    return {
        "HIGH": 3,
        "MEDIUM": 2,
        "LOW": 1,
    }.get(str(value).upper(), 0)


def normalize_finding(item):
    return {
        "test_id": str(item.get("test_id", "N/A")),
        "test_name": str(item.get("test_name", "Security finding")),
        "issue_text": str(item.get("issue_text", "No description")),
        "severity": str(item.get("issue_severity", "LOW")).upper(),
        "confidence": str(item.get("issue_confidence", "LOW")).upper(),
        "line": item.get("line_number", "?"),
        "code": str(item.get("code", "")).strip(),
        "filename": Path(str(item.get("filename", "source.py"))).name,
    }


def run_bandit(source, filename):
    if not source.strip():
        raise ValueError("The source file is empty.")

    if len(source.encode("utf-8")) > MAX_SOURCE_BYTES:
        raise ValueError("Maximum file size is 512 KB.")

    with tempfile.TemporaryDirectory(prefix="securecode_") as folder:
        safe_name = secure_filename(filename) or "source.py"
        if not safe_name.lower().endswith(".py"):
            safe_name = "source.py"

        source_path = Path(folder) / safe_name
        source_path.write_text(source, encoding="utf-8")

        executable = Path(sys.executable).parent / (
            "bandit.exe" if os.name == "nt" else "bandit"
        )

        try:
            completed = subprocess.run(
                [str(executable), "-f", "json", "-q", str(source_path)],
                capture_output=True,
                text=True,
                timeout=25,
                check=False,
                cwd=folder,
                shell=False,
            )
        except FileNotFoundError as exc:
            raise RuntimeError(
                "Bandit is not installed. Run pip install -r requirements.txt."
            ) from exc
        except subprocess.TimeoutExpired as exc:
            raise RuntimeError("The scan timed out after 25 seconds.") from exc

        try:
            data = json.loads(completed.stdout or "{}")
        except json.JSONDecodeError as exc:
            raise RuntimeError("Bandit returned invalid output.") from exc

    findings = [
        normalize_finding(item)
        for item in data.get("results", [])
    ]

    counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for finding in findings:
        if finding["severity"] in counts:
            counts[finding["severity"]] += 1

    findings.sort(
        key=lambda item: (
            -severity_rank(item["severity"]),
            str(item["line"]),
        )
    )

    return {
        "filename": Path(filename).name,
        "created_at": datetime.now().astimezone().strftime(
            "%d %b %Y, %I:%M %p"
        ),
        "findings": findings,
        "counts": counts,
        "total": len(findings),
        "scanner": "Bandit",
    }


def current_result():
    result = session.get("last_scan")
    return result if isinstance(result, dict) else None


@app.get("/")
def dashboard():
    return render_template(
        "dashboard.html",
        result=current_result(),
    )


@app.post("/scan")
def scan_source():
    upload = request.files.get("source_file")

    if not upload or not upload.filename:
        flash("Please select a Python file.", "error")
        return redirect(url_for("dashboard"))

    filename = secure_filename(upload.filename)

    if not filename or Path(filename).suffix.lower() != ".py":
        flash("Only .py files are supported.", "error")
        return redirect(url_for("dashboard"))

    raw = upload.read(MAX_SOURCE_BYTES + 1)

    if len(raw) > MAX_SOURCE_BYTES:
        flash("The file exceeds the 512 KB size limit.", "error")
        return redirect(url_for("dashboard"))

    try:
        source = raw.decode("utf-8")
        result = run_bandit(source, filename)
    except UnicodeDecodeError:
        flash("The file must use UTF-8 text encoding.", "error")
        return redirect(url_for("dashboard"))
    except (ValueError, RuntimeError) as exc:
        flash(str(exc), "error")
        return redirect(url_for("dashboard"))

    session["last_scan"] = result
    flash(
        f"Scan completed: {result['total']} finding(s) returned.",
        "success",
    )
    return redirect(url_for("dashboard"))


@app.post("/scan-sample")
def scan_sample():
    sample = BASE_DIR / "samples" / "vulnerable_sample.py"

    try:
        result = run_bandit(
            sample.read_text(encoding="utf-8"),
            sample.name,
        )
    except (OSError, ValueError, RuntimeError) as exc:
        flash(str(exc), "error")
        return redirect(url_for("dashboard"))

    session["last_scan"] = result
    flash("Demo sample scan completed.", "success")
    return redirect(url_for("dashboard"))


@app.get("/report")
def report():
    result = current_result()

    if not result:
        flash("Run a scan before viewing the report.", "error")
        return redirect(url_for("dashboard"))

    return render_template(
        "report.html",
        result=result,
        generated=datetime.now().astimezone().strftime("%d %B %Y"),
    )


@app.get("/export/json")
def export_json():
    result = current_result()

    if not result:
        flash("Run a scan before exporting results.", "error")
        return redirect(url_for("dashboard"))

    output = BytesIO(json.dumps(result, indent=2).encode("utf-8"))
    output.seek(0)

    return send_file(
        output,
        mimetype="application/json",
        as_attiachment=True,
        download_name="securecode-audit-report.json",
    )


@app.errorhandler(413)
def upload_too_large(_error):
    flash("Upload too large. Maximum size is 512 KB.", "error")
    return redirect(url_for("dashboard"))


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5001, debug=False)
