"""
SecureScan — Flask API Server.
Exposes endpoints for starting scans, checking status, and retrieving results.
"""

import os
import json
import threading
from dotenv import load_dotenv
from flask import Flask, jsonify, request
from flask_cors import CORS
import sqlite3

from core.engine import ScannerEngine, RUNNING_SCANS
from security import validate_target_url
from database import DB_PATH, has_running_scan
from core.recommendations import enrich_owasp_results


load_dotenv()

PORT = int(os.getenv("PORT", "5000"))
FRONTEND_ORIGIN = os.getenv("FRONTEND_ORIGIN", "http://localhost:5173")

app = Flask(__name__)
CORS(app, resources={r"/api/*": {"origins": [FRONTEND_ORIGIN]}})


@app.get("/api/health")
def health():
    return jsonify({"status": "ok"})


# ---------------------------------------------------------------------------
# Scan lifecycle
# ---------------------------------------------------------------------------

def run_background_scan(target_url: str):
    scan_id = None
    try:
        engine = ScannerEngine(target_url, max_depth=2)
        # Assuming the ScannerEngine creates the scan initially and returns data at the end
        engine.run()
    except Exception as e:
        print(f"Background scan failed: {e}")
        try:
            import sqlite3
            from database import DB_PATH
            conn = sqlite3.connect(DB_PATH)
            cur = conn.cursor()
            cur.execute("UPDATE scans SET status='error' WHERE target_url=? AND status='running'", (target_url,))
            conn.commit()
            conn.close()
        except:
            pass


@app.post("/api/scan/start")
def start_scan():
    payload = request.get_json(silent=True) or {}
    raw_url = payload.get("url", "")

    try:
        target_url = validate_target_url(raw_url)

        # Block concurrent scans — only one scan at a time
        if RUNNING_SCANS or has_running_scan():
            return jsonify({
                "error": "A scan is already running. Please wait for it to finish or cancel it first."
            }), 409

        # Start in background
        thread = threading.Thread(target=run_background_scan, args=(target_url,))
        thread.start()

        return jsonify({"message": "Scan started", "target": target_url}), 202

    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    except Exception as e:
        return jsonify({"error": "Scan failed due to an unexpected error"}), 500


@app.post("/api/scan/cancel")
def cancel_scan():
    """Cancel an ongoing scan."""
    payload = request.get_json(silent=True) or {}
    target_url = payload.get("url", "")

    if not target_url:
        return jsonify({"error": "URL parameter required"}), 400

    try:
        target_url = validate_target_url(target_url)
        
        if target_url in RUNNING_SCANS:
            engine = RUNNING_SCANS[target_url]
            engine.cancel_requested = True
            return jsonify({"message": "Scan cancellation requested", "target": target_url}), 200
        else:
            return jsonify({"error": "No running scan found for this URL"}), 404

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.get("/api/scan/status")
def scan_status():
    target_url = request.args.get("url")
    if not target_url:
        return jsonify({"error": "URL parameter required"}), 400

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute(
        "SELECT status, started_at, completed_at, score, grade, tests_passed, tests_total, "
        "tech_stack, tech_stack_confidence, tech_stack_details "
        "FROM scans WHERE target_url=? ORDER BY id DESC LIMIT 1",
        (target_url,)
    )
    row = cursor.fetchone()
    conn.close()

    if not row:
        return jsonify({"status": "not_found"}), 404

    return jsonify({
        "status": row[0],
        "started_at": row[1],
        "completed_at": row[2],
        "score": row[3],
        "grade": row[4],
        "tests_passed": row[5],
        "tests_total": row[6],
        "tech_stack": row[7],
        "tech_stack_confidence": row[8],
        "tech_stack_details": json.loads(row[9]) if row[9] else None,
    }), 200


# ---------------------------------------------------------------------------
# Results (enhanced with OWASP data)
# ---------------------------------------------------------------------------

@app.get("/api/scan/results")
def scan_results():
    target_url = request.args.get("url")
    if not target_url:
        return jsonify({"error": "URL parameter required"}), 400

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # Get the latest scan for this URL
    cursor.execute(
        "SELECT id, score, grade, tests_passed, tests_total, tech_stack, tech_stack_confidence, tech_stack_details "
        "FROM scans WHERE target_url=? ORDER BY id DESC LIMIT 1",
        (target_url,)
    )
    scan_row = cursor.fetchone()

    if not scan_row:
        conn.close()
        return jsonify({"error": "No scan found"}), 404

    scan_id = scan_row[0]
    tech_stack = scan_row[5]
    tech_stack_confidence = scan_row[6]
    tech_stack_details = json.loads(scan_row[7]) if scan_row[7] else None

    # Get OWASP test results
    cursor.execute(
        "SELECT owasp_id, owasp_name, status, severity, description, recommendation, findings_json "
        "FROM scan_results WHERE scan_id=? ORDER BY owasp_id ASC",
        (scan_id,)
    )
    owasp_rows = cursor.fetchall()

    owasp_results = []
    for r in owasp_rows:
        owasp_results.append({
            "owasp_id": r[0],
            "owasp_name": r[1],
            "status": r[2],
            "severity": r[3],
            "description": r[4],
            "recommendation": r[5],
            "findings": json.loads(r[6]) if r[6] else []
        })

    owasp_results = enrich_owasp_results(owasp_results, tech_stack)


    # Get raw vulnerabilities
    cursor.execute(
        "SELECT type, url, parameter, payload, severity, description, owasp_category "
        "FROM vulnerabilities WHERE scan_id=?",
        (scan_id,)
    )
    vulns = cursor.fetchall()
    conn.close()

    findings = []
    for v in vulns:
        findings.append({
            "type": v[0],
            "url": v[1],
            "parameter": v[2],
            "payload": v[3],
            "severity": v[4],
            "description": v[5],
            "owasp_category": v[6]
        })

    return jsonify({
        "target": target_url,
        "score": scan_row[1],
        "grade": scan_row[2],
        "tests_passed": scan_row[3],
        "tests_total": scan_row[4],
        "tech_stack": tech_stack,
        "tech_stack_confidence": tech_stack_confidence,
        "tech_stack_details": tech_stack_details,
        "owasp_results": owasp_results,
        "vulnerabilities": findings,
        "summary": {
            "total": len(findings),
            "high": sum(1 for f in findings if f["severity"] == "High"),
            "medium": sum(1 for f in findings if f["severity"] == "Medium"),
            "low": sum(1 for f in findings if f["severity"] == "Low"),
        }
    }), 200


# ---------------------------------------------------------------------------
# Report endpoint (structured JSON for export)
# ---------------------------------------------------------------------------

@app.get("/api/scan/report")
def scan_report():
    """Returns a full structured report suitable for PDF/JSON export."""
    target_url = request.args.get("url")
    if not target_url:
        return jsonify({"error": "URL parameter required"}), 400

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute(
        "SELECT id, score, grade, tests_passed, tests_total, started_at, completed_at, "
        "tech_stack, tech_stack_confidence, tech_stack_details "
        "FROM scans WHERE target_url=? ORDER BY id DESC LIMIT 1",
        (target_url,)
    )
    scan_row = cursor.fetchone()

    if not scan_row:
        conn.close()
        return jsonify({"error": "No scan found"}), 404

    scan_id = scan_row[0]
    tech_stack = scan_row[7]
    tech_stack_confidence = scan_row[8]
    tech_stack_details = json.loads(scan_row[9]) if scan_row[9] else None

    # OWASP results
    cursor.execute(
        "SELECT owasp_id, owasp_name, status, severity, description, recommendation, findings_json "
        "FROM scan_results WHERE scan_id=? ORDER BY owasp_id ASC",
        (scan_id,)
    )
    owasp_rows = cursor.fetchall()

    owasp_results = []
    for r in owasp_rows:
        owasp_results.append({
            "owasp_id": r[0],
            "owasp_name": r[1],
            "status": r[2],
            "severity": r[3],
            "description": r[4],
            "recommendation": r[5],
            "findings": json.loads(r[6]) if r[6] else []
        })

    owasp_results = enrich_owasp_results(owasp_results, tech_stack)


    # Vulnerabilities
    cursor.execute(
        "SELECT type, url, parameter, payload, severity, description, owasp_category "
        "FROM vulnerabilities WHERE scan_id=?",
        (scan_id,)
    )
    vulns = cursor.fetchall()

    # Pages
    cursor.execute("SELECT url FROM pages WHERE scan_id=?", (scan_id,))
    pages = [row[0] for row in cursor.fetchall()]

    conn.close()

    findings = []
    for v in vulns:
        findings.append({
            "type": v[0], "url": v[1], "parameter": v[2],
            "payload": v[3], "severity": v[4],
            "description": v[5], "owasp_category": v[6]
        })

    report = {
        "report_title": "SecureScan Vulnerability Assessment Report",
        "target": target_url,
        "scan_date": scan_row[5],
        "completed_at": scan_row[6],
        "score": scan_row[1],
        "grade": scan_row[2],
        "tests_passed": scan_row[3],
        "tests_total": scan_row[4],
        "tech_stack": tech_stack,
        "tech_stack_confidence": tech_stack_confidence,
        "tech_stack_details": tech_stack_details,
        "pages_crawled": len(pages),
        "owasp_results": owasp_results,
        "vulnerabilities": findings,
        "risk_summary": {
            "total": len(findings),
            "high": sum(1 for f in findings if f["severity"] == "High"),
            "medium": sum(1 for f in findings if f["severity"] == "Medium"),
            "low": sum(1 for f in findings if f["severity"] == "Low"),
        },
        "recommendations": [
            r["recommendation"]
            for r in owasp_results
            if r["status"] == "fail" and r["recommendation"]
        ]
    }

    return jsonify(report), 200


# ---------------------------------------------------------------------------
# History & Timeline
# ---------------------------------------------------------------------------

@app.get("/api/scan/history")
def scan_history():
    """Returns a list of all scans with pagination."""
    page = request.args.get("page", 1, type=int)
    limit = request.args.get("limit", 10, type=int)
    offset = (page - 1) * limit

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # Get total count
    cursor.execute("SELECT COUNT(*) FROM scans")
    total = cursor.fetchone()[0]

    # Get paginated scans ordered by date descending
    cursor.execute(
        "SELECT id, target_url, status, score, grade, started_at, completed_at, tests_passed, tests_total, "
        "tech_stack, tech_stack_confidence "
        "FROM scans ORDER BY started_at DESC LIMIT ? OFFSET ?",
        (limit, offset)
    )
    rows = cursor.fetchall()
    conn.close()

    scans = []
    for row in rows:
        scans.append({
            "id": row[0],
            "target_url": row[1],
            "status": row[2],
            "score": row[3],
            "grade": row[4],
            "started_at": row[5],
            "completed_at": row[6],
            "tests_passed": row[7],
            "tests_total": row[8],
            "tech_stack": row[9],
            "tech_stack_confidence": row[10]
        })

    return jsonify({
        "scans": scans,
        "total": total,
        "page": page,
        "limit": limit,
        "total_pages": (total + limit - 1) // limit
    }), 200


@app.get("/api/scan/report/<int:scan_id>")
def historical_scan_report(scan_id):
    """Returns full report for a specific historical scan by ID."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # Get scan metadata
    cursor.execute(
        "SELECT id, target_url, status, score, grade, tests_passed, tests_total, started_at, completed_at, "
        "tech_stack, tech_stack_confidence, tech_stack_details "
        "FROM scans WHERE id=?",
        (scan_id,)
    )
    scan_row = cursor.fetchone()

    if not scan_row:
        conn.close()
        return jsonify({"error": "Scan not found"}), 404

    target_url = scan_row[1]
    tech_stack = scan_row[9]
    tech_stack_confidence = scan_row[10]
    tech_stack_details = json.loads(scan_row[11]) if scan_row[11] else None

    # Get OWASP results
    cursor.execute(
        "SELECT owasp_id, owasp_name, status, severity, description, recommendation, findings_json "
        "FROM scan_results WHERE scan_id=? ORDER BY owasp_id ASC",
        (scan_id,)
    )
    owasp_rows = cursor.fetchall()

    owasp_results = []
    for r in owasp_rows:
        owasp_results.append({
            "owasp_id": r[0],
            "owasp_name": r[1],
            "status": r[2],
            "severity": r[3],
            "description": r[4],
            "recommendation": r[5],
            "findings": json.loads(r[6]) if r[6] else []
        })

    owasp_results = enrich_owasp_results(owasp_results, tech_stack)


    # Get raw vulnerabilities
    cursor.execute(
        "SELECT type, url, parameter, payload, severity, description, owasp_category "
        "FROM vulnerabilities WHERE scan_id=?",
        (scan_id,)
    )
    vulns = cursor.fetchall()

    # Get pages crawled
    cursor.execute("SELECT url FROM pages WHERE scan_id=?", (scan_id,))
    pages = [row[0] for row in cursor.fetchall()]

    # Get logs for this scan
    cursor.execute(
        "SELECT message, timestamp FROM logs WHERE scan_id=? ORDER BY id ASC",
        (scan_id,)
    )
    log_rows = cursor.fetchall()

    conn.close()

    findings = []
    for v in vulns:
        findings.append({
            "type": v[0],
            "url": v[1],
            "parameter": v[2],
            "payload": v[3],
            "severity": v[4],
            "description": v[5],
            "owasp_category": v[6]
        })

    logs = [{"message": r[0], "timestamp": r[1]} for r in log_rows]

    return jsonify({
        "scan_id": scan_row[0],
        "target": target_url,
        "status": scan_row[2],
        "score": scan_row[3],
        "grade": scan_row[4],
        "tests_passed": scan_row[5],
        "tests_total": scan_row[6],
        "started_at": scan_row[7],
        "completed_at": scan_row[8],
        "tech_stack": tech_stack,
        "tech_stack_confidence": tech_stack_confidence,
        "tech_stack_details": tech_stack_details,
        "pages_crawled": len(pages),
        "owasp_results": owasp_results,
        "vulnerabilities": findings,
        "logs": logs,
        "summary": {
            "total": len(findings),
            "high": sum(1 for f in findings if f["severity"] == "High"),
            "medium": sum(1 for f in findings if f["severity"] == "Medium"),
            "low": sum(1 for f in findings if f["severity"] == "Low"),
        }
    }), 200


# ---------------------------------------------------------------------------
# Logs
# ---------------------------------------------------------------------------

@app.get("/api/scan/logs")
def scan_logs():
    target_url = request.args.get("url")
    if not target_url:
        return jsonify({"error": "URL parameter required"}), 400

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute(
        "SELECT id FROM scans WHERE target_url=? ORDER BY id DESC LIMIT 1",
        (target_url,)
    )
    scan_row = cursor.fetchone()

    if not scan_row:
        conn.close()
        return jsonify({"error": "No scan found"}), 404

    scan_id = scan_row[0]
    cursor.execute(
        "SELECT message, timestamp FROM logs WHERE scan_id=? ORDER BY id ASC",
        (scan_id,)
    )
    rows = cursor.fetchall()
    conn.close()

    logs = [{"message": r[0], "timestamp": r[1]} for r in rows]
    return jsonify({"logs": logs}), 200


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=PORT, debug=True)
