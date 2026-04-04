import os
import threading
from dotenv import load_dotenv
from flask import Flask, jsonify, request
from flask_cors import CORS
import sqlite3

from core.engine import ScannerEngine
from security import validate_target_url
from database import DB_PATH

load_dotenv()

PORT = int(os.getenv("PORT", "5000"))
FRONTEND_ORIGIN = os.getenv("FRONTEND_ORIGIN", "http://localhost:5173")

app = Flask(__name__)
CORS(app, resources={r"/api/*": {"origins": [FRONTEND_ORIGIN]}})

@app.get("/api/health")
def health():
    return jsonify({"status": "ok"})

def run_background_scan(target_url: str):
    try:
        engine = ScannerEngine(target_url, max_depth=2)
        engine.run()
    except Exception as e:
        print(f"Background scan failed: {e}")

@app.post("/api/scan/start")
def start_scan():
    payload = request.get_json(silent=True) or {}
    raw_url = payload.get("url", "")

    try:
        target_url = validate_target_url(raw_url)
        
        # Start in background
        thread = threading.Thread(target=run_background_scan, args=(target_url,))
        thread.start()

        return jsonify({"message": "Scan started", "target": target_url}), 202

    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    except Exception as e:
        return jsonify({"error": "Scan failed due to an unexpected error"}), 500

@app.get("/api/scan/status")
def scan_status():
    target_url = request.args.get("url")
    if not target_url:
        return jsonify({"error": "URL parameter required"}), 400

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    # Get the latest scan for this URL
    cursor.execute("SELECT status, started_at, completed_at FROM scans WHERE target_url=? ORDER BY id DESC LIMIT 1", (target_url,))
    row = cursor.fetchone()
    conn.close()

    if not row:
        return jsonify({"status": "not_found"}), 404

    return jsonify({
        "status": row[0],
        "started_at": row[1],
        "completed_at": row[2]
    }), 200

@app.get("/api/scan/results")
def scan_results():
    target_url = request.args.get("url")
    if not target_url:
        return jsonify({"error": "URL parameter required"}), 400

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM scans WHERE target_url=? ORDER BY id DESC LIMIT 1", (target_url,))
    scan_row = cursor.fetchone()
    
    if not scan_row:
        conn.close()
        return jsonify({"error": "No scan found"}), 404
        
    scan_id = scan_row[0]

    # Get vulnerabilities
    cursor.execute("SELECT type, url, parameter, payload, severity, description FROM vulnerabilities WHERE scan_id=?", (scan_id,))
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
            "description": v[5]
        })

    return jsonify({
        "target": target_url,
        "vulnerabilities": findings,
        "summary": {
            "total": len(findings),
            "high": sum(1 for f in findings if f["severity"] == "High"),
            "medium": sum(1 for f in findings if f["severity"] == "Medium"),
            "low": sum(1 for f in findings if f["severity"] == "Low"),
        }
    }), 200

@app.get("/api/scan/logs")
def scan_logs():
    target_url = request.args.get("url")
    if not target_url:
        return jsonify({"error": "URL parameter required"}), 400

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM scans WHERE target_url=? ORDER BY id DESC LIMIT 1", (target_url,))
    scan_row = cursor.fetchone()
    
    if not scan_row:
        conn.close()
        return jsonify({"error": "No scan found"}), 404
        
    scan_id = scan_row[0]
    cursor.execute("SELECT message, timestamp FROM logs WHERE scan_id=? ORDER BY id ASC", (scan_id,))
    rows = cursor.fetchall()
    conn.close()

    logs = [{"message": r[0], "timestamp": r[1]} for r in rows]
    return jsonify({"logs": logs}), 200

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=PORT, debug=True)
