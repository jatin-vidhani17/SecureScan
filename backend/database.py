"""
Database layer for SecureScan.
Manages SQLite tables for scans, pages, vulnerabilities, OWASP results, and logs.
"""

import sqlite3
import os
from typing import Dict, List, Any

DB_PATH = os.path.join(os.path.dirname(__file__), "securescan.db")


def _get_conn():
    """Get a new SQLite connection with WAL mode for concurrency."""
    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def init_db():
    """Initializes the SQLite database with all necessary tables."""
    conn = _get_conn()
    cursor = conn.cursor()

    # --- Scans table (enhanced with score/grade) ---
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target_url TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'running',
            score INTEGER DEFAULT NULL,
            grade TEXT DEFAULT NULL,
            tests_passed INTEGER DEFAULT NULL,
            tests_total INTEGER DEFAULT 10,
            tech_stack TEXT DEFAULT NULL,
            tech_stack_confidence REAL DEFAULT NULL,
            tech_stack_details TEXT DEFAULT NULL,
            started_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            completed_at DATETIME
        )
    """)

    _ensure_scan_columns(conn)

    # --- Logs table ---
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER,
            message TEXT NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(scan_id) REFERENCES scans(id)
        )
    """)

    # --- Crawled pages ---
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS pages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER,
            url TEXT NOT NULL,
            FOREIGN KEY(scan_id) REFERENCES scans(id)
        )
    """)

    # --- Raw vulnerabilities (kept for backward compat) ---
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS vulnerabilities (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER,
            type TEXT NOT NULL,
            url TEXT NOT NULL,
            parameter TEXT,
            payload TEXT,
            severity TEXT,
            description TEXT,
            owasp_category TEXT,
            FOREIGN KEY(scan_id) REFERENCES scans(id)
        )
    """)

    # --- OWASP test results (new) ---
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scan_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER,
            owasp_id TEXT NOT NULL,
            owasp_name TEXT NOT NULL,
            status TEXT NOT NULL,
            severity TEXT,
            description TEXT,
            recommendation TEXT,
            findings_json TEXT,
            FOREIGN KEY(scan_id) REFERENCES scans(id)
        )
    """)

    conn.commit()
    conn.close()


# ---------------------------------------------------------------------------
# Scan lifecycle
# ---------------------------------------------------------------------------

def create_scan(target_url: str) -> int:
    conn = _get_conn()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO scans (target_url, status) VALUES (?, 'running')",
        (target_url,)
    )
    scan_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return scan_id


def complete_scan(scan_id: int):
    conn = _get_conn()
    cursor = conn.cursor()
    cursor.execute(
        "UPDATE scans SET status='completed', completed_at=CURRENT_TIMESTAMP WHERE id=?",
        (scan_id,)
    )
    conn.commit()
    conn.close()


def cancel_scan(scan_id: int):
    """Mark a scan as cancelled with current timestamp."""
    conn = _get_conn()
    cursor = conn.cursor()
    cursor.execute(
        "UPDATE scans SET status='cancelled', completed_at=CURRENT_TIMESTAMP WHERE id=?",
        (scan_id,)
    )
    conn.commit()
    conn.close()


def mark_scan_error(scan_id: int, error_message: str):
    """Mark a scan as errored with error message."""
    conn = _get_conn()
    cursor = conn.cursor()
    cursor.execute(
        "UPDATE scans SET status='error', completed_at=CURRENT_TIMESTAMP WHERE id=?",
        (scan_id,)
    )
    conn.commit()
    conn.close()


def update_scan_score(scan_id: int, score: int, grade: str, tests_passed: int, tests_total: int):
    """Update the scan record with the calculated score and grade."""
    conn = _get_conn()
    cursor = conn.cursor()
    cursor.execute(
        "UPDATE scans SET score=?, grade=?, tests_passed=?, tests_total=? WHERE id=?",
        (score, grade, tests_passed, tests_total, scan_id)
    )
    conn.commit()
    conn.close()


def update_scan_tech_stack(scan_id: int, tech_stack: str, confidence: float, details_json: str):
    """Update the scan record with detected tech stack information."""
    conn = _get_conn()
    cursor = conn.cursor()
    cursor.execute(
        "UPDATE scans SET tech_stack=?, tech_stack_confidence=?, tech_stack_details=? WHERE id=?",
        (tech_stack, confidence, details_json, scan_id)
    )
    conn.commit()
    conn.close()


def _ensure_scan_columns(conn: sqlite3.Connection):
    """Ensure new scan columns exist in older databases."""
    cursor = conn.cursor()
    cursor.execute("PRAGMA table_info(scans)")
    existing_columns = {row[1] for row in cursor.fetchall()}

    required_columns = {
        "tech_stack": "TEXT",
        "tech_stack_confidence": "REAL",
        "tech_stack_details": "TEXT",
    }

    for column, col_type in required_columns.items():
        if column not in existing_columns:
            cursor.execute(f"ALTER TABLE scans ADD COLUMN {column} {col_type}")

    conn.commit()


# ---------------------------------------------------------------------------
# Pages
# ---------------------------------------------------------------------------

def save_pages(scan_id: int, urls: List[str]):
    conn = _get_conn()
    cursor = conn.cursor()
    for url in urls:
        cursor.execute("INSERT INTO pages (scan_id, url) VALUES (?, ?)", (scan_id, url))
    conn.commit()
    conn.close()


# ---------------------------------------------------------------------------
# Vulnerabilities (legacy / raw findings)
# ---------------------------------------------------------------------------

def save_vulnerabilities(scan_id: int, vulnerabilities: List[Dict[str, Any]]):
    conn = _get_conn()
    cursor = conn.cursor()
    for vuln in vulnerabilities:
        cursor.execute("""
            INSERT INTO vulnerabilities (scan_id, type, url, parameter, payload, severity, description, owasp_category)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            scan_id,
            vuln.get("type", "Unknown"),
            vuln.get("url", ""),
            vuln.get("parameter", ""),
            vuln.get("payload", ""),
            vuln.get("severity", "Low"),
            vuln.get("details", vuln.get("description", "")),
            vuln.get("owasp_category", "")
        ))
    conn.commit()
    conn.close()


# ---------------------------------------------------------------------------
# OWASP test results (new)
# ---------------------------------------------------------------------------

def save_owasp_results(scan_id: int, owasp_results: List[Dict[str, Any]]):
    """Persist the structured OWASP test results to the scan_results table."""
    import json
    conn = _get_conn()
    cursor = conn.cursor()
    for result in owasp_results:
        cursor.execute("""
            INSERT INTO scan_results (scan_id, owasp_id, owasp_name, status, severity, description, recommendation, findings_json)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            scan_id,
            result.get("owasp_id", ""),
            result.get("owasp_name", ""),
            result.get("status", "fail"),
            result.get("severity", "Medium"),
            result.get("description", ""),
            result.get("recommendation", ""),
            json.dumps(result.get("findings", []))
        ))
    conn.commit()
    conn.close()


# ---------------------------------------------------------------------------
# Logs
# ---------------------------------------------------------------------------

def save_log(scan_id: int, message: str):
    conn = _get_conn()
    cursor = conn.cursor()
    cursor.execute("INSERT INTO logs (scan_id, message) VALUES (?, ?)", (scan_id, message))
    conn.commit()
    conn.close()


def get_logs(scan_id: int) -> List[Dict[str, Any]]:
    conn = _get_conn()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT message, timestamp FROM logs WHERE scan_id=? ORDER BY id ASC",
        (scan_id,)
    )
    rows = cursor.fetchall()
    conn.close()
    return [{"message": r[0], "timestamp": r[1]} for r in rows]


def cleanup_stale_scans():
    """Mark any scans left in 'running' status as 'interrupted'.
    This handles the case where the server was killed mid-scan."""
    conn = _get_conn()
    cursor = conn.cursor()
    cursor.execute(
        "UPDATE scans SET status='interrupted', completed_at=CURRENT_TIMESTAMP "
        "WHERE status='running'"
    )
    count = cursor.rowcount
    conn.commit()
    conn.close()
    if count > 0:
        print(f"[DB Cleanup] Marked {count} stale running scan(s) as 'interrupted'.")


def has_running_scan() -> bool:
    """Check if there is any scan currently in 'running' status."""
    conn = _get_conn()
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM scans WHERE status='running'")
    count = cursor.fetchone()[0]
    conn.close()
    return count > 0


# Initialize upon import
init_db()
cleanup_stale_scans()
