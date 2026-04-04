import sqlite3
import os
from typing import Dict, List, Any

DB_PATH = os.path.join(os.path.dirname(__file__), "securescan.db")

def init_db():
    """Initializes the SQLite database with necessary tables."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target_url TEXT NOT NULL,
            status TEXT NOT NULL,
            started_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            completed_at DATETIME
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER,
            message TEXT NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(scan_id) REFERENCES scans(id)
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS pages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER,
            url TEXT NOT NULL,
            FOREIGN KEY(scan_id) REFERENCES scans(id)
        )
    """)

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
            FOREIGN KEY(scan_id) REFERENCES scans(id)
        )
    """)

    conn.commit()
    conn.close()

def create_scan(target_url: str) -> int:
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("INSERT INTO scans (target_url, status) VALUES (?, 'running')", (target_url,))
    scan_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return scan_id

def complete_scan(scan_id: int):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("UPDATE scans SET status='completed', completed_at=CURRENT_TIMESTAMP WHERE id=?", (scan_id,))
    conn.commit()
    conn.close()

def save_pages(scan_id: int, urls: List[str]):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    for url in urls:
        cursor.execute("INSERT INTO pages (scan_id, url) VALUES (?, ?)", (scan_id, url))
    conn.commit()
    conn.close()

def save_vulnerabilities(scan_id: int, vulnerabilities: List[Dict[str, Any]]):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    for vuln in vulnerabilities:
        cursor.execute("""
            INSERT INTO vulnerabilities (scan_id, type, url, parameter, payload, severity, description)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            scan_id,
            vuln.get("type", "Unknown"),
            vuln.get("url", ""),
            vuln.get("parameter", ""),
            vuln.get("payload", ""),
            vuln.get("severity", "Low"),
            vuln.get("details", vuln.get("description", ""))
        ))
    conn.commit()
    conn.close()

def save_log(scan_id: int, message: str):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("INSERT INTO logs (scan_id, message) VALUES (?, ?)", (scan_id, message))
    conn.commit()
    conn.close()

def get_logs(scan_id: int) -> List[Dict[str, Any]]:
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT message, timestamp FROM logs WHERE scan_id=? ORDER BY id ASC", (scan_id,))
    rows = cursor.fetchall()
    conn.close()
    return [{"message": r[0], "timestamp": r[1]} for r in rows]

# Initialize upon import
init_db()
