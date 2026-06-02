# utils/db_logger.py
# Database Logger Module
# Saves all scan results to SQLite for admin dashboard access
# Tables: scan_logs, flagged_items

import sqlite3
import os
import json
from datetime import datetime

# ─────────────────────────────────────────
# DATABASE SETUP
# ─────────────────────────────────────────

DB_PATH = "genius_talk.db"


def get_connection():
    """Get a database connection."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row  # Returns rows as dictionaries
    return conn


def initialize_database():
    """
    Creates all tables if they don't exist yet.
    Call this once when server starts.
    """
    conn = get_connection()
    cursor = conn.cursor()

    # ── Table 1: All scan logs ──
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS scan_logs (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_type       TEXT NOT NULL,
            source          TEXT NOT NULL,
            input_summary   TEXT,
            risk_score      INTEGER,
            risk_label      TEXT,
            is_flagged      INTEGER DEFAULT 0,
            is_blocked      INTEGER DEFAULT 0,
            details_json    TEXT,
            scanned_at      TEXT NOT NULL
        )
    ''')

    # ── Table 2: Flagged items only (HIGH risk) ──
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS flagged_items (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_log_id     INTEGER,
            scan_type       TEXT NOT NULL,
            risk_score      INTEGER,
            risk_label      TEXT,
            summary         TEXT,
            matched_keywords TEXT,
            flagged_at      TEXT NOT NULL,
            FOREIGN KEY (scan_log_id) REFERENCES scan_logs(id)
        )
    ''')

    # ── Table 3: System health stats ──
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS system_stats (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            total_scans     INTEGER DEFAULT 0,
            total_flagged   INTEGER DEFAULT 0,
            total_blocked   INTEGER DEFAULT 0,
            last_updated    TEXT
        )
    ''')

    # Insert initial stats row if empty
    cursor.execute('SELECT COUNT(*) FROM system_stats')
    if cursor.fetchone()[0] == 0:
        cursor.execute('''
            INSERT INTO system_stats (total_scans, total_flagged, total_blocked, last_updated)
            VALUES (0, 0, 0, ?)
        ''', (datetime.now().isoformat(),))

    conn.commit()
    conn.close()
    print("Database initialized successfully.")


# ─────────────────────────────────────────
# LOGGING FUNCTIONS
# ─────────────────────────────────────────

def log_text_scan(text_input, analysis_result):
    """
    Logs a text scan result.
    Called after every /scan/text request.
    """
    conn = get_connection()
    cursor = conn.cursor()

    is_flagged = 1 if analysis_result.get("risk_label") == "HIGH" else 0
    is_blocked = 1 if analysis_result.get("is_scam") else 0

    # Shorten input for summary (don't store full message for privacy)
    input_summary = text_input[:100] + "..." if len(text_input) > 100 else text_input

    cursor.execute('''
        INSERT INTO scan_logs
        (scan_type, source, input_summary, risk_score, risk_label,
         is_flagged, is_blocked, details_json, scanned_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        "text",
        "direct",
        input_summary,
        analysis_result.get("risk_score", 0),
        analysis_result.get("risk_label", "LOW"),
        is_flagged,
        is_blocked,
        json.dumps(analysis_result),
        datetime.now().isoformat()
    ))

    scan_id = cursor.lastrowid

    # If HIGH risk — also add to flagged_items table
    if is_flagged:
        keywords = analysis_result.get("matched_keywords", {})
        all_keywords = (
            keywords.get("high", []) +
            keywords.get("medium", [])
        )
        cursor.execute('''
            INSERT INTO flagged_items
            (scan_log_id, scan_type, risk_score, risk_label,
             summary, matched_keywords, flagged_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (
            scan_id,
            "text",
            analysis_result.get("risk_score", 0),
            analysis_result.get("risk_label", "LOW"),
            analysis_result.get("summary", ""),
            json.dumps(all_keywords),
            datetime.now().isoformat()
        ))

    _update_stats(cursor, is_flagged, is_blocked)
    conn.commit()
    conn.close()
    return scan_id


def log_file_scan(filename, inspection_result):
    """
    Logs a file inspection result.
    Called after every /scan/file request.
    """
    conn = get_connection()
    cursor = conn.cursor()

    is_flagged = 1 if inspection_result.get("risk_label") == "HIGH" else 0
    is_blocked = 1 if inspection_result.get("is_blocked") else 0

    cursor.execute('''
        INSERT INTO scan_logs
        (scan_type, source, input_summary, risk_score, risk_label,
         is_flagged, is_blocked, details_json, scanned_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        "file",
        "upload",
        filename,
        inspection_result.get("risk_score", 0),
        inspection_result.get("risk_label", "LOW"),
        is_flagged,
        is_blocked,
        json.dumps(inspection_result),
        datetime.now().isoformat()
    ))

    scan_id = cursor.lastrowid

    if is_flagged or is_blocked:
        cursor.execute('''
            INSERT INTO flagged_items
            (scan_log_id, scan_type, risk_score, risk_label,
             summary, matched_keywords, flagged_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (
            scan_id,
            "file",
            inspection_result.get("risk_score", 0),
            inspection_result.get("risk_label", "LOW"),
            inspection_result.get("reason", ""),
            json.dumps([inspection_result.get("extension", "")]),
            datetime.now().isoformat()
        ))

    _update_stats(cursor, is_flagged, is_blocked)
    conn.commit()
    conn.close()
    return scan_id


def log_image_scan(filename, ocr_result):
    """
    Logs an image OCR scan result.
    Called after every /scan/image request.
    """
    conn = get_connection()
    cursor = conn.cursor()

    analysis = ocr_result.get("analysis", {})
    is_flagged = 1 if analysis.get("risk_label") == "HIGH" else 0
    is_blocked = 1 if analysis.get("is_scam") else 0

    cursor.execute('''
        INSERT INTO scan_logs
        (scan_type, source, input_summary, risk_score, risk_label,
         is_flagged, is_blocked, details_json, scanned_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        "image",
        "upload",
        filename,
        analysis.get("risk_score", 0),
        analysis.get("risk_label", "LOW"),
        is_flagged,
        is_blocked,
        json.dumps(ocr_result),
        datetime.now().isoformat()
    ))

    scan_id = cursor.lastrowid

    if is_flagged:
        keywords = analysis.get("matched_keywords", {})
        all_keywords = (
            keywords.get("high", []) +
            keywords.get("medium", [])
        )
        cursor.execute('''
            INSERT INTO flagged_items
            (scan_log_id, scan_type, risk_score, risk_label,
             summary, matched_keywords, flagged_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (
            scan_id,
            "image",
            analysis.get("risk_score", 0),
            analysis.get("risk_label", "LOW"),
            analysis.get("summary", ""),
            json.dumps(all_keywords),
            datetime.now().isoformat()
        ))

    _update_stats(cursor, is_flagged, is_blocked)
    conn.commit()
    conn.close()
    return scan_id


# ─────────────────────────────────────────
# STATS UPDATER
# ─────────────────────────────────────────

def _update_stats(cursor, is_flagged, is_blocked):
    """Updates the running system stats counters."""
    cursor.execute('''
        UPDATE system_stats SET
            total_scans   = total_scans + 1,
            total_flagged = total_flagged + ?,
            total_blocked = total_blocked + ?,
            last_updated  = ?
        WHERE id = 1
    ''', (is_flagged, is_blocked, datetime.now().isoformat()))


# ─────────────────────────────────────────
# QUERY FUNCTIONS (for admin dashboard)
# ─────────────────────────────────────────

def get_all_flagged(limit=50):
    """Returns the most recent flagged items — for admin flagged logs view."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT * FROM flagged_items
        ORDER BY flagged_at DESC
        LIMIT ?
    ''', (limit,))
    rows = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return rows


def get_scan_history(limit=100):
    """Returns recent scan history — for admin activity monitoring."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT id, scan_type, source, input_summary,
               risk_score, risk_label, is_flagged,
               is_blocked, scanned_at
        FROM scan_logs
        ORDER BY scanned_at DESC
        LIMIT ?
    ''', (limit,))
    rows = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return rows


def get_system_stats():
    """Returns overall system health stats."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM system_stats WHERE id = 1')
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else {}


# ─────────────────────────────────────────
# QUICK TEST
# ─────────────────────────────────────────

if __name__ == "__main__":
    print("Initializing database...")
    initialize_database()

    # Simulate logging a scam text scan
    print("\nLogging a fake scam text scan...")
    fake_analysis = {
        "risk_score"      : 87,
        "risk_label"      : "HIGH",
        "is_scam"         : True,
        "matched_keywords": {"high": ["you won", "bank details"], "medium": [], "low": []},
        "summary"         : "High risk keywords detected: you won, bank details",
        "source"          : "direct"
    }
    scan_id = log_text_scan("URGENT! You won RM10,000! Send bank details now!", fake_analysis)
    print(f"Logged with scan ID: {scan_id}")

    # Simulate logging a safe file scan
    print("\nLogging a fake safe file scan...")
    fake_file = {
        "risk_score" : 10,
        "risk_label" : "LOW",
        "is_blocked" : False,
        "reason"     : "File appears safe"
    }
    log_file_scan("photo.jpg", fake_file)

    # Check stats
    print("\nSystem stats:")
    print(json.dumps(get_system_stats(), indent=2))

    # Check flagged items
    print("\nFlagged items:")
    print(json.dumps(get_all_flagged(), indent=2))

    # Check scan history
    print("\nScan history:")
    print(json.dumps(get_scan_history(), indent=2))