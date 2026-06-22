# utils/db_logger.py
# Complete Database Logger
# Tables: scan_logs, flagged_items, system_stats,
#         qr_scan_logs, reported_messages, reported_users, banned_users

import sqlite3
import os
import json
from datetime import datetime

DB_PATH = "genius_talk.db"


# ─────────────────────────────────────────
# CONNECTION
# ─────────────────────────────────────────

def get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


# ─────────────────────────────────────────
# INITIALIZE ALL TABLES
# ─────────────────────────────────────────

def initialize_database():
    conn   = get_connection()
    cursor = conn.cursor()

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS scan_logs (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_type     TEXT NOT NULL,
            source        TEXT NOT NULL,
            input_summary TEXT,
            risk_score    INTEGER,
            risk_label    TEXT,
            is_flagged    INTEGER DEFAULT 0,
            is_blocked    INTEGER DEFAULT 0,
            details_json  TEXT,
            scanned_at    TEXT NOT NULL
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS flagged_items (
            id               INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_log_id      INTEGER,
            scan_type        TEXT NOT NULL,
            risk_score       INTEGER,
            risk_label       TEXT,
            summary          TEXT,
            matched_keywords TEXT,
            flagged_at       TEXT NOT NULL,
            FOREIGN KEY (scan_log_id) REFERENCES scan_logs(id)
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS system_stats (
            id             INTEGER PRIMARY KEY AUTOINCREMENT,
            total_scans    INTEGER DEFAULT 0,
            total_flagged  INTEGER DEFAULT 0,
            total_blocked  INTEGER DEFAULT 0,
            total_reported INTEGER DEFAULT 0,
            total_banned   INTEGER DEFAULT 0,
            last_updated   TEXT
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS qr_scan_logs (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            image_name   TEXT,
            qr_content   TEXT,
            content_type TEXT,
            risk_score   INTEGER,
            risk_label   TEXT,
            is_blocked   INTEGER DEFAULT 0,
            flags_json   TEXT,
            scanned_at   TEXT NOT NULL
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS reported_messages (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            reported_by     TEXT,
            message_content TEXT,
            reason          TEXT,
            risk_score      INTEGER DEFAULT 0,
            status          TEXT DEFAULT 'pending',
            reviewed_by     TEXT DEFAULT NULL,
            reported_at     TEXT NOT NULL,
            reviewed_at     TEXT DEFAULT NULL
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS reported_users (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            reported_by   TEXT,
            reported_user TEXT,
            reason        TEXT,
            evidence      TEXT DEFAULT NULL,
            status        TEXT DEFAULT 'pending',
            reviewed_by   TEXT DEFAULT NULL,
            reported_at   TEXT NOT NULL,
            reviewed_at   TEXT DEFAULT NULL
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS banned_users (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id    TEXT NOT NULL,
            device_id  TEXT DEFAULT NULL,
            ban_type   TEXT NOT NULL,
            reason     TEXT,
            banned_by  TEXT DEFAULT 'system',
            banned_at  TEXT NOT NULL,
            expires_at TEXT DEFAULT NULL,
            is_active  INTEGER DEFAULT 1
        )
    ''')

    # ── Table 8: Security alerts ──
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS security_alerts (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            title        TEXT NOT NULL,
            message      TEXT NOT NULL,
            severity     TEXT DEFAULT 'medium',
            created_by   TEXT DEFAULT 'admin',
            is_active    INTEGER DEFAULT 1,
            created_at   TEXT NOT NULL,
            expires_at   TEXT DEFAULT NULL
        )
    ''')

    # ── Table 9: Phishing drills ──
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS phishing_drills (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            title        TEXT NOT NULL,
            drill_message TEXT NOT NULL,
            target_user  TEXT DEFAULT 'all',
            status       TEXT DEFAULT 'active',
            created_by   TEXT DEFAULT 'admin',
            created_at   TEXT NOT NULL,
            pass_count   INTEGER DEFAULT 0,
            fail_count   INTEGER DEFAULT 0
        )
    ''')

    # ── Table 10: Safety tips ──
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS safety_tips (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            category     TEXT NOT NULL,
            title        TEXT NOT NULL,
            content      TEXT NOT NULL,
            created_by   TEXT DEFAULT 'admin',
            is_active    INTEGER DEFAULT 1,
            created_at   TEXT NOT NULL
        )
    ''')

    # ── Table 11: User feedback ──
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS user_feedback (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id      TEXT,
            feedback_type TEXT DEFAULT 'general',
            message      TEXT NOT NULL,
            rating       INTEGER DEFAULT NULL,
            status       TEXT DEFAULT 'unread',
            submitted_at TEXT NOT NULL
        )
    ''')

    cursor.execute('SELECT COUNT(*) FROM system_stats')
    if cursor.fetchone()[0] == 0:
        cursor.execute('''
            INSERT INTO system_stats
            (total_scans, total_flagged, total_blocked,
             total_reported, total_banned, last_updated)
            VALUES (0, 0, 0, 0, 0, ?)
        ''', (datetime.now().isoformat(),))

    conn.commit()
    conn.close()
    print("Database initialized successfully.")


# ─────────────────────────────────────────
# STATS UPDATER
# ─────────────────────────────────────────

def _update_stats(cursor, is_flagged=0, is_blocked=0,
                  is_reported=0, is_banned=0):
    cursor.execute('''
        UPDATE system_stats SET
            total_scans    = total_scans    + 1,
            total_flagged  = total_flagged  + ?,
            total_blocked  = total_blocked  + ?,
            total_reported = total_reported + ?,
            total_banned   = total_banned   + ?,
            last_updated   = ?
        WHERE id = 1
    ''', (is_flagged, is_blocked, is_reported,
          is_banned, datetime.now().isoformat()))


# ─────────────────────────────────────────
# SCAN LOGGERS
# ─────────────────────────────────────────

def log_text_scan(text_input, analysis_result):
    """Logs a text scan result."""
    conn   = get_connection()
    cursor = conn.cursor()

    is_flagged = 1 if analysis_result.get("risk_label") == "HIGH" else 0
    is_blocked = 1 if analysis_result.get("is_scam") else 0
    summary    = text_input[:100] + "..." if len(text_input) > 100 else text_input

    cursor.execute('''
        INSERT INTO scan_logs
        (scan_type, source, input_summary, risk_score, risk_label,
         is_flagged, is_blocked, details_json, scanned_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        "text", "direct", summary,
        analysis_result.get("risk_score", 0),
        analysis_result.get("risk_label", "LOW"),
        is_flagged, is_blocked,
        json.dumps(analysis_result),
        datetime.now().isoformat()
    ))

    scan_id = cursor.lastrowid

    if is_flagged:
        keywords     = analysis_result.get("matched_keywords", {})
        all_keywords = (
            keywords.get("high", []) + keywords.get("medium", [])
        )
        cursor.execute('''
            INSERT INTO flagged_items
            (scan_log_id, scan_type, risk_score, risk_label,
             summary, matched_keywords, flagged_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (
            scan_id, "text",
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
    """Logs a file inspection result."""
    conn   = get_connection()
    cursor = conn.cursor()

    is_flagged = 1 if inspection_result.get("risk_label") == "HIGH" else 0
    is_blocked = 1 if inspection_result.get("is_blocked") else 0

    cursor.execute('''
        INSERT INTO scan_logs
        (scan_type, source, input_summary, risk_score, risk_label,
         is_flagged, is_blocked, details_json, scanned_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        "file", "upload", filename,
        inspection_result.get("risk_score", 0),
        inspection_result.get("risk_label", "LOW"),
        is_flagged, is_blocked,
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
            scan_id, "file",
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
    """Logs an image OCR scan result."""
    conn   = get_connection()
    cursor = conn.cursor()

    analysis   = ocr_result.get("analysis", {})
    is_flagged = 1 if analysis.get("risk_label") == "HIGH" else 0
    is_blocked = 1 if analysis.get("is_scam") else 0

    cursor.execute('''
        INSERT INTO scan_logs
        (scan_type, source, input_summary, risk_score, risk_label,
         is_flagged, is_blocked, details_json, scanned_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        "image", "upload", filename,
        analysis.get("risk_score", 0),
        analysis.get("risk_label", "LOW"),
        is_flagged, is_blocked,
        json.dumps(ocr_result),
        datetime.now().isoformat()
    ))

    scan_id = cursor.lastrowid

    if is_flagged:
        keywords     = analysis.get("matched_keywords", {})
        all_keywords = (
            keywords.get("high", []) + keywords.get("medium", [])
        )
        cursor.execute('''
            INSERT INTO flagged_items
            (scan_log_id, scan_type, risk_score, risk_label,
             summary, matched_keywords, flagged_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (
            scan_id, "image",
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


def log_qr_scan(qr_result):
    """Logs a QR code scan result."""
    conn     = get_connection()
    cursor   = conn.cursor()
    analysis = qr_result.get("analysis", {})

    if analysis:
        risk_score = analysis.get("risk_score", 0)
        risk_label = analysis.get("risk_label", "LOW")
        is_blocked = 1 if analysis.get("is_blocked") else 0
        flags      = analysis.get("flags", [])
    else:
        risk_score = 0
        risk_label = "LOW"
        is_blocked = 0
        flags      = []

    cursor.execute('''
        INSERT INTO qr_scan_logs
        (image_name, qr_content, content_type, risk_score,
         risk_label, is_blocked, flags_json, scanned_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        qr_result.get("image_name", "unknown"),
        qr_result.get("qr_content", ""),
        analysis.get("content_type", "unknown"),
        risk_score, risk_label, is_blocked,
        json.dumps(flags),
        datetime.now().isoformat()
    ))

    conn.commit()
    conn.close()


# ─────────────────────────────────────────
# COMMUNITY DEFENSE HUB
# ─────────────────────────────────────────

def report_message(reported_by, message_content, reason, risk_score=0):
    """Logs a reported message."""
    conn   = get_connection()
    cursor = conn.cursor()

    cursor.execute('''
        INSERT INTO reported_messages
        (reported_by, message_content, reason,
         risk_score, status, reported_at)
        VALUES (?, ?, ?, ?, 'pending', ?)
    ''', (
        reported_by, message_content,
        reason, risk_score,
        datetime.now().isoformat()
    ))

    cursor.execute('''
        UPDATE system_stats SET
            total_reported = total_reported + 1,
            last_updated   = ?
        WHERE id = 1
    ''', (datetime.now().isoformat(),))

    conn.commit()
    conn.close()


def report_user(reported_by, reported_user, reason, evidence=None):
    """Logs a reported user."""
    conn   = get_connection()
    cursor = conn.cursor()

    cursor.execute('''
        INSERT INTO reported_users
        (reported_by, reported_user, reason,
         evidence, status, reported_at)
        VALUES (?, ?, ?, ?, 'pending', ?)
    ''', (
        reported_by, reported_user,
        reason, evidence,
        datetime.now().isoformat()
    ))

    cursor.execute('''
        UPDATE system_stats SET
            total_reported = total_reported + 1,
            last_updated   = ?
        WHERE id = 1
    ''', (datetime.now().isoformat(),))

    conn.commit()
    conn.close()


# ─────────────────────────────────────────
# GOVERNANCE MANAGER
# ─────────────────────────────────────────

def ban_user(user_id, ban_type, reason,
             device_id=None, banned_by="admin", expires_at=None):
    """Bans a user. ban_type = 'temporary' or 'permanent'."""
    conn   = get_connection()
    cursor = conn.cursor()

    cursor.execute('''
        INSERT INTO banned_users
        (user_id, device_id, ban_type, reason,
         banned_by, banned_at, expires_at, is_active)
        VALUES (?, ?, ?, ?, ?, ?, ?, 1)
    ''', (
        user_id, device_id, ban_type, reason,
        banned_by, datetime.now().isoformat(), expires_at
    ))

    cursor.execute('''
        UPDATE system_stats SET
            total_banned = total_banned + 1,
            last_updated = ?
        WHERE id = 1
    ''', (datetime.now().isoformat(),))

    conn.commit()
    conn.close()


def unban_user(user_id):
    """Removes active ban for a user."""
    conn   = get_connection()
    cursor = conn.cursor()
    cursor.execute('''
        UPDATE banned_users SET is_active = 0
        WHERE user_id = ? AND is_active = 1
    ''', (user_id,))
    conn.commit()
    conn.close()


def is_user_banned(user_id):
    """Checks if a user is currently banned."""
    conn   = get_connection()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT * FROM banned_users
        WHERE user_id = ? AND is_active = 1
        ORDER BY banned_at DESC LIMIT 1
    ''', (user_id,))
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None

# ─────────────────────────────────────────
# TRUST SCORE
# ─────────────────────────────────────────

def get_user_trust_score(user_id):
    """
    Calculates a trust score for a user based on their history.

    Score starts at 100 and decreases based on:
    - Each report against them  : -10 points
    - Each temporary ban        : -20 points
    - Each permanent ban        : -50 points
    - Currently banned          : -30 extra points

    Score ranges:
    0  - 39  = LOW TRUST  (red)
    40 - 69  = MEDIUM TRUST (orange)
    70 - 100 = HIGH TRUST (green)
    """
    conn   = get_connection()
    cursor = conn.cursor()

    # Count reports against this user
    cursor.execute('''
        SELECT COUNT(*) FROM reported_users
        WHERE reported_user = ?
    ''', (user_id,))
    report_count = cursor.fetchone()[0]

    # Count temporary bans
    cursor.execute('''
        SELECT COUNT(*) FROM banned_users
        WHERE user_id = ? AND ban_type = 'temporary'
    ''', (user_id,))
    temp_ban_count = cursor.fetchone()[0]

    # Count permanent bans
    cursor.execute('''
        SELECT COUNT(*) FROM banned_users
        WHERE user_id = ? AND ban_type = 'permanent'
    ''', (user_id,))
    perm_ban_count = cursor.fetchone()[0]

    # Check if currently banned
    cursor.execute('''
        SELECT COUNT(*) FROM banned_users
        WHERE user_id = ? AND is_active = 1
    ''', (user_id,))
    is_currently_banned = cursor.fetchone()[0] > 0

    conn.close()

    # Calculate score
    score = 100
    score -= report_count  * 10
    score -= temp_ban_count * 20
    score -= perm_ban_count * 50
    if is_currently_banned:
        score -= 30

    # Clamp between 0 and 100
    score = max(0, min(100, score))

    # Determine label
    if score >= 70:
        trust_label = "HIGH"
        trust_color = "green"
    elif score >= 40:
        trust_label = "MEDIUM"
        trust_color = "orange"
    else:
        trust_label = "LOW"
        trust_color = "red"

    return {
        "user_id"           : user_id,
        "trust_score"       : score,
        "trust_label"       : trust_label,
        "trust_color"       : trust_color,
        "is_currently_banned": is_currently_banned,
        "report_count"      : report_count,
        "temp_ban_count"    : temp_ban_count,
        "perm_ban_count"    : perm_ban_count,
        "breakdown"         : {
            "base_score"       : 100,
            "reports_penalty"  : -(report_count * 10),
            "temp_ban_penalty" : -(temp_ban_count * 20),
            "perm_ban_penalty" : -(perm_ban_count * 50),
            "active_ban_penalty": -30 if is_currently_banned else 0
        }
    }

# ─────────────────────────────────────────
# AWARENESS & EDUCATION MANAGER
# ─────────────────────────────────────────

def create_security_alert(title, message, severity="medium",
                          created_by="admin", expires_at=None):
    """
    Creates a new security alert broadcast.
    severity = 'low', 'medium', 'high', 'critical'
    """
    conn   = get_connection()
    cursor = conn.cursor()

    cursor.execute('''
        INSERT INTO security_alerts
        (title, message, severity, created_by, is_active,
         created_at, expires_at)
        VALUES (?, ?, ?, ?, 1, ?, ?)
    ''', (
        title, message, severity,
        created_by, datetime.now().isoformat(), expires_at
    ))

    conn.commit()
    conn.close()


def get_active_alerts():
    """Returns all currently active security alerts."""
    conn   = get_connection()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT * FROM security_alerts
        WHERE is_active = 1
        ORDER BY created_at DESC
    ''')
    rows = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return rows


def deactivate_alert(alert_id):
    """Deactivates a security alert."""
    conn   = get_connection()
    cursor = conn.cursor()
    cursor.execute('''
        UPDATE security_alerts SET is_active = 0
        WHERE id = ?
    ''', (alert_id,))
    conn.commit()
    conn.close()


def create_phishing_drill(title, drill_message,
                          target_user="all", created_by="admin"):
    """
    Creates a phishing drill — a fake scam message sent to test users.
    Users who report it = pass. Users who click = fail.
    """
    conn   = get_connection()
    cursor = conn.cursor()

    cursor.execute('''
        INSERT INTO phishing_drills
        (title, drill_message, target_user,
         status, created_by, created_at)
        VALUES (?, ?, ?, 'active', ?, ?)
    ''', (
        title, drill_message,
        target_user, created_by,
        datetime.now().isoformat()
    ))

    conn.commit()
    conn.close()


def record_drill_result(drill_id, passed):
    """
    Records a user's response to a phishing drill.
    passed=True means user correctly identified and reported it.
    passed=False means user fell for it.
    """
    conn   = get_connection()
    cursor = conn.cursor()

    if passed:
        cursor.execute('''
            UPDATE phishing_drills
            SET pass_count = pass_count + 1
            WHERE id = ?
        ''', (drill_id,))
    else:
        cursor.execute('''
            UPDATE phishing_drills
            SET fail_count = fail_count + 1
            WHERE id = ?
        ''', (drill_id,))

    conn.commit()
    conn.close()


def get_all_drills():
    """Returns all phishing drills."""
    conn   = get_connection()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT * FROM phishing_drills
        ORDER BY created_at DESC
    ''')
    rows = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return rows


def add_safety_tip(category, title, content, created_by="admin"):
    """
    Adds a new safety tip.
    category = 'phishing', 'malware', 'qr_scam',
               'social_engineering', 'general'
    """
    conn   = get_connection()
    cursor = conn.cursor()

    cursor.execute('''
        INSERT INTO safety_tips
        (category, title, content, created_by,
         is_active, created_at)
        VALUES (?, ?, ?, ?, 1, ?)
    ''', (
        category, title, content,
        created_by, datetime.now().isoformat()
    ))

    conn.commit()
    conn.close()


def get_safety_tips(category=None):
    """
    Returns active safety tips.
    Optionally filter by category.
    """
    conn   = get_connection()
    cursor = conn.cursor()

    if category:
        cursor.execute('''
            SELECT * FROM safety_tips
            WHERE is_active = 1 AND category = ?
            ORDER BY created_at DESC
        ''', (category,))
    else:
        cursor.execute('''
            SELECT * FROM safety_tips
            WHERE is_active = 1
            ORDER BY created_at DESC
        ''')

    rows = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return rows


def submit_user_feedback(user_id, message,
                         feedback_type="general", rating=None):
    """
    Submits user feedback about the app or a scan result.
    feedback_type = 'general', 'false_positive',
                   'false_negative', 'suggestion'
    rating = 1-5 or None
    """
    conn   = get_connection()
    cursor = conn.cursor()

    cursor.execute('''
        INSERT INTO user_feedback
        (user_id, feedback_type, message,
         rating, status, submitted_at)
        VALUES (?, ?, ?, ?, 'unread', ?)
    ''', (
        user_id, feedback_type,
        message, rating,
        datetime.now().isoformat()
    ))

    conn.commit()
    conn.close()


def get_user_feedback(status=None):
    """
    Returns user feedback.
    Optionally filter by status: 'unread', 'read', 'resolved'
    """
    conn   = get_connection()
    cursor = conn.cursor()

    if status:
        cursor.execute('''
            SELECT * FROM user_feedback
            WHERE status = ?
            ORDER BY submitted_at DESC
        ''', (status,))
    else:
        cursor.execute('''
            SELECT * FROM user_feedback
            ORDER BY submitted_at DESC
        ''')

    rows = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return rows

# ─────────────────────────────────────────
# ADMIN QUERY FUNCTIONS
# ─────────────────────────────────────────

def get_all_flagged(limit=50):
    """Returns most recent flagged HIGH risk items."""
    conn   = get_connection()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT * FROM flagged_items
        ORDER BY flagged_at DESC LIMIT ?
    ''', (limit,))
    rows = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return rows


def get_scan_history(limit=100):
    """Returns recent scan history."""
    conn   = get_connection()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT id, scan_type, source, input_summary,
               risk_score, risk_label, is_flagged,
               is_blocked, scanned_at
        FROM scan_logs
        ORDER BY scanned_at DESC LIMIT ?
    ''', (limit,))
    rows = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return rows


def get_system_stats():
    """Returns system health stats."""
    conn   = get_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM system_stats WHERE id = 1')
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else {}


def get_pending_reports(limit=50):
    """Returns all pending reported messages and users."""
    conn   = get_connection()
    cursor = conn.cursor()

    cursor.execute('''
        SELECT * FROM reported_messages
        WHERE status = 'pending'
        ORDER BY reported_at DESC LIMIT ?
    ''', (limit,))
    messages = [dict(row) for row in cursor.fetchall()]

    cursor.execute('''
        SELECT * FROM reported_users
        WHERE status = 'pending'
        ORDER BY reported_at DESC LIMIT ?
    ''', (limit,))
    users = [dict(row) for row in cursor.fetchall()]

    conn.close()
    return {"reported_messages": messages, "reported_users": users}


def get_banned_users(limit=50):
    """Returns all active banned users."""
    conn   = get_connection()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT * FROM banned_users
        WHERE is_active = 1
        ORDER BY banned_at DESC LIMIT ?
    ''', (limit,))
    rows = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return rows


def get_qr_scan_history(limit=50):
    """Returns QR scan history."""
    conn   = get_connection()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT * FROM qr_scan_logs
        ORDER BY scanned_at DESC LIMIT ?
    ''', (limit,))
    rows = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return rows