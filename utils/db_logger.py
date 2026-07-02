# utils/db_logger.py
# Firebase Firestore Database Logger (REST API version)
# No SDK needed — works everywhere
# Replaces SQLite completely

import os
import json
from datetime import datetime
from utils.firebase_config import (
    add_document,
    set_document,
    get_document,
    update_document,
    query_collection,
    increment_field
)


# ─────────────────────────────────────────
# INITIALIZE
# ─────────────────────────────────────────

def initialize_database():
    """Sets up initial stats document if not exists."""
    try:
        existing = get_document('system_stats', 'main')
        if not existing:
            set_document('system_stats', 'main', {
                'total_scans'   : 0,
                'total_flagged' : 0,
                'total_blocked' : 0,
                'total_reported': 0,
                'total_banned'  : 0,
                'last_updated'  : datetime.now().isoformat()
            })
        print("Database initialized successfully.")
    except Exception as e:
        print(f"Database init error: {e}")


# ─────────────────────────────────────────
# STATS UPDATER
# ─────────────────────────────────────────

def _update_stats(is_flagged=0, is_blocked=0,
                  is_reported=0, is_banned=0):
    """Updates running counters in Firestore."""
    try:
        increment_field('system_stats', 'main', 'total_scans', 1)
        if is_flagged:
            increment_field('system_stats', 'main',
                          'total_flagged', is_flagged)
        if is_blocked:
            increment_field('system_stats', 'main',
                          'total_blocked', is_blocked)
        if is_reported:
            increment_field('system_stats', 'main',
                          'total_reported', is_reported)
        if is_banned:
            increment_field('system_stats', 'main',
                          'total_banned', is_banned)
        update_document('system_stats', 'main', {
            'last_updated': datetime.now().isoformat()
        })
    except Exception as e:
        print(f"Stats update error: {e}")


# ─────────────────────────────────────────
# SCAN LOGGERS
# ─────────────────────────────────────────

def log_text_scan(text_input, analysis_result):
    """Logs a text scan result to Firestore."""
    try:
        is_flagged = 1 if analysis_result.get('risk_label') == 'HIGH' else 0
        is_blocked = 1 if analysis_result.get('is_scam') else 0
        summary    = (text_input[:100] + '...'
                     if len(text_input) > 100 else text_input)

        add_document('scan_logs', {
            'scan_type'    : 'text',
            'source'       : 'direct',
            'input_summary': summary,
            'risk_score'   : analysis_result.get('risk_score', 0),
            'risk_label'   : analysis_result.get('risk_label', 'LOW'),
            'is_flagged'   : is_flagged,
            'is_blocked'   : is_blocked,
            'scanned_at'   : datetime.now().isoformat()
        })

        if is_flagged:
            keywords     = analysis_result.get('matched_keywords', {})
            all_keywords = (
                keywords.get('high', []) +
                keywords.get('medium', [])
            )
            add_document('flagged_items', {
                    'scan_type'       : 'text',
                    'text'            : text_input,
                    'risk_score'      : analysis_result.get('risk_score', 0),
                    'risk_label'      : analysis_result.get('risk_label', 'HIGH'),
                    'summary'         : analysis_result.get('summary', ''),
                    'matched_keywords': json.dumps(all_keywords),
                    'flagged_at'      : datetime.now().isoformat()
                })

        _update_stats(is_flagged, is_blocked)

    except Exception as e:
        print(f"log_text_scan error: {e}")


def log_file_scan(filename, inspection_result):
    """Logs a file inspection result to Firestore."""
    try:
        is_flagged = 1 if inspection_result.get('risk_label') == 'HIGH' else 0
        is_blocked = 1 if inspection_result.get('is_blocked') else 0

        add_document('scan_logs', {
            'scan_type'    : 'file',
            'source'       : 'upload',
            'input_summary': filename,
            'risk_score'   : inspection_result.get('risk_score', 0),
            'risk_label'   : inspection_result.get('risk_label', 'LOW'),
            'is_flagged'   : is_flagged,
            'is_blocked'   : is_blocked,
            'scanned_at'   : datetime.now().isoformat()
        })

        if is_flagged or is_blocked:
            add_document('flagged_items', {
                    'scan_type'       : 'file',
                    'text'            : f"File: {filename} — {inspection_result.get('reason', '')}",
                    'risk_score'      : inspection_result.get('risk_score', 0),
                    'risk_label'      : inspection_result.get('risk_label', 'LOW'),
                    'summary'         : inspection_result.get('reason', ''),
                    'matched_keywords' : json.dumps(
                        [inspection_result.get('extension', '')]
                    ),
                    'flagged_at'      : datetime.now().isoformat()
                })

        _update_stats(is_flagged, is_blocked)

    except Exception as e:
        print(f"log_file_scan error: {e}")


def log_image_scan(filename, ocr_result):
    """Logs an image OCR scan result to Firestore."""
    try:
        analysis   = ocr_result.get('analysis', {})
        is_flagged = 1 if analysis.get('risk_label') == 'HIGH' else 0
        is_blocked = 1 if analysis.get('is_scam') else 0

        add_document('scan_logs', {
            'scan_type'    : 'image',
            'source'       : 'upload',
            'input_summary': filename,
            'risk_score'   : analysis.get('risk_score', 0),
            'risk_label'   : analysis.get('risk_label', 'LOW'),
            'is_flagged'   : is_flagged,
            'is_blocked'   : is_blocked,
            'scanned_at'   : datetime.now().isoformat()
        })

        if is_flagged:
            keywords     = analysis.get('matched_keywords', {})
            all_keywords = (
                keywords.get('high', []) +
                keywords.get('medium', [])
            )
            add_document('flagged_items', {
                    'scan_type'       : 'image',
                    'text'            : ocr_result.get('extracted_text', ''),
                    'risk_score'      : analysis.get('risk_score', 0),
                    'risk_label'      : analysis.get('risk_label', 'HIGH'),
                    'summary'         : analysis.get('summary', ''),
                    'matched_keywords' : json.dumps(all_keywords),
                    'flagged_at'      : datetime.now().isoformat()
                })

        _update_stats(is_flagged, is_blocked)

    except Exception as e:
        print(f"log_image_scan error: {e}")


def log_qr_scan(qr_result):
    """Logs a QR scan result to Firestore."""
    try:
        analysis = qr_result.get('analysis', {})

        add_document('qr_scan_logs', {
            'image_name' : qr_result.get('image_name', 'unknown'),
            'qr_content' : qr_result.get('qr_content', ''),
            'content_type': (analysis.get('content_type', 'unknown')
                            if analysis else 'unknown'),
            'risk_score' : analysis.get('risk_score', 0) if analysis else 0,
            'risk_label' : analysis.get('risk_label', 'LOW') if analysis else 'LOW',
            'is_blocked' : analysis.get('is_blocked', False) if analysis else False,
            'flags'      : analysis.get('flags', []) if analysis else [],
            'scanned_at' : datetime.now().isoformat()
        })

    except Exception as e:
        print(f"log_qr_scan error: {e}")


# ─────────────────────────────────────────
# COMMUNITY DEFENSE
# ─────────────────────────────────────────

def report_message(reported_by, message_content, reason,
                   message_sender=None, risk_score=0,
                   media_url=None, media_type=None, file_name=None):
    try:
        add_document('reported_messages', {
            'reported_by'    : reported_by,
            'message_sender' : message_sender or 'unknown',
            'message_content': message_content,
            'reason'         : reason,
            'risk_score'     : risk_score,
            'media_url'      : media_url or '',
            'media_type'     : media_type or 'text',
            'file_name'      : file_name or '',
            'status'         : 'pending',
            'reviewed_by'    : None,
            'reported_at'    : datetime.now().isoformat(),
            'reviewed_at'    : None
        })
        increment_field('system_stats', 'main', 'total_reported', 1)
    except Exception as e:
        print(f"report_message error: {e}")


def report_user(reported_by, reported_user,
                reason, evidence=None):
    """Logs a reported user."""
    try:
        add_document('reported_users', {
            'reported_by'  : reported_by,
            'reported_user': reported_user,
            'reason'       : reason,
            'evidence'     : evidence,
            'status'       : 'pending',
            'reviewed_by'  : None,
            'reported_at'  : datetime.now().isoformat(),
            'reviewed_at'  : None
        })
        increment_field('system_stats', 'main', 'total_reported', 1)
    except Exception as e:
        print(f"report_user error: {e}")


# ─────────────────────────────────────────
# GOVERNANCE
# ─────────────────────────────────────────

def ban_user(user_id, ban_type, reason,
             device_id=None, banned_by='admin',
             expires_at=None, source_report_id=None):
    """Bans a user. Optionally links to the report that caused it."""
    try:
        add_document('banned_users', {
            'user_id'          : user_id,
            'device_id'        : device_id,
            'ban_type'         : ban_type,
            'reason'           : reason,
            'banned_by'        : banned_by,
            'banned_at'        : datetime.now().isoformat(),
            'expires_at'       : expires_at,
            'is_active'        : True,
            'source_report_id' : source_report_id
        })
        increment_field('system_stats', 'main', 'total_banned', 1)
        log_admin_action('ban_user', banned_by, target=user_id,
                          details=f"{ban_type} ban — {reason}")
    except Exception as e:
        print(f"ban_user error: {e}")


def unban_user(user_id, unbanned_by='admin'):
    """Removes active ban for a user."""
    try:
        docs = query_collection(
            'banned_users',
            filters=[
                ('user_id', 'EQUAL', user_id),
                ('is_active', 'EQUAL', True)
            ]
        )
        for doc in docs:
            update_document('banned_users', doc['id'],
                          {'is_active': False})
        log_admin_action('unban_user', unbanned_by, target=user_id)
    except Exception as e:
        print(f"unban_user error: {e}")


def is_user_banned(user_id):
    """Checks if user is currently banned."""
    try:
        docs = query_collection(
            'banned_users',
            filters=[
                ('user_id', 'EQUAL', user_id),
                ('is_active', 'EQUAL', True)
            ],
            limit=1
        )
        return docs[0] if docs else None
    except Exception as e:
        print(f"is_user_banned error: {e}")
        return None


# ─────────────────────────────────────────
# TRUST SCORE
# ─────────────────────────────────────────

def get_user_trust_score(user_id):
    """Calculates trust score for a user."""
    try:
        report_docs = query_collection(
            'reported_users',
            filters=[('reported_user', 'EQUAL', user_id)]
        )
        report_count = len(report_docs)

        temp_docs = query_collection(
            'banned_users',
            filters=[
                ('user_id', 'EQUAL', user_id),
                ('ban_type', 'EQUAL', 'temporary')
            ]
        )
        temp_count = len(temp_docs)

        perm_docs = query_collection(
            'banned_users',
            filters=[
                ('user_id', 'EQUAL', user_id),
                ('ban_type', 'EQUAL', 'permanent')
            ]
        )
        perm_count = len(perm_docs)

        active_ban = is_user_banned(user_id)

        score  = 100
        score -= report_count * 10
        score -= temp_count   * 20
        score -= perm_count   * 50
        if active_ban:
            score -= 30
        score = max(0, min(100, score))

        if score >= 70:
            trust_label = 'HIGH'
            trust_color = 'green'
        elif score >= 40:
            trust_label = 'MEDIUM'
            trust_color = 'orange'
        else:
            trust_label = 'LOW'
            trust_color = 'red'

        return {
            'user_id'            : user_id,
            'trust_score'        : score,
            'trust_label'        : trust_label,
            'trust_color'        : trust_color,
            'is_currently_banned': active_ban is not None,
            'report_count'       : report_count,
            'temp_ban_count'     : temp_count,
            'perm_ban_count'     : perm_count,
            'breakdown': {
                'base_score'        : 100,
                'reports_penalty'   : -(report_count * 10),
                'temp_ban_penalty'  : -(temp_count * 20),
                'perm_ban_penalty'  : -(perm_count * 50),
                'active_ban_penalty': -30 if active_ban else 0
            }
        }
    except Exception as e:
        print(f"get_user_trust_score error: {e}")
        return {
            'user_id'    : user_id,
            'trust_score': 100,
            'trust_label': 'HIGH',
            'trust_color': 'green'
        }


# ─────────────────────────────────────────
# AWARENESS & EDUCATION
# ─────────────────────────────────────────

def create_security_alert(title, message, severity='medium',
                          created_by='admin', expires_at=None):
    """Creates a security alert."""
    try:
        add_document('security_alerts', {
            'title'     : title,
            'message'   : message,
            'severity'  : severity,
            'created_by': created_by,
            'is_active' : True,
            'created_at': datetime.now().isoformat(),
            'expires_at': expires_at
        })
        log_admin_action('create_alert', created_by, target=title)
    except Exception as e:
        print(f"create_security_alert error: {e}")


def get_active_alerts():
    """Returns all active security alerts."""
    try:
        return query_collection(
            'security_alerts',
            filters=[('is_active', 'EQUAL', True)],
            order_by='created_at'
        )
    except Exception as e:
        print(f"get_active_alerts error: {e}")
        return []


def deactivate_alert(alert_id):
    """Deactivates a security alert."""
    try:
        update_document('security_alerts', alert_id,
                       {'is_active': False})
    except Exception as e:
        print(f"deactivate_alert error: {e}")


def create_phishing_drill(title, drill_message,
                          target_user='all', created_by='admin'):
    """Creates a phishing drill."""
    try:
        add_document('phishing_drills', {
            'title'        : title,
            'drill_message': drill_message,
            'target_user'  : target_user,
            'status'       : 'active',
            'created_by'   : created_by,
            'created_at'   : datetime.now().isoformat(),
            'pass_count'   : 0,
            'fail_count'   : 0
        })
        log_admin_action('create_drill', created_by, target=title)
    except Exception as e:
        print(f"create_phishing_drill error: {e}")


def record_drill_result(drill_id, passed):
    """Records drill result."""
    try:
        field = 'pass_count' if passed else 'fail_count'
        increment_field('phishing_drills', drill_id, field, 1)
    except Exception as e:
        print(f"record_drill_result error: {e}")


def get_all_drills():
    """Returns all phishing drills."""
    try:
        return query_collection(
            'phishing_drills',
            order_by='created_at'
        )
    except Exception as e:
        print(f"get_all_drills error: {e}")
        return []


def add_safety_tip(category, title, content, created_by='admin'):
    """Adds a safety tip."""
    try:
        add_document('safety_tips', {
            'category'  : category,
            'title'     : title,
            'content'   : content,
            'created_by': created_by,
            'is_active' : True,
            'created_at': datetime.now().isoformat()
        })
        log_admin_action('create_tip', created_by, target=title)
    except Exception as e:
        print(f"add_safety_tip error: {e}")


def get_safety_tips(category=None):
    """Returns active safety tips."""
    try:
        filters = [('is_active', 'EQUAL', True)]
        if category:
            filters.append(('category', 'EQUAL', category))
        return query_collection(
            'safety_tips',
            filters=filters,
            order_by='created_at'
        )
    except Exception as e:
        print(f"get_safety_tips error: {e}")
        return []


def submit_user_feedback(user_id, message,
                         feedback_type='general', rating=None):
    """Submits user feedback."""
    try:
        add_document('user_feedback', {
            'user_id'      : user_id,
            'feedback_type': feedback_type,
            'message'      : message,
            'rating'       : rating,
            'status'       : 'unread',
            'submitted_at' : datetime.now().isoformat()
        })
    except Exception as e:
        print(f"submit_user_feedback error: {e}")


def get_user_feedback(status=None):
    """Returns user feedback."""
    try:
        filters = []
        if status:
            filters.append(('status', 'EQUAL', status))
        return query_collection(
            'user_feedback',
            filters=filters if filters else None,
            order_by='submitted_at'
        )
    except Exception as e:
        print(f"get_user_feedback error: {e}")
        return []


# ─────────────────────────────────────────
# ADMIN QUERIES
# ─────────────────────────────────────────

def get_all_flagged(limit=50):
    """Returns most recent flagged items."""
    try:
        return query_collection(
            'flagged_items',
            order_by='flagged_at',
            limit=limit
        )
    except Exception as e:
        print(f"get_all_flagged error: {e}")
        return []


def get_scan_history(limit=100):
    """Returns recent scan history."""
    try:
        return query_collection(
            'scan_logs',
            order_by='scanned_at',
            limit=limit
        )
    except Exception as e:
        print(f"get_scan_history error: {e}")
        return []


def get_system_stats():
    """Returns system health stats."""
    try:
        return get_document('system_stats', 'main') or {}
    except Exception as e:
        print(f"get_system_stats error: {e}")
        return {}


def get_pending_reports(limit=50):
    """Returns all pending reports."""
    try:
        messages = query_collection(
            'reported_messages',
            filters=[('status', 'EQUAL', 'pending')],
            order_by='reported_at',
            limit=limit
        )
        users = query_collection(
            'reported_users',
            filters=[('status', 'EQUAL', 'pending')],
            order_by='reported_at',
            limit=limit
        )
        return {
            'reported_messages': messages,
            'reported_users'   : users
        }
    except Exception as e:
        print(f"get_pending_reports error: {e}")
        return {'reported_messages': [], 'reported_users': []}


# ─────────────────────────────────────────
# USER LOOKUP (for displaying real names)
# ─────────────────────────────────────────

def get_user_display_name(user_id):
    """
    Looks up a user's display name from the 'users' collection.
    Falls back to the raw user_id if not found.
    """
    try:
        if not user_id or user_id == 'unknown':
            return user_id or 'unknown'
        user_doc = get_document('users', user_id)
        if user_doc:
            return (user_doc.get('display_name') or
                    user_doc.get('name') or
                    user_doc.get('username') or
                    user_id)
        return user_id
    except Exception as e:
        print(f"get_user_display_name error: {e}")
        return user_id


def get_banned_users(limit=50):
    """Returns all active banned users."""
    try:
        return query_collection(
            'banned_users',
            filters=[('is_active', 'EQUAL', True)],
            order_by='banned_at',
            limit=limit
        )
    except Exception as e:
        print(f"get_banned_users error: {e}")
        return []

def get_banned_users_with_names(limit=50):
    """Returns active banned users with display names looked up from users collection."""
    try:
        bans = query_collection(
            'banned_users',
            filters=[('is_active', 'EQUAL', True)],
            order_by='banned_at',
            limit=limit
        )
        for ban in bans:
            uid = ban.get('user_id', '')
            if uid:
                user_doc = get_document('users', uid)
                if user_doc:
                    ban['display_name'] = (
                        user_doc.get('fullName') or
                        user_doc.get('full_name') or
                        user_doc.get('name') or
                        uid
                    )
                    ban['email'] = user_doc.get('email', '')
                else:
                    ban['display_name'] = uid
        return bans
    except Exception as e:
        print(f"get_banned_users_with_names error: {e}")
        return []

def get_qr_scan_history(limit=50):
    """Returns QR scan history."""
    try:
        return query_collection(
            'qr_scan_logs',
            order_by='scanned_at',
            limit=limit
        )
    except Exception as e:
        print(f"get_qr_scan_history error: {e}")
        return []


# ─────────────────────────────────────────
# ADMIN ACTIVITY LOG (separate from user scans)
# ─────────────────────────────────────────

def log_admin_action(action_type, performed_by, target=None, details=None):
    """
    Logs an admin action for the Activity Monitoring screen.
    action_type examples: 'ban_user', 'unban_user', 'create_alert',
    'create_drill', 'create_tip', 'review_message_report',
    'review_user_report', 'update_alert', 'delete_alert'
    """
    try:
        add_document('admin_actions', {
            'action_type' : action_type,
            'performed_by': performed_by,
            'target'      : target or '',
            'details'     : details or '',
            'timestamp'   : datetime.now().isoformat()
        })
    except Exception as e:
        print(f"log_admin_action error: {e}")


def get_admin_actions(limit=100):
    """Returns admin activity log, most recent first."""
    try:
        return query_collection(
            'admin_actions',
            order_by='timestamp',
            limit=limit
        )
    except Exception as e:
        print(f"get_admin_actions error: {e}")
        return []


# ─────────────────────────────────────────
# REPORT REVIEW ACTIONS
# ─────────────────────────────────────────

def review_message_report(report_id, decision, reviewed_by='admin'):
    """
    Admin marks a reported message as 'confirmed_scam' or 'not_scam'.
    Does NOT ban anyone — pure content moderation.
    """
    try:
        update_document('reported_messages', report_id, {
            'status'     : decision,  # 'confirmed_scam' or 'not_scam'
            'reviewed_by': reviewed_by,
            'reviewed_at': datetime.now().isoformat()
        })
        log_admin_action(
            'review_message_report', reviewed_by,
            target=report_id, details=f"Marked as {decision}"
        )
    except Exception as e:
        print(f"review_message_report error: {e}")


def review_user_report(report_id, decision, reviewed_by='admin'):
    """
    Admin marks a reported user report as 'dismissed' or 'actioned'.
    The actual ban is a separate call to ban_user().
    """
    try:
        update_document('reported_users', report_id, {
            'status'     : decision,  # 'dismissed' or 'actioned'
            'reviewed_by': reviewed_by,
            'reviewed_at': datetime.now().isoformat()
        })
        log_admin_action(
            'review_user_report', reviewed_by,
            target=report_id, details=f"Marked as {decision}"
        )
    except Exception as e:
        print(f"review_user_report error: {e}")