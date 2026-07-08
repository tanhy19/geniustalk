# utils/db_logger.py
# Firebase Firestore Database Logger (REST API version)

import os
import json
import hashlib
import random
from datetime import datetime, timezone, timedelta
from utils.firebase_config import (
    add_document,
    set_document,
    get_document,
    get_collection,
    update_document,
    query_collection,
    increment_field
)


FAILED_LOGIN_LIMIT = 5
LOCKOUT_MINUTES = 15
SECURITY_QUESTION = "What is the name of your first pet?"


def _now_utc():
    return datetime.now(timezone.utc)


def _parse_datetime(value):
    if not value:
        return None
    if isinstance(value, datetime):
        return value.astimezone(timezone.utc)
    if isinstance(value, str):
        try:
            parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
            if parsed.tzinfo is None:
                return parsed.replace(tzinfo=timezone.utc)
            return parsed.astimezone(timezone.utc)
        except Exception:
            return None
    return None


def _minutes_left(until_dt):
    if not until_dt:
        return 0
    diff = int((until_dt - _now_utc()).total_seconds() / 60)
    return max(diff, 0)


def _email_key(email):
    normalized = (email or '').strip().lower()
    digest = hashlib.sha256(normalized.encode('utf-8')).hexdigest()[:24]
    return f'email_{digest}'


def _normalize_alert_audience(value):
    normalized = (value or 'public').strip().lower()
    return 'private' if normalized == 'private' else 'public'


def _normalize_alert_category(value):
    normalized = (value or 'general').strip().lower()
    return normalized or 'general'


def _is_private_system_alert(alert):
    created_by = (alert.get('created_by') or '').strip().lower()
    audience = _normalize_alert_audience(alert.get('audience'))
    category = _normalize_alert_category(alert.get('category'))
    if audience == 'private' or category == 'account_security':
        return True

    if created_by != 'system':
        return False

    haystack = ' '.join([
        str(alert.get('title') or ''),
        str(alert.get('message') or ''),
        str(alert.get('details') or ''),
    ]).lower()
    private_markers = [
        'account temporarily locked',
        'locked after 5 failed login attempts',
        'new device login',
        'failed login attempts',
        'unlock otp',
        'account unlocked',
    ]
    return any(marker in haystack for marker in private_markers)


def _matches_private_alert_target(alert, target_user_id=None, target_email=None):
    normalized_user_id = (target_user_id or '').strip()
    normalized_email = (target_email or '').strip().lower()
    if not normalized_user_id and not normalized_email:
        return True

    alert_user_id = (alert.get('target_user_id') or '').strip()
    alert_email = (alert.get('target_email') or '').strip().lower()
    if normalized_user_id and alert_user_id and alert_user_id == normalized_user_id:
        return True
    if normalized_email and alert_email and alert_email == normalized_email:
        return True
    return False


def _dedupe_activity_rows(rows):
    deduped = []
    seen = set()
    for row in rows:
        key = row.get('id') or (
            row.get('event_type'),
            row.get('timestamp'),
            row.get('email'),
            row.get('user_id'),
        )
        if key in seen:
            continue
        seen.add(key)
        deduped.append(row)
    return deduped

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


def log_image_scan(filename, result):
    """
    Logs an image scan transaction cleanly based on the new ocr_engine schema.
    """
    try:
        # Extract data from the new structure safely using .get()
        extracted_text = result.get("extracted_text", "")
        text_length    = result.get("text_length", 0)
        has_text       = result.get("has_text", False)
        
        # Pull metadata values from the inner image_properties dictionary
        properties     = result.get("image_properties", {})
        is_suspicious  = properties.get("is_suspicious", False)
        reasons        = properties.get("suspicion_reason", [])
        img_format     = properties.get("format", "unknown")
        
        scan_record = {
            "filename"       : filename,
            "timestamp"      : datetime.now(timezone.utc).isoformat(),
            "extracted_text" : extracted_text,
            "text_length"    : text_length,
            "has_text"       : has_text,
            "is_suspicious"  : is_suspicious,
            "reasons"        : reasons,
            "format"         : img_format,
            "status"         : "success" if not result.get("error") else "failed",
            "error_message"  : result.get("error")
        }
        
        # ── FIXED: Call standalone add_document directly ──
        return add_document("image_scans", scan_record)
    except Exception as e:
        print(f"[db_logger] log_image_scan error: {e}")
        return None


def log_qr_scan(result):
    """
    Logs a QR code transaction matching the nested qr_scanner schema.
    """
    try:
        filename   = result.get("image_name", "unknown")
        qr_found   = result.get("qr_found", False)
        qr_content = result.get("qr_content", "")
        
        # Pull risk tags from the inner analysis dictionary
        analysis   = result.get("analysis") or {}
        risk_score = analysis.get("risk_score", 0)
        risk_label = analysis.get("risk_label", "LOW")
        is_blocked = analysis.get("is_blocked", False)
        flags      = analysis.get("flags", [])
        url_type   = analysis.get("content_type", "unknown")
        
        scan_record = {
            "filename"     : filename,
            "timestamp"    : datetime.now(timezone.utc).isoformat(), # ── FIXED: added timezone here too ──
            "qr_found"     : qr_found,
            "content"      : qr_content,
            "content_type" : url_type,
            "risk_score"   : risk_score,
            "risk_label"   : risk_label,
            "is_blocked"   : is_blocked,
            "flags"        : flags,
            "error_message": result.get("error")
        }
        
        # ── FIXED: Call standalone add_document directly ──
        return add_document("qr_scans", scan_record)
    except Exception as e:
        print(f"[db_logger] log_qr_scan error: {e}")
        return None
    
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


def is_device_banned(device_id):
    """Checks if a device is currently banned."""
    if not device_id:
        return None
    try:
        docs = query_collection(
            'banned_users',
            filters=[
                ('device_id', 'EQUAL', device_id),
                ('is_active', 'EQUAL', True)
            ],
            limit=1
        )
        return docs[0] if docs else None
    except Exception as e:
        print(f"is_device_banned error: {e}")
        return None


# ─────────────────────────────────────────
# AUTH SECURITY (FAILED LOGIN PROTECTION)
# ─────────────────────────────────────────
def get_login_security_state(email):
    """
    Returns lockout state for an email.
    - 1st lockout: auto-unlocks after LOCKOUT_MINUTES.
    - 2nd lockout: permanent — is_permanently_locked=True, requires admin unlock.
    """
    try:
        normalized = (email or '').strip().lower()
        if not normalized:
            return {
                'email': '',
                'failed_attempts': 0,
                'attempts_left': FAILED_LOGIN_LIMIT,
                'is_locked': False,
                'is_permanently_locked': False,
                'lock_until': None,
                'minutes_until_unlock': 0,
                'requires_admin_unlock': False,
            }

        doc_id = _email_key(normalized)
        state = get_document('login_protection', doc_id) or {}

        failed_attempts = int(state.get('failed_attempts', 0) or 0)
        lockout_count = int(state.get('lockout_count', 0) or 0)
        is_permanently_locked = bool(state.get('is_permanently_locked', False))
        lock_until_raw = state.get('lock_until')
        lock_until = _parse_datetime(lock_until_raw)
        is_locked = bool(state.get('is_locked', False))

        # Auto-unlock only applies to the FIRST (temporary) lockout.
        if is_locked and not is_permanently_locked and lock_until and _now_utc() >= lock_until:
            is_locked = False
            failed_attempts = 0
            lock_until = None
            update_document('login_protection', doc_id, {
                'is_locked': False,
                'failed_attempts': 0,
                'lock_until': None,
                'updated_at': _now_utc().isoformat(),
            })

        minutes_until_unlock = _minutes_left(lock_until) if not is_permanently_locked else 0
        attempts_left = max(FAILED_LOGIN_LIMIT - failed_attempts, 0)

        return {
            'email': normalized,
            'failed_attempts': failed_attempts,
            'attempts_left': attempts_left,
            'is_locked': is_locked or is_permanently_locked,
            'is_permanently_locked': is_permanently_locked,
            'lock_until': lock_until.isoformat() if lock_until else None,
            'minutes_until_unlock': minutes_until_unlock,
            'requires_admin_unlock': is_permanently_locked,
        }
    except Exception as e:
        print(f"get_login_security_state error: {e}")
        return {
            'email': (email or '').strip().lower(),
            'failed_attempts': 0,
            'attempts_left': FAILED_LOGIN_LIMIT,
            'is_locked': False,
            'is_permanently_locked': False,
            'lock_until': None,
            'minutes_until_unlock': 0,
            'requires_admin_unlock': False,
        }


def reset_failed_login_attempts(email):
    """Clears failed login attempts and unlocks an account (does NOT clear lockout_count)."""
    try:
        normalized = (email or '').strip().lower()
        if not normalized:
            return False
        doc_id = _email_key(normalized)
        existing = get_document('login_protection', doc_id) or {}
        return set_document('login_protection', doc_id, {
            'email': normalized,
            'failed_attempts': 0,
            'is_locked': False,
            'lock_until': None,
            'lockout_count': existing.get('lockout_count', 0),
            'is_permanently_locked': existing.get('is_permanently_locked', False),
            'updated_at': _now_utc().isoformat(),
        })
    except Exception as e:
        print(f"reset_failed_login_attempts error: {e}")
        return False


def record_failed_login_attempt(email):
    """
    Increments failed attempts. On hitting FAILED_LOGIN_LIMIT:
      - 1st time  -> temporary lock, auto-unlocks after LOCKOUT_MINUTES
      - 2nd+ time -> permanent lock, requires admin unlock
    """
    try:
        normalized = (email or '').strip().lower()
        if not normalized:
            return get_login_security_state(normalized)

        state = get_login_security_state(normalized)
        doc_id = _email_key(normalized)

        if state.get('is_locked'):
            return state

        existing_doc = get_document('login_protection', doc_id) or {}
        lockout_count = int(existing_doc.get('lockout_count', 0) or 0)

        failed_attempts = int(state.get('failed_attempts', 0) or 0) + 1
        hit_limit = failed_attempts >= FAILED_LOGIN_LIMIT

        is_locked = False
        is_permanently_locked = False
        lock_until = None

        if hit_limit:
            lockout_count += 1
            if lockout_count >= 2:
                is_permanently_locked = True
                is_locked = True
            else:
                is_locked = True
                lock_until = _now_utc() + timedelta(minutes=LOCKOUT_MINUTES)

        set_document('login_protection', doc_id, {
            'email': normalized,
            'failed_attempts': failed_attempts,
            'is_locked': is_locked,
            'is_permanently_locked': is_permanently_locked,
            'lockout_count': lockout_count,
            'lock_until': lock_until.isoformat() if lock_until else None,
            'last_failed_at': _now_utc().isoformat(),
            'updated_at': _now_utc().isoformat(),
        })

        return {
            'email': normalized,
            'failed_attempts': failed_attempts,
            'attempts_left': max(FAILED_LOGIN_LIMIT - failed_attempts, 0),
            'is_locked': is_locked,
            'is_permanently_locked': is_permanently_locked,
            'lock_until': lock_until.isoformat() if lock_until else None,
            'minutes_until_unlock': LOCKOUT_MINUTES if (is_locked and not is_permanently_locked) else 0,
            'requires_admin_unlock': is_permanently_locked,
        }
    except Exception as e:
        print(f"record_failed_login_attempt error: {e}")
        return get_login_security_state(email)


def get_locked_accounts(limit=50):
    """Returns accounts that are permanently locked and need admin unlock."""
    try:
        docs = query_collection(
            'login_protection',
            filters=[('is_permanently_locked', 'EQUAL', True)],
            limit=limit,
        )
        return docs
    except Exception as e:
        print(f"get_locked_accounts error: {e}")
        return []


def admin_unlock_account(email, unlocked_by='admin'):
    """Admin fully resets an account's lockout state (temporary or permanent)."""
    try:
        normalized = (email or '').strip().lower()
        if not normalized:
            return {'success': False, 'error': 'Email is required'}
        doc_id = _email_key(normalized)
        set_document('login_protection', doc_id, {
            'email': normalized,
            'failed_attempts': 0,
            'is_locked': False,
            'is_permanently_locked': False,
            'lockout_count': 0,
            'lock_until': None,
            'updated_at': _now_utc().isoformat(),
        })
        log_admin_action('unlock_account', unlocked_by, target=normalized,
                          details='Account lockout manually cleared by admin')
        return {'success': True, 'email': normalized}
    except Exception as e:
        print(f"admin_unlock_account error: {e}")
        return {'success': False, 'error': str(e)}


# ─────────────────────────────────────────
# SECURITY QUESTION (replaces email OTP for MFA + unlock)
# ─────────────────────────────────────────

def _answer_hash(answer):
    normalized = (answer or '').strip().lower()
    return hashlib.sha256(normalized.encode('utf-8')).hexdigest()


def set_security_answer(email, answer):
    """Stores a hashed security-question answer for a user, set at registration."""
    try:
        normalized = (email or '').strip().lower()
        clean_answer = (answer or '').strip()
        if not normalized or not clean_answer:
            return {'success': False, 'error': 'Email and answer are required'}

        doc_id = _email_key(normalized)
        set_document('security_answers', doc_id, {
            'email': normalized,
            'answer_hash': _answer_hash(clean_answer),
            'question': SECURITY_QUESTION,
            'updated_at': _now_utc().isoformat(),
        })
        return {'success': True, 'email': normalized}
    except Exception as e:
        print(f"set_security_answer error: {e}")
        return {'success': False, 'error': str(e)}


def submit_security_answer_reset_request(email, requested_by='user', message=''):
    """Creates a pending security-answer reset request for admin review."""
    try:
        normalized = (email or '').strip().lower()
        if not normalized:
            return {'success': False, 'error': 'Email is required'}

        doc_id = _email_key(normalized)
        payload = {
            'email': normalized,
            'status': 'pending',
            'requested_by': (requested_by or 'user').strip() or 'user',
            'message': (message or '').strip(),
            'requested_at': _now_utc().isoformat(),
            'updated_at': _now_utc().isoformat(),
        }
        set_document('security_answer_reset_requests', doc_id, payload)
        return {'success': True, 'email': normalized, 'status': 'pending'}
    except Exception as e:
        print(f"submit_security_answer_reset_request error: {e}")
        return {'success': False, 'error': str(e)}


def get_security_answer_reset_state(email):
    """Returns the current status of a security-answer reset request."""
    try:
        normalized = (email or '').strip().lower()
        if not normalized:
            return {'exists': False, 'status': None, 'is_approved': False}

        doc_id = _email_key(normalized)
        doc = get_document('security_answer_reset_requests', doc_id) or {}
        status = (doc.get('status') or '').strip().lower()
        return {
            'exists': bool(doc),
            'email': normalized,
            'status': status,
            'is_approved': status == 'approved',
            'requested_by': doc.get('requested_by') or 'user',
            'message': doc.get('message') or '',
        }
    except Exception as e:
        print(f"get_security_answer_reset_state error: {e}")
        return {'exists': False, 'status': None, 'is_approved': False}


def get_pending_security_answer_reset_requests():
    """Returns all pending security-answer reset requests for admin review."""
    try:
        docs = get_collection('security_answer_reset_requests') or []
        pending = [
            row for row in docs
            if (row.get('status') or '').strip().lower() == 'pending'
        ]
        return pending
    except Exception as e:
        print(f"get_pending_security_answer_reset_requests error: {e}")
        return []


def approve_security_answer_reset_request(email, approved_by='admin'):
    """Approves a pending security-answer reset request."""
    try:
        normalized = (email or '').strip().lower()
        if not normalized:
            return {'success': False, 'error': 'Email is required'}

        doc_id = _email_key(normalized)
        payload = {
            'email': normalized,
            'status': 'approved',
            'approved_by': (approved_by or 'admin').strip() or 'admin',
            'approved_at': _now_utc().isoformat(),
            'updated_at': _now_utc().isoformat(),
        }
        set_document('security_answer_reset_requests', doc_id, payload)
        return {'success': True, 'email': normalized, 'status': 'approved'}
    except Exception as e:
        print(f"approve_security_answer_reset_request error: {e}")
        return {'success': False, 'error': str(e)}


def verify_security_answer(email, answer):
    """Validates a security-question answer against the stored hash."""
    try:
        normalized = (email or '').strip().lower()
        provided = (answer or '').strip()
        if not normalized or not provided:
            return {'success': False, 'error': 'Email and answer are required'}

        doc_id = _email_key(normalized)
        doc = get_document('security_answers', doc_id) or {}
        stored_hash = doc.get('answer_hash')

        if not stored_hash:
            return {'success': False, 'error': 'No security answer set for this account'}

        if _answer_hash(provided) != stored_hash:
            return {'success': False, 'error': 'Incorrect answer'}

        return {'success': True, 'email': normalized}
    except Exception as e:
        print(f"verify_security_answer error: {e}")
        return {'success': False, 'error': str(e)}

# ─────────────────────────────────────────
# SECURITY ACTIVITY LOG
# ─────────────────────────────────────────

def log_security_event(
    event_type,
    status='info',
    user_id=None,
    email=None,
    role='user',
    device_id=None,
    device_name=None,
    ip_address=None,
    location=None,
    details=None,
    is_suspicious=False,
    suspicious_reason=None,
):
    """Persists user/admin security and account activity for audit viewing."""
    try:
        return add_document('security_activity', {
            'event_type': event_type,
            'status': status,
            'user_id': user_id or '',
            'email': (email or '').strip().lower(),
            'role': role or 'user',
            'device_id': device_id or '',
            'device_name': device_name or '',
            'ip_address': ip_address or 'unknown',
            'location': location or 'unknown',
            'details': details or '',
            'is_suspicious': bool(is_suspicious),
            'suspicious_reason': suspicious_reason or '',
            'timestamp': _now_utc().isoformat(),
        })
    except Exception as e:
        print(f"log_security_event error: {e}")
        return None


def get_security_activity(
    user_id=None,
    email=None,
    role=None,
    event_type=None,
    start_iso=None,
    end_iso=None,
    limit=100,
):
    """Returns security activity logs with optional filters.

    NOTE: when looking up by a specific user_id/email (identity-based
    lookup), the 'role' filter is intentionally NOT applied. Once you're
    already matching an exact user's identity, an additional role
    equality filter adds no protective value — it only risks silently
    zeroing out valid results if role is ever recorded with a slightly
    different value than what the caller passes in. Role filtering is
    only meaningful for the broad "no identity given" browse case (e.g.
    an admin listing all events for a given role).
    """
    try:
        normalized_user_id = (user_id or '').strip()
        normalized_email = (email or '').strip().lower()
        max_limit = max(1, min(int(limit or 100), 500))

        def _query(identity_filter=None, include_role=True):
            filters = []
            if identity_filter is not None:
                filters.append(identity_filter)
            if include_role and role:
                filters.append(('role', 'EQUAL', role))
            if event_type:
                filters.append(('event_type', 'EQUAL', event_type))

            return query_collection(
                'security_activity',
                filters=filters if filters else None,
                order_by='timestamp',
                limit=max_limit,
            )

        logs = []
        if normalized_user_id and normalized_email:
            logs.extend(_query(('user_id', 'EQUAL', normalized_user_id), include_role=False))
            logs.extend(_query(('email', 'EQUAL', normalized_email), include_role=False))
            logs = _dedupe_activity_rows(logs)
        elif normalized_user_id:
            logs = _query(('user_id', 'EQUAL', normalized_user_id), include_role=False)
        elif normalized_email:
            logs = _query(('email', 'EQUAL', normalized_email), include_role=False)
        else:
            logs = _query(include_role=True)

        start_dt = _parse_datetime(start_iso)
        end_dt = _parse_datetime(end_iso)
        output = []
        for item in logs:
            ts = _parse_datetime(item.get('timestamp'))
            if start_dt and ts and ts < start_dt:
                continue
            if end_dt and ts and ts > end_dt:
                continue
            output.append(item)
        output.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
        return output[:max_limit]
    except Exception as e:
        print(f"get_security_activity error: {e}")
        return []


def get_recent_suspicious_activity(user_id=None, email=None, limit=20):
    """Returns suspicious activity entries for alert banners."""
    try:
        items = get_security_activity(
            user_id=user_id,
            email=email,
            limit=max(1, min(int(limit or 20), 200)),
        )
        return [row for row in items if row.get('is_suspicious')]
    except Exception as e:
        print(f"get_recent_suspicious_activity error: {e}")
        return []


def unban_device(device_id, unbanned_by='admin'):
    """Removes active device bans."""
    try:
        docs = query_collection(
            'banned_users',
            filters=[
                ('device_id', 'EQUAL', device_id),
                ('is_active', 'EQUAL', True)
            ]
        )
        for doc in docs:
            update_document('banned_users', doc['id'], {'is_active': False})
        log_admin_action('unban_device', unbanned_by, target=device_id)
    except Exception as e:
        print(f"unban_device error: {e}")
        return None


# ─────────────────────────────────────────
# TRUST SCORE
# ─────────────────────────────────────────

def get_user_trust_score(user_id):
    """Calculates trust score for a user."""
    try:
        report_count = get_confirmed_user_report_count(user_id)

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
                          created_by='admin', expires_at=None,
                          audience='public', target_user_id=None,
                          target_email=None, category='general'):
    """Creates a security alert."""
    try:
        normalized_audience = _normalize_alert_audience(audience)
        normalized_email = (target_email or '').strip().lower()
        normalized_category = _normalize_alert_category(category)
        add_document('security_alerts', {
            'title'         : title,
            'message'       : message,
            'severity'      : severity,
            'created_by'    : created_by,
            'is_active'     : True,
            'created_at'    : datetime.now().isoformat(),
            'expires_at'    : expires_at,
            'audience'      : normalized_audience,
            'target_user_id': target_user_id or '',
            'target_email'  : normalized_email,
            'category'      : normalized_category,
        })
        log_admin_action('create_alert', created_by, target=title)
    except Exception as e:
        print(f"create_security_alert error: {e}")


def get_active_alerts(audience=None, target_user_id=None,
                      target_email=None, category=None):
    """Returns all active security alerts."""
    try:
        alerts = query_collection(
            'security_alerts',
            filters=[('is_active', 'EQUAL', True)],
            order_by='created_at'
        )
        now = _now_utc()
        normalized_audience = (audience or '').strip().lower()
        normalized_category = _normalize_alert_category(category) if category else None
        normalized_target_user_id = (target_user_id or '').strip()
        normalized_target_email = (target_email or '').strip().lower()

        filtered = []
        for alert in alerts:
            expires_at = _parse_datetime(alert.get('expires_at'))
            if expires_at and expires_at <= now:
                continue

            alert_audience = _normalize_alert_audience(alert.get('audience'))
            if normalized_audience == 'public':
                if alert_audience != 'public' or _is_private_system_alert(alert):
                    continue
            elif normalized_audience == 'private':
                if alert_audience != 'private':
                    continue
                if not _matches_private_alert_target(
                    alert,
                    target_user_id=normalized_target_user_id,
                    target_email=normalized_target_email,
                ):
                    continue
            elif normalized_audience and alert_audience != normalized_audience:
                continue

            alert_category = _normalize_alert_category(alert.get('category'))
            if normalized_category and alert_category != normalized_category:
                continue

            filtered.append(alert)

        filtered.sort(key=lambda x: x.get('created_at', ''), reverse=True)
        return filtered
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


def add_safety_tip(category, title, content, created_by='admin', is_active=True):
    """Adds a safety tip."""
    try:
        return add_document('safety_tips', {
            'category'  : category,
            'title'     : title,
            'content'   : content,
            'created_by': created_by,
            'is_active' : bool(is_active),
            'created_at': datetime.now().isoformat()
        })
        log_admin_action('create_tip', created_by, target=title)
    except Exception as e:
        print(f"add_safety_tip error: {e}")
        return None


def get_safety_tips(category=None, include_inactive=False):
    """Returns active safety tips."""
    try:
        filters = []
        if not include_inactive:
            filters.append(('is_active', 'EQUAL', True))
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


# ─────────────────────────────────────────
# USER FEEDBACK
# ─────────────────────────────────────────

def submit_user_feedback(user_id, feedback, rating=None):
    """Submits user feedback for admin review.

    Stores the feedback under a schema matching what the Flutter side
    expects to render: 'feedback' (message text), 'rating', 'status'
    ('pending' | 'read' | 'replied'), and empty admin_reply/replied_at
    placeholders that get filled in by reply_to_feedback().
    """
    try:
        return add_document('user_feedback', {
            'user_id'     : user_id or '',
            'feedback'    : feedback,
            'rating'      : rating,
            'status'      : 'pending',
            'admin_reply' : '',
            'replied_by'  : '',
            'replied_at'  : None,
            'submitted_at': _now_utc().isoformat(),
        })
    except Exception as e:
        print(f"submit_user_feedback error: {e}")
        return None


def get_user_feedback(status=None):
    """Returns all user feedback (admin view), optionally filtered by status."""
    try:
        filters = []
        if status:
            filters.append(('status', 'EQUAL', status))
        rows = query_collection(
            'user_feedback',
            filters=filters if filters else None,
            order_by='submitted_at',
            limit=200,
        )
        rows.sort(key=lambda x: x.get('submitted_at', ''), reverse=True)
        return rows
    except Exception as e:
        print(f"get_user_feedback error: {e}")
        return []


def get_user_feedback_by_user(user_id):
    """Returns feedback submissions for a single user, most recent first."""
    try:
        rows = query_collection(
            'user_feedback',
            filters=[('user_id', 'EQUAL', user_id)],
            limit=200,
        )
        rows.sort(key=lambda x: x.get('submitted_at', ''), reverse=True)
        return rows
    except Exception as e:
        print(f"get_user_feedback_by_user error: {e}")
        return []


def reply_to_feedback(feedback_id, reply, replied_by='admin'):
    """Admin replies to a feedback submission; marks it as 'replied'."""
    try:
        ok = update_document('user_feedback', feedback_id, {
            'admin_reply': reply,
            'status': 'replied',
            'replied_by': replied_by,
            'replied_at': _now_utc().isoformat(),
        })
        if ok:
            log_admin_action(
                'reply_feedback', replied_by,
                target=feedback_id, details=reply[:80]
            )
        return bool(ok)
    except Exception as e:
        print(f"reply_to_feedback error: {e}")
        return False


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


def confirm_user_report_scam(report_id, reviewed_by='admin'):
    """
    Marks a pending reported-user item as confirmed scam.
    Returns the updated report document on success.
    """
    try:
        report = get_document('reported_users', report_id)
        if not report:
            return None
        update_document('reported_users', report_id, {
            'status'      : 'confirmed_scam',
            'reviewed_by' : reviewed_by,
            'reviewed_at' : datetime.now().isoformat(),
            'confirmed_by': reviewed_by,
            'confirmed_at': datetime.now().isoformat(),
        })
        report['status'] = 'confirmed_scam'
        report['reviewed_by'] = reviewed_by
        report['confirmed_by'] = reviewed_by
        log_admin_action(
            'confirm_user_report_scam', reviewed_by,
            target=report_id, details='Marked as confirmed_scam'
        )
        return report
    except Exception as e:
        print(f"confirm_user_report_scam error: {e}")
        return None


def get_confirmed_user_report_count(user_id):
    """
    Counts only user reports that were confirmed/actioned by admin.
    Pending/dismissed reports are excluded from trust deductions.
    """
    try:
        report_docs = query_collection(
            'reported_users',
            filters=[('reported_user', 'EQUAL', user_id)]
        )
        confirmed_statuses = {'confirmed_scam', 'actioned'}
        return len([
            r for r in report_docs
            if (r.get('status') or '').strip().lower() in confirmed_statuses
        ])
    except Exception as e:
        print(f"get_confirmed_user_report_count error: {e}")
        return 0


def enforce_trust_score_ban(user_id, triggered_by='system', source_report_id=None):
    """
    Auto-enforce permanent ban when trust score reaches 0.
    If an active temporary ban exists, it is upgraded to permanent.
    """
    try:
        trust = get_user_trust_score(user_id)
        trust_score = int(trust.get('trust_score', 100))
        if trust_score > 0:
            return {
                'user_id': user_id,
                'trust_score': trust_score,
                'auto_banned': False,
                'ban_type': None,
            }

        active_bans = query_collection(
            'banned_users',
            filters=[
                ('user_id', 'EQUAL', user_id),
                ('is_active', 'EQUAL', True),
            ]
        )

        has_active_permanent = any(
            (b.get('ban_type') or '').strip().lower() == 'permanent'
            for b in active_bans
        )
        if has_active_permanent:
            return {
                'user_id': user_id,
                'trust_score': trust_score,
                'auto_banned': False,
                'ban_type': 'permanent',
            }

        # Deactivate any active non-permanent bans before upgrading.
        for ban in active_bans:
            ban_id = ban.get('id')
            if ban_id:
                update_document('banned_users', ban_id, {'is_active': False})

        ban_user(
            user_id=user_id,
            ban_type='permanent',
            reason='Auto permanent ban because trust score reached 0',
            banned_by=triggered_by,
            source_report_id=source_report_id,
        )
        return {
            'user_id': user_id,
            'trust_score': trust_score,
            'auto_banned': True,
            'ban_type': 'permanent',
        }
    except Exception as e:
        print(f"enforce_trust_score_ban error: {e}")
        return {
            'user_id': user_id,
            'trust_score': 100,
            'auto_banned': False,
            'ban_type': None,
        }
