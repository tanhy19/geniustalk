# app.py
# GeniusTalk Complete Backend Server v2.0

from flask import Flask, request, jsonify
import os
import sys
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from utils.file_inspector import inspect_file
from utils.text_analyzer  import analyze_text
from utils.translator     import prepare_text_for_scanning

# ── IMPORT YOUR NEW OCR SCANNER ──
from utils.ocr_engine     import scan_image

from utils.db_logger      import (
    initialize_database,
    log_text_scan,
    log_file_scan,
    log_image_scan,
    log_qr_scan,
    report_message,
    report_user,
    ban_user,
    unban_user,
    unban_device,
    is_user_banned,
    is_device_banned,
    get_all_flagged,
    get_scan_history,
    get_system_stats,
    get_pending_reports,
    get_banned_users,
    get_qr_scan_history,
    get_user_trust_score,
    get_user_display_name,
    create_security_alert,
    get_active_alerts,
    deactivate_alert,
    create_phishing_drill,
    record_drill_result,
    get_all_drills,
    add_safety_tip,
    get_safety_tips,
    submit_user_feedback,
    get_user_feedback,
    get_admin_actions,
    review_message_report,
    review_user_report,
    get_user_display_name,
    confirm_user_report_scam,
    enforce_trust_score_ban,
    get_login_security_state,
    record_failed_login_attempt,
    reset_failed_login_attempts,
    log_security_event,
    get_security_activity,
    get_recent_suspicious_activity,
    get_locked_accounts,
    admin_unlock_account,
    set_security_answer,
    verify_security_answer,
    submit_security_answer_reset_request,
    get_security_answer_reset_state,
    get_pending_security_answer_reset_requests,
    approve_security_answer_reset_request,
)

from utils.keyword_engine import keyword_scan
from utils.qr_scanner     import scan_qr, analyze_qr_content
from utils.link_verifier  import verify_links
from utils.firebase_config import FirebaseConfig

app = Flask(__name__)
firebase = FirebaseConfig()
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  

# ─────────────────────────────────────────
# CONFIGURATION
# ─────────────────────────────────────────

MAX_FILE_SIZE_MB    = 50
MAX_FILE_SIZE_BYTES = MAX_FILE_SIZE_MB * 1024 * 1024
TEMP_FOLDER         = "temp_uploads"

os.makedirs(TEMP_FOLDER, exist_ok=True)
initialize_database()


# ─────────────────────────────────────────
# HELPER
# ─────────────────────────────────────────

def make_response(success, data=None, error=None, status_code=200):
    return jsonify({
        "success": success,
        "data"   : data,
        "error"  : error
    }), status_code


def _client_ip(req):
    forwarded = req.headers.get('X-Forwarded-For', '')
    if forwarded:
        return forwarded.split(',')[0].strip()
    real_ip = req.headers.get('X-Real-IP', '').strip()
    if real_ip:
        return real_ip
    return (req.remote_addr or 'unknown').strip()


def _approx_location(ip_address):
    if not ip_address or ip_address == 'unknown':
        return 'unknown'
    if ':' in ip_address:
        return 'approx-ipv6'
    parts = ip_address.split('.')
    if len(parts) == 4:
        return f"{parts[0]}.{parts[1]}.x.x"
    return 'approx-ip'


def _is_new_device_login(user_id, email, device_id):
    if not device_id:
        return False
    key = (user_id or email or '').strip().lower()
    if not key:
        return False
    doc_id = f"security_state_{key.replace('@', '_').replace('.', '_')}"
    state = firebase.get_document('user_security_state', doc_id) or {}
    last_device = (state.get('last_device_id') or '').strip()
    is_new = bool(last_device) and last_device != device_id
    firebase.set_document('user_security_state', doc_id, {
        'user_id': user_id or '',
        'email': (email or '').strip().lower(),
        'last_device_id': device_id,
        'updated_at': datetime.now(timezone.utc).isoformat(),
    })
    return is_new


# ─────────────────────────────────────────
# HEALTH CHECK
# ─────────────────────────────────────────

@app.route('/health', methods=['GET'])
def health_check():
    return make_response(True, {
        "status" : "running",
        "version": "2.0.0",
        "modules": [
            "file_inspector", "ocr_engine", "text_analyzer",
            "translator", "keyword_engine", "qr_scanner", "link_verifier"
        ]
    })


# ─────────────────────────────────────────
# YOUR ENDPOINTS
# ─────────────────────────────────────────

@app.route('/scan/text', methods=['POST'])
def scan_text():
    data = request.get_json()
    if not data or "text" not in data:
        return make_response(False, error="Missing 'text' field", status_code=400)
    text = data["text"].strip()
    if not text:
        return make_response(False, error="Text cannot be empty", status_code=400)
    translation  = prepare_text_for_scanning(text)
    text_to_scan = translation["translated_text"]
    result       = analyze_text(text_to_scan, source="direct")
    result["translation"] = {
        "original_text"    : translation["original_text"],
        "detected_language": translation["detected_language"],
        "language_name"    : translation["language_name"],
        "was_translated"   : translation["was_translated"],
        "translation_note" : translation["translation_note"]
    }
    log_text_scan(text, result)
    return make_response(True, result)


@app.route('/scan/file', methods=['POST'])
def scan_file():
    if 'file' not in request.files:
        return make_response(False, error="No file uploaded", status_code=400)
    uploaded_file = request.files['file']
    if uploaded_file.filename == '':
        return make_response(False, error="Empty filename", status_code=400)
    uploaded_file.seek(0, 2)
    file_size = uploaded_file.tell()
    uploaded_file.seek(0)
    if file_size > MAX_FILE_SIZE_BYTES:
        return make_response(False, error=f"File too large. Maximum {MAX_FILE_SIZE_MB}MB", status_code=413)
    temp_path = os.path.join(TEMP_FOLDER, uploaded_file.filename)
    try:
        uploaded_file.save(temp_path)
        result = inspect_file(temp_path)
        log_file_scan(uploaded_file.filename, result)
        return make_response(True, result)
    except Exception as e:
        return make_response(False, error=str(e), status_code=500)
    finally:
        if os.path.exists(temp_path):
            os.remove(temp_path)


@app.route('/scan/image', methods=['POST'])
def scan_image_endpoint():
    if 'image' not in request.files:
        return make_response(False, error="No image uploaded", status_code=400)
    uploaded_image = request.files['image']
    if uploaded_image.filename == '':
        return make_response(False, error="Empty filename", status_code=400)
    temp_path = os.path.join(TEMP_FOLDER, uploaded_image.filename)
    try:
        uploaded_image.save(temp_path)
        
        # ── FIXED: Swapped to your new stand-alone OCR Engine ──
        result = scan_image(temp_path)
        
        log_image_scan(uploaded_image.filename, result)
        return make_response(True, result)
    except Exception as e:
        return make_response(False, error=str(e), status_code=500)
    finally:
        if os.path.exists(temp_path):
            os.remove(temp_path)


@app.route('/scan/full', methods=['POST'])
def full_scan():
    if 'file' not in request.files:
        return make_response(False, error="No file uploaded", status_code=400)
    uploaded_file = request.files['file']
    temp_path     = os.path.join(TEMP_FOLDER, uploaded_file.filename)
    try:
        uploaded_file.save(temp_path)
        file_result      = inspect_file(temp_path)
        image_extensions = {'.jpg', '.jpeg', '.png', '.bmp', '.gif', '.webp', '.tiff'}
        _, ext           = os.path.splitext(uploaded_file.filename)
        ocr_result       = None
        
        if ext.lower() in image_extensions:
            # ── FIXED: Calls new OCR scan engine ──
            ocr_result = scan_image(temp_path)
            
        combined = {
            "file_inspection": file_result,
            "ocr_analysis"   : ocr_result,
            "should_block"   : (
                file_result.get("is_blocked", False) or
                # ── FIXED: Maps properties correctly matching your new nested schema ──
                (ocr_result and ocr_result.get("image_properties", {}).get("is_suspicious", False))
            )
        }
        return make_response(True, combined)
    except Exception as e:
        return make_response(False, error=str(e), status_code=500)
    finally:
        if os.path.exists(temp_path):
            os.remove(temp_path)


# ─────────────────────────────────────────
# YY'S ENDPOINTS
# ─────────────────────────────────────────

@app.route('/scan/keyword', methods=['POST'])
def scan_keyword():
    data = request.get_json()
    if not data or "text" not in data:
        return make_response(False, error="Missing 'text' field", status_code=400)
    text = data["text"].strip()
    if not text:
        return make_response(False, error="Text cannot be empty", status_code=400)
    translation  = prepare_text_for_scanning(text)
    text_to_scan = translation["translated_text"]
    risk_level, score, matches, tones = keyword_scan(text_to_scan)
    result = {
        "risk_level"     : risk_level,
        "score"          : score,
        "matches"        : matches,
        "detected_tones" : tones,
        "is_scam"        : risk_level == "HIGH",
        "translation"    : {
            "detected_language": translation["detected_language"],
            "language_name"    : translation["language_name"],
            "was_translated"   : translation["was_translated"]
        },
        "warning_message": (
            "This message appears highly suspicious. Do NOT click links or share personal information."
            if risk_level == "HIGH" else
            "This message may contain suspicious content. Review carefully."
            if risk_level == "MEDIUM" else
            "No major scam indicators detected."
        )
    }
    log_text_scan(text, {
        "risk_score": score, "risk_label": risk_level,
        "is_scam": risk_level == "HIGH",
        "summary": f"Keyword engine: {len(matches)} matches found",
        "source": "keyword_engine"
    })
    return make_response(True, result)


@app.route('/scan/qr', methods=['POST'])
def scan_qr_endpoint():
    if 'image' not in request.files:
        return make_response(False, error="No image uploaded", status_code=400)
    uploaded_image = request.files['image']
    temp_path      = os.path.join(TEMP_FOLDER, uploaded_image.filename)
    try:
        uploaded_image.save(temp_path)
        result = scan_qr(temp_path)
        log_qr_scan(result)
        return make_response(True, result)
    except Exception as e:
        return make_response(False, error=str(e), status_code=500)
    finally:
        if os.path.exists(temp_path):
            os.remove(temp_path)


@app.route('/scan/qr/content', methods=['POST'])
def scan_qr_content():
    data = request.get_json()
    if not data or "content" not in data:
        return make_response(False, error="Missing 'content' field", status_code=400)
    content = data["content"].strip()
    if not content:
        return make_response(False, error="Content cannot be empty", status_code=400)
    result = analyze_qr_content(content)
    return make_response(True, result)


@app.route('/scan/link', methods=['POST'])
def scan_link():
    data = request.get_json()
    if not data or "text" not in data:
        return make_response(False, error="Missing 'text' field", status_code=400)
    text = data["text"].strip()
    score, urls, flags = verify_links(text)
    if score >= 70:
        risk_label = "HIGH"
    elif score >= 40:
        risk_label = "MEDIUM"
    else:
        risk_label = "LOW"
    return make_response(True, {
        "urls_found"  : urls,
        "risk_score"  : min(score, 100),
        "risk_label"  : risk_label,
        "is_dangerous": risk_label == "HIGH",
        "flags"       : flags
    })


# ─────────────────────────────────────────
# COMBINED SMART SCAN
# ─────────────────────────────────────────

@app.route('/scan/smart', methods=['POST'])
def smart_scan():
    data = request.get_json()
    if not data or "text" not in data:
        return make_response(False, error="Missing 'text' field", status_code=400)
    text         = data["text"].strip()
    translation  = prepare_text_for_scanning(text)
    text_to_scan = translation["translated_text"]
    your_result                       = analyze_text(text_to_scan, source="direct")
    risk_level, score, matches, tones = keyword_scan(text_to_scan)
    your_score     = your_result.get("risk_score", 0)
    friend_score   = score
    combined_score = int(
        (max(your_score, friend_score) * 0.7) +
        (min(your_score, friend_score) * 0.3)
    )
    combined_score = min(combined_score, 100)
    if combined_score >= 70:
        final_label = "HIGH"
        is_scam     = True
    elif combined_score >= 40:
        final_label = "MEDIUM"
        is_scam     = False
    else:
        final_label = "LOW"
        is_scam     = False
    result = {
        "combined_score"  : combined_score,
        "combined_label"  : final_label,
        "is_scam"         : is_scam,
        "translation"     : {
            "original_text"    : translation["original_text"],
            "detected_language": translation["detected_language"],
            "language_name"    : translation["language_name"],
            "was_translated"   : translation["was_translated"],
            "translation_note" : translation["translation_note"]
        },
        "your_analysis"   : your_result,
        "keyword_analysis": {
            "risk_level"    : risk_level,
            "score"         : score,
            "matches"       : matches,
            "detected_tones": tones
        }
    }
    log_text_scan(text, {
        "risk_score": combined_score, "risk_label": final_label,
        "is_scam": is_scam,
        "summary": f"Smart scan: your={your_score}, keyword={friend_score}",
        "source": "smart_scan"
    })
    return make_response(True, result)


# ─────────────────────────────────────────
# COMMUNITY DEFENSE ENDPOINTS
# ─────────────────────────────────────────

@app.route('/report/message', methods=['POST'])
def report_message_endpoint():
    data = request.get_json()
    if not data:
        return make_response(False, error="Missing data", status_code=400)
    report_message(
        reported_by     = data.get("reported_by", "anonymous"),
        message_content = data.get("message_content", ""),
        reason          = data.get("reason", ""),
        message_sender  = data.get("reported_user") or data.get("message_sender"),
        risk_score      = data.get("risk_score", 0),
        media_url       = data.get("media_url"),
        media_type      = data.get("media_type"),
        file_name       = data.get("file_name"),
    )
    return make_response(True, {"message": "Report submitted successfully"})


@app.route('/report/user', methods=['POST'])
def report_user_endpoint():
    data = request.get_json()
    if not data:
        return make_response(False, error="Missing data", status_code=400)
    report_user(
        reported_by   = data.get("reported_by", "anonymous"),
        reported_user = data.get("reported_user", ""),
        reason        = data.get("reason", ""),
        evidence      = data.get("evidence", None)
    )
    return make_response(True, {"message": "User reported successfully"})


# ─────────────────────────────────────────
# GOVERNANCE ENDPOINTS
# ─────────────────────────────────────────

@app.route('/admin/ban', methods=['POST'])
def ban_user_endpoint():
    data = request.get_json()
    if not data:
        return make_response(False, error="Missing data", status_code=400)

    source_report_id = data.get("source_report_id", None)
    if source_report_id:
      report = firebase.get_document("reported_users", source_report_id)
      if not report:
          return make_response(False, error="source_report_id not found", status_code=404)
      status = (report.get('status') or '').strip().lower()
      if status != 'confirmed_scam':
          return make_response(
              False,
              error="User report must be confirmed as scam before ban",
              status_code=400
          )

    ban_user(
        user_id           = data.get("user_id", ""),
        ban_type          = data.get("ban_type", "temporary"),
        reason            = data.get("reason", ""),
        device_id         = data.get("device_id", None),
        banned_by         = data.get("banned_by", "admin"),
        expires_at        = data.get("expires_at", None),
        source_report_id  = source_report_id
    )
    return make_response(True, {"message": "User banned successfully"})


@app.route('/admin/unban', methods=['POST'])
def unban_user_endpoint():
    data = request.get_json()
    if not data or "user_id" not in data:
        return make_response(False, error="Missing user_id", status_code=400)
    unban_user(data["user_id"], unbanned_by=data.get("unbanned_by", "admin"))
    return make_response(True, {"message": "User unbanned successfully"})


@app.route('/admin/check-ban/<user_id>', methods=['GET'])
def check_ban_endpoint(user_id):
    result = is_user_banned(user_id)
    return make_response(True, {
        "is_banned"  : result is not None,
        "ban_details": result
    })


@app.route('/admin/check-device-ban/<device_id>', methods=['GET'])
def check_device_ban_endpoint(device_id):
    result = is_device_banned(device_id)
    return make_response(True, {
        "is_banned"  : result is not None,
        "ban_details": result
    })


@app.route('/admin/ban-device', methods=['POST'])
def ban_device_endpoint():
    data = request.get_json()
    if not data or "device_id" not in data:
        return make_response(False, error="Missing device_id", status_code=400)
    ban_user(
        user_id           = data.get("user_id", ""),
        ban_type          = data.get("ban_type", "temporary"),
        reason            = data.get("reason", ""),
        device_id         = data.get("device_id"),
        banned_by         = data.get("banned_by", "admin"),
        expires_at        = data.get("expires_at", None),
        source_report_id  = data.get("source_report_id", None)
    )
    return make_response(True, {"message": "Device banned successfully"})


@app.route('/admin/unban-device', methods=['POST'])
def unban_device_endpoint():
    data = request.get_json()
    if not data or "device_id" not in data:
        return make_response(False, error="Missing device_id", status_code=400)
    unban_device(data["device_id"], unbanned_by=data.get("unbanned_by", "admin"))
    return make_response(True, {"message": "Device unbanned successfully"})


@app.route('/auth/access-check', methods=['POST'])
def auth_access_check_endpoint():
    data = request.get_json() or {}
    user_id = (data.get("user_id") or "").strip()
    device_id = (data.get("device_id") or "").strip()
    if not user_id and not device_id:
        return make_response(False, error="Missing user_id or device_id", status_code=400)

    user_ban = is_user_banned(user_id) if user_id else None
    device_ban = is_device_banned(device_id) if device_id else None
    is_blocked = user_ban is not None or device_ban is not None

    return make_response(True, {
        "is_blocked"      : is_blocked,
        "is_user_banned"  : user_ban is not None,
        "is_device_banned": device_ban is not None,
        "user_ban_details": user_ban,
        "device_ban_details": device_ban
    })


@app.route('/auth/login-status', methods=['POST'])
def auth_login_status_endpoint():
    data = request.get_json() or {}
    email = (data.get('email') or '').strip().lower()
    if not email:
        return make_response(False, error='Missing email', status_code=400)

    state = get_login_security_state(email)
    return make_response(True, {
        'email': state.get('email'),
        'is_locked': state.get('is_locked', False),
        'is_permanently_locked': state.get('is_permanently_locked', False),
        'requires_admin_unlock': state.get('requires_admin_unlock', False),
        'failed_attempts': state.get('failed_attempts', 0),
        'attempts_left': state.get('attempts_left', 3),
        'lock_until': state.get('lock_until'),
        'minutes_until_unlock': state.get('minutes_until_unlock', 0),
    })



@app.route('/auth/login-attempt', methods=['POST'])
def auth_login_attempt_endpoint():
    data = request.get_json() or {}
    email = (data.get('email') or '').strip().lower()
    if not email:
        return make_response(False, error='Missing email', status_code=400)

    user_id = (data.get('user_id') or '').strip()
    role = (data.get('role') or 'user').strip().lower()
    device_id = (data.get('device_id') or '').strip()
    device_name = (data.get('device_name') or '').strip()
    success = bool(data.get('success', False))
    reason = (data.get('reason') or '').strip()

    ip_address = _client_ip(request)
    location = _approx_location(ip_address)

    if success:
        reset_failed_login_attempts(email)
        is_new_device = _is_new_device_login(user_id, email, device_id)
        suspicious_reason = 'new_device_login' if is_new_device else ''

        log_security_event(
            event_type='user_logged_in',
            status='success',
            user_id=user_id,
            email=email,
            role=role,
            device_id=device_id,
            device_name=device_name,
            ip_address=ip_address,
            location=location,
            details='Successful login',
            is_suspicious=is_new_device,
            suspicious_reason=suspicious_reason,
        )

        # NOTE: New-device logins are recorded above via log_security_event
        # only. They are intentionally NOT written to security_alerts,
        # since that collection feeds the admin's public Live Alerts CRUD
        # screen. This event is private to the user and shows up in their
        # own Profile > Security Activity Log instead.

        return make_response(True, {
            'is_locked': False,
            'failed_attempts': 0,
            'attempts_left': 5,
            'suspicious': is_new_device,
            'suspicious_reason': suspicious_reason,
        })

    state = record_failed_login_attempt(email)
    is_locked = state.get('is_locked', False)
    failed_attempts = int(state.get('failed_attempts', 0) or 0)

    is_suspicious = failed_attempts >= 5
    suspicious_reason = 'five_failed_logins' if is_suspicious else ''

    log_security_event(
        event_type='failed_login_attempt',
        status='failed',
        user_id=user_id,
        email=email,
        role=role,
        device_id=device_id,
        device_name=device_name,
        ip_address=ip_address,
        location=location,
        details=reason or 'Incorrect password',
        is_suspicious=is_suspicious,
        suspicious_reason=suspicious_reason,
    )

    if is_locked:
        # NOTE: Account-lockout events are recorded below via
        # log_security_event only, and intentionally NOT written to
        # security_alerts. This keeps them private to the affected user
        # (visible in their own Profile > Security Activity Log) instead
        # of leaking into the admin's public Live Alerts CRUD screen.
        log_security_event(
            event_type='account_locked',
            status='info',
            user_id=user_id,
            email=email,
            role=role,
            device_id=device_id,
            device_name=device_name,
            ip_address=ip_address,
            location=location,
            details='Account locked due to multiple failed login attempts',
            is_suspicious=True,
            suspicious_reason='five_failed_logins',
        )

    return make_response(True, {
        'is_locked': is_locked,
        'failed_attempts': failed_attempts,
        'attempts_left': state.get('attempts_left', 0),
        'lock_until': state.get('lock_until'),
        'minutes_until_unlock': state.get('minutes_until_unlock', 0),
        'message': (
            'Your account has been temporarily locked due to multiple failed login attempts.'
            if is_locked else
            'Incorrect credentials.'
        ),
    })

@app.route('/auth/security-question/set', methods=['POST'])
def auth_security_question_set_endpoint():
    """Called once at registration to store the user's security answer."""
    data = request.get_json() or {}
    email = (data.get('email') or '').strip().lower()
    answer = (data.get('answer') or '').strip()
    if not email or not answer:
        return make_response(False, error='Missing email or answer', status_code=400)

    result = set_security_answer(email, answer)
    if not result.get('success'):
        return make_response(False, error=result.get('error', 'Failed to save security answer'), status_code=500)

    return make_response(True, {'email': email, 'message': 'Security answer saved.'})


@app.route('/auth/security-question/verify', methods=['POST'])
def auth_security_question_verify_endpoint():
    """Called after correct email+password, as the MFA step."""
    data = request.get_json() or {}
    email = (data.get('email') or '').strip().lower()
    answer = (data.get('answer') or '').strip()
    if not email or not answer:
        return make_response(False, error='Missing email or answer', status_code=400)

    result = verify_security_answer(email, answer)
    if not result.get('success'):
        return make_response(False, error=result.get('error', 'Incorrect answer'), status_code=400)

    ip_address = _client_ip(request)
    log_security_event(
        event_type='mfa_security_question_verified',
        status='success',
        email=email,
        role='user',
        ip_address=ip_address,
        location=_approx_location(ip_address),
        details='Login MFA security question verified',
    )

    return make_response(True, {'email': email, 'message': 'Verification successful.'})


@app.route('/auth/security-question/reset-request', methods=['POST'])
def auth_security_question_reset_request_endpoint():
    """Submits a forgot-security-answer request for admin approval."""
    data = request.get_json() or {}
    email = (data.get('email') or '').strip().lower()
    message = (data.get('message') or '').strip()
    if not email:
        return make_response(False, error='Email is required', status_code=400)

    result = submit_security_answer_reset_request(email, requested_by='user', message=message)
    if not result.get('success'):
        return make_response(False, error=result.get('error', 'Failed to submit request'), status_code=500)

    return make_response(True, {
        'email': email,
        'status': result.get('status', 'pending'),
        'message': 'The reset security answer request has been submitted to administrator. Once approved by administrator, you will be able to create a new security answer.',
    })


@app.route('/auth/security-question/reset-status', methods=['GET'])
def auth_security_question_reset_status_endpoint():
    """Returns whether a reset request for the given user has been approved."""
    email = (request.args.get('email') or '').strip().lower()
    if not email:
        return make_response(False, error='Email is required', status_code=400)

    result = get_security_answer_reset_state(email)
    return make_response(True, result)


@app.route('/admin/security-answer-reset/requests', methods=['GET'])
def admin_security_answer_reset_requests_endpoint():
    """Lists pending security-answer reset requests for admins."""
    return make_response(True, get_pending_security_answer_reset_requests())


@app.route('/admin/security-answer-reset/approve', methods=['POST'])
def admin_security_answer_reset_approve_endpoint():
    """Approves a pending security-answer reset request."""
    data = request.get_json() or {}
    email = (data.get('email') or '').strip().lower()
    approved_by = (data.get('approved_by') or 'admin').strip() or 'admin'
    if not email:
        return make_response(False, error='Email is required', status_code=400)

    result = approve_security_answer_reset_request(email, approved_by=approved_by)
    if not result.get('success'):
        return make_response(False, error=result.get('error', 'Failed to approve request'), status_code=500)

    return make_response(True, {
        'email': email,
        'status': result.get('status', 'approved'),
        'message': 'Security answer reset request approved.',
    })

@app.route('/security/event', methods=['POST'])
def security_event_endpoint():
    data = request.get_json() or {}
    event_type = (data.get('event_type') or '').strip()
    if not event_type:
        return make_response(False, error='Missing event_type', status_code=400)

    ip_address = _client_ip(request)
    location = _approx_location(ip_address)
    event_id = log_security_event(
        event_type=event_type,
        status=(data.get('status') or 'info').strip(),
        user_id=(data.get('user_id') or '').strip(),
        email=(data.get('email') or '').strip().lower(),
        role=(data.get('role') or 'user').strip().lower(),
        device_id=(data.get('device_id') or '').strip(),
        device_name=(data.get('device_name') or '').strip(),
        ip_address=ip_address,
        location=location,
        details=(data.get('details') or '').strip(),
        is_suspicious=bool(data.get('is_suspicious', False)),
        suspicious_reason=(data.get('suspicious_reason') or '').strip(),
    )
    return make_response(True, {'id': str(event_id) if event_id else ''})


@app.route('/security/activity', methods=['GET'])
def security_activity_endpoint():
    user_id = (request.args.get('user_id') or '').strip()
    email = (request.args.get('email') or '').strip().lower()
    role = (request.args.get('role') or '').strip().lower() or None
    event_type = (request.args.get('event_type') or '').strip() or None
    start = (request.args.get('start') or '').strip() or None
    end = (request.args.get('end') or '').strip() or None
    limit = request.args.get('limit', default=100, type=int)

    # Prevent broad admin audit queries from returning everyone.
    if role == 'admin' and not user_id and not email:
        return make_response(
            False,
            error='Admin security activity requires email or user_id filter',
            status_code=400,
        )

    items = get_security_activity(
        user_id=user_id or None,
        email=email or None,
        role=role,
        event_type=event_type,
        start_iso=start,
        end_iso=end,
        limit=limit,
    )
    return make_response(True, items)


@app.route('/security/suspicious', methods=['GET'])
def security_suspicious_endpoint():
    user_id = (request.args.get('user_id') or '').strip() or None
    email = (request.args.get('email') or '').strip().lower() or None
    limit = request.args.get('limit', default=20, type=int)
    items = get_recent_suspicious_activity(user_id=user_id, email=email, limit=limit)
    return make_response(True, items)


# ─────────────────────────────────────────
# ADMIN ENDPOINTS
# ─────────────────────────────────────────

@app.route('/admin/flagged', methods=['GET'])
def admin_flagged():
    items = get_all_flagged()
    return make_response(True, items)


@app.route('/admin/history', methods=['GET'])
def admin_history():
    return make_response(True, get_admin_actions())


@app.route('/admin/stats', methods=['GET'])
def admin_stats():
    base = get_system_stats() or {}
    try:
        pending = get_pending_reports()
        report_count = len(pending.get('reported_messages', [])) + len(pending.get('reported_users', []))
        active_bans  = get_banned_users()
        flagged      = get_all_flagged()
        base.update({
            "status"       : "running",
            "version"      : "2.0.0",
            "uptime"       : "Live on Render",
            "total_reports": base.get("total_reported", report_count),
            "active_bans"  : len(active_bans),
            "flagged_count": len(flagged),
        })
    except Exception as e:
        print(f"admin_stats enrich error: {e}")
        base["status"]  = "running"
        base["version"] = "2.0.0"
    return make_response(True, base)


@app.route('/admin/banned', methods=['GET'])
def get_banned_list():
    from utils.db_logger import get_banned_users_with_names
    return make_response(True, get_banned_users_with_names())

@app.route('/admin/reports', methods=['GET'])
def get_reports():
    return make_response(True, get_pending_reports())


@app.route('/admin/report/message/review', methods=['POST'])
def review_message_report_endpoint():
    data = request.get_json()
    if not data or "report_id" not in data or "decision" not in data:
        return make_response(False, error="Missing report_id or decision", status_code=400)
    decision = data["decision"]
    if decision not in ['confirmed_scam', 'not_scam']:
        return make_response(False, error="decision must be 'confirmed_scam' or 'not_scam'", status_code=400)
    review_message_report(data["report_id"], decision, data.get("reviewed_by", "admin"))
    return make_response(True, {"message": f"Message marked as {decision}"})


@app.route('/admin/report/user/review', methods=['POST'])
def review_user_report_endpoint():
    data = request.get_json()
    if not data or "report_id" not in data or "decision" not in data:
        return make_response(False, error="Missing report_id or decision", status_code=400)
    decision = data["decision"]
    if decision not in ['dismissed', 'actioned', 'confirmed_scam']:
        return make_response(False, error="decision must be 'dismissed', 'confirmed_scam' or 'actioned'", status_code=400)
    report_id = data["report_id"]
    reviewed_by = data.get("reviewed_by", "admin")
    review_user_report(report_id, decision, reviewed_by)

    # Auto permanent ban when trust score hits 0 after confirmed/actioned report.
    auto = None
    if decision in ['confirmed_scam', 'actioned']:
        report = firebase.get_document('reported_users', report_id)
        reported_user = (report or {}).get('reported_user', '')
        if reported_user:
            auto = enforce_trust_score_ban(
                reported_user,
                triggered_by=reviewed_by,
                source_report_id=report_id,
            )

    return make_response(True, {
        "message": f"User report marked as {decision}",
        "auto_ban": auto,
    })


@app.route('/admin/report/user/confirm', methods=['POST'])
def confirm_user_report_endpoint():
    data = request.get_json() or {}
    report_id = (data.get('report_id') or '').strip()
    reviewed_by = data.get('reviewed_by', 'admin')
    if not report_id:
        return make_response(False, error='Missing report_id', status_code=400)

    report = confirm_user_report_scam(report_id, reviewed_by)
    if not report:
        return make_response(False, error='Report not found or update failed', status_code=404)

    reported_user = (report.get('reported_user') or '').strip()
    if not reported_user:
        return make_response(True, {
            'message': 'Report confirmed as scam',
            'report_id': report_id,
            'auto_banned': False,
        })

    trust = get_user_trust_score(reported_user)
    trust_score = int(trust.get('trust_score', 100))
    auto = enforce_trust_score_ban(
        reported_user,
        triggered_by=reviewed_by,
        source_report_id=report_id,
    )
    auto_banned = auto.get('auto_banned') == True

    if auto_banned:
        review_user_report(report_id, 'actioned', reviewed_by)

    return make_response(True, {
        'message': 'Report confirmed as scam',
        'report_id': report_id,
        'reported_user': reported_user,
        'trust_score': trust_score,
        'auto_banned': auto_banned,
        'auto_ban': auto,
    })


@app.route('/admin/qr-history', methods=['GET'])
def get_qr_history():
    return make_response(True, get_qr_scan_history())


@app.route('/admin/confirm-scam', methods=['POST'])
def confirm_scam_endpoint():
    data = request.get_json()
    if not data:
        return make_response(False, error="Missing data", status_code=400)
    report_id = data.get('report_id', '')
    message_text = data.get('message_text', '')
    category = data.get('category', 'Other')
    risk_level = data.get('risk_level', 'medium')
    notes = data.get('notes', '')
    confirmed_by = data.get('confirmed_by', 'admin')
    if not message_text:
        return make_response(False, error="message_text required", status_code=400)
    from utils.db_logger import log_admin_action
    try:
        doc_id = firebase.add_document('confirmed_scams', {
            'message_text' : message_text,
            'category'     : category,
            'risk_level'   : risk_level,
            'notes'        : notes,
            'confirmed_by' : confirmed_by,
            'source_report_id': report_id,
            'confirmed_at' : datetime.now(timezone.utc).isoformat(),
        })
        if report_id:
            firebase.update_document('reported_messages', report_id, {
                'status'     : 'confirmed_scam',
                'reviewed_by': confirmed_by,
                'reviewed_at': datetime.now(timezone.utc).isoformat(),
            })
        log_admin_action(
            'confirm_scam', confirmed_by, target=category, details=f"Risk: {risk_level} — {message_text[:80]}"
        )
        return make_response(True, {'doc_id': doc_id, 'message': 'Scam confirmed and catalogued'})
    except Exception as e:
        return make_response(False, error=str(e), status_code=500)

@app.route('/admin/confirmed-scams', methods=['GET'])
def get_confirmed_scams():
    try:
        items = firebase.query_collection('confirmed_scams', order_by='confirmed_at', limit=100)
        return make_response(True, items)
    except Exception as e:
        return make_response(False, error=str(e), status_code=500)

@app.route('/user/trust/<user_id>', methods=['GET'])
def get_trust_score(user_id):
    result = get_user_trust_score(user_id)
    auto = enforce_trust_score_ban(user_id, triggered_by='system')
    result['auto_ban'] = auto
    return make_response(True, result)


@app.route('/admin/report/update', methods=['POST'])
def update_report_status_endpoint():
    data = request.get_json()
    if not data:
        return make_response(False, error="Missing data", status_code=400)
    report_id = data.get("report_id", "")
    report_type = data.get("report_type", "")
    status = data.get("status", "reviewed")
    reviewed_by = data.get("reviewed_by", "admin")
    if not report_id:
        return make_response(False, error="report_id required", status_code=400)
    collection = "reported_users" if report_type == "user" else "reported_messages"
    try:
        result = firebase.update_document(collection, report_id, {
            "status"     : status,
            "reviewed_by": reviewed_by,
            "reviewed_at": datetime.now().isoformat()
        })
        if result:
            return make_response(True, {"updated": report_id, "status": status})
        return make_response(False, error="Update failed")
    except Exception as e:
        return make_response(False, error=str(e), status_code=500)

@app.route('/admin/locked-accounts', methods=['GET'])
def admin_locked_accounts_endpoint():
    return make_response(True, get_locked_accounts())


@app.route('/admin/unlock-account', methods=['POST'])
def admin_unlock_account_endpoint():
    data = request.get_json() or {}
    email = (data.get('email') or '').strip().lower()
    unlocked_by = data.get('unlocked_by', 'admin')
    if not email:
        return make_response(False, error='Missing email', status_code=400)

    result = admin_unlock_account(email, unlocked_by=unlocked_by)
    if not result.get('success'):
        return make_response(False, error=result.get('error', 'Failed to unlock account'), status_code=500)

    ip_address = _client_ip(request)
    log_security_event(
        event_type='account_unlocked_by_admin',
        status='success',
        email=email,
        role='user',
        ip_address=ip_address,
        location=_approx_location(ip_address),
        details=f'Account unlocked by {unlocked_by}',
    )

    return make_response(True, {'email': email, 'message': 'Account unlocked successfully.'})

# ─────────────────────────────────────────
# AWARENESS & EDUCATION ENDPOINTS
# ─────────────────────────────────────────

@app.route('/awareness/alert', methods=['POST'])
def create_alert():
    data = request.get_json()
    if not data:
        return make_response(False, error="Missing data", status_code=400)
    title = data.get("title", "")
    message = data.get("message") or data.get("body", "")
    if not title or not message:
        return make_response(False, error="Missing 'title' or 'message'", status_code=400)
    result = create_security_alert(
        title = title, message = message,
        severity = data.get("severity", "medium"),
        created_by = data.get("created_by", "admin"),
        expires_at = data.get("expires_at", None),
        audience = data.get("audience", "public"),
        target_user_id = data.get("target_user_id", ""),
        target_email = data.get("target_email", ""),
        category = data.get("category", "general"),
    )
    return make_response(True, {"message": "Security alert created", "id": str(result) if result else ""})

@app.route('/awareness/alerts', methods=['GET'])
def get_alerts():
    # Default to 'public' so admin-facing calls that omit the audience
    # param (e.g. the Live Alerts CRUD screen) never see private,
    # system-generated per-user security events.
    audience = (request.args.get('audience') or 'public').strip().lower()
    user_id = (request.args.get('user_id') or '').strip() or None
    email = (request.args.get('email') or '').strip().lower() or None
    category = (request.args.get('category') or '').strip().lower() or None
    alerts = get_active_alerts(
        audience=audience,
        target_user_id=user_id,
        target_email=email,
        category=category,
    )
    return make_response(True, alerts)

@app.route('/awareness/alert/<string:alert_id>/deactivate', methods=['POST'])
def deactivate_alert_endpoint(alert_id):
    deactivate_alert(alert_id)
    return make_response(True, {"message": "Alert deactivated"})

@app.route('/awareness/alert/<string:alert_id>', methods=['PUT'])
def update_alert_endpoint(alert_id):
    data = request.get_json() or {}
    fields = {}
    if "title" in data: fields["title"] = data["title"]
    if "message" in data: fields["message"] = data["message"]
    if "body" in data: fields["message"] = data["body"]
    if "severity" in data: fields["severity"] = data["severity"]
    if "active" in data: fields["is_active"] = data["active"]
    if "is_active" in data: fields["is_active"] = data["is_active"]
    if not fields:
        return make_response(False, error="No fields to update", status_code=400)
    try:
        ok = firebase.update_document("security_alerts", alert_id, fields)
        if ok: return make_response(True, {"updated": alert_id})
        return make_response(False, error="Update failed")
    except Exception as e:
        return make_response(False, error=str(e), status_code=500)

@app.route('/awareness/alert/<string:alert_id>', methods=['DELETE'])
def delete_alert_endpoint(alert_id):
    try:
        ok = firebase.delete_document("security_alerts", alert_id)
        if ok: return make_response(True, {"deleted": alert_id})
        return make_response(False, error="Delete failed")
    except Exception as e:
        return make_response(False, error=str(e), status_code=500)

@app.route('/awareness/drill', methods=['POST'])
def create_drill():
    data = request.get_json()
    if not data:
        return make_response(False, error="Missing data", status_code=400)
    if "title" not in data or "drill_message" not in data:
        return make_response(False, error="Missing 'title' or 'drill_message'", status_code=400)
    create_phishing_drill(
        title = data["title"], drill_message = data["drill_message"],
        target_user = data.get("target_user", "all"), created_by = data.get("created_by", "admin")
    )
    return make_response(True, {"message": "Phishing drill created"})

@app.route('/awareness/drill/<string:drill_id>/result', methods=['POST'])
def submit_drill_result(drill_id):
    data = request.get_json()
    if not data or "passed" not in data:
        return make_response(False, error="Missing 'passed' field", status_code=400)
    record_drill_result(drill_id, data["passed"])
    message = "Well done! You correctly identified the phishing attempt." if data["passed"] else "You fell for the drill. Please review our safety tips."
    return make_response(True, {"message": message, "passed": data["passed"]})

@app.route('/awareness/drill/<string:drill_id>', methods=['PUT'])
def update_drill_endpoint(drill_id):
    data = request.get_json() or {}
    fields = {}
    if "title" in data: fields["title"] = data["title"]
    if "drill_message" in data: fields["drill_message"] = data["drill_message"]
    if "active" in data: fields["active"] = data["active"]
    if not fields:
        return make_response(False, error="No fields to update", status_code=400)
    try:
        ok = firebase.update_document("phishing_drills", drill_id, fields)
        if ok: return make_response(True, {"updated": drill_id})
        return make_response(False, error="Update failed")
    except Exception as e:
        return make_response(False, error=str(e), status_code=500)

@app.route('/awareness/drill/<string:drill_id>', methods=['DELETE'])
def delete_drill_endpoint(drill_id):
    try:
        ok = firebase.delete_document("phishing_drills", drill_id)
        if ok: return make_response(True, {"deleted": drill_id})
        return make_response(False, error="Delete failed")
    except Exception as e:
        return make_response(False, error=str(e), status_code=500)

@app.route('/awareness/drills', methods=['GET'])
def get_drills():
    return make_response(True, get_all_drills())

@app.route('/awareness/tip', methods=['POST'])
def add_tip():
    data = request.get_json()
    if not data:
        return make_response(False, error="Missing data", status_code=400)
    title = data.get("title", "")
    content = data.get("content") or data.get("body", "")
    category = data.get("category", "general")
    is_active = data.get("active", data.get("is_active", True))
    if not title or not content:
        return make_response(False, error="Missing 'title' or 'content'", status_code=400)
    tip_id = add_safety_tip(
        category=category,
        title=title,
        content=content,
        created_by=data.get("created_by", "admin"),
        is_active=is_active,
    )
    return make_response(True, {
        "message": "Safety tip added",
        "id": tip_id or "",
        "title": title,
        "content": content,
        "category": category,
        "active": bool(is_active),
    })

@app.route('/awareness/tips', methods=['GET'])
def get_tips():
    category = request.args.get("category", None)
    include_inactive = request.args.get("include_inactive", "false").lower() == "true"
    return make_response(True, get_safety_tips(category, include_inactive=include_inactive))


@app.route('/awareness/tip/<string:tip_id>', methods=['PUT'])
def update_tip_endpoint(tip_id):
    data = request.get_json() or {}
    fields = {}
    if "title" in data:
        fields["title"] = data["title"]
    if "content" in data:
        fields["content"] = data["content"]
    if "body" in data:
        fields["content"] = data["body"]
    if "category" in data:
        fields["category"] = data["category"]
    if "active" in data:
        fields["is_active"] = bool(data["active"])
    if "is_active" in data:
        fields["is_active"] = bool(data["is_active"])

    if not fields:
        return make_response(False, error="No fields to update", status_code=400)

    try:
        ok = firebase.update_document("safety_tips", tip_id, fields)
        if ok:
            return make_response(True, {"updated": tip_id})
        return make_response(False, error="Update failed")
    except Exception as e:
        return make_response(False, error=str(e), status_code=500)


@app.route('/awareness/tip/<string:tip_id>', methods=['DELETE'])
def delete_tip_endpoint(tip_id):
    try:
        ok = firebase.delete_document("safety_tips", tip_id)
        if ok:
            return make_response(True, {"deleted": tip_id})
        return make_response(False, error="Delete failed")
    except Exception as e:
        return make_response(False, error=str(e), status_code=500)


if __name__ == '__main__':
    # Binds to 0.0.0.0 and dynamically grabs Port for clean local testing
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port)
