# app.py
# GeniusTalk Complete Backend Server v2.0

from flask import Flask, request, jsonify
import os
import sys
from datetime import datetime, timezone
import pytesseract
pytesseract.pytesseract.tesseract_cmd = r'C:\Program Files\Tesseract-OCR\tesseract.exe'

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


from utils.file_inspector import inspect_file
from utils.text_analyzer  import analyze_text, analyze_image_text
from utils.translator     import prepare_text_for_scanning
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
    is_user_banned,
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
    get_user_display_name 
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
def scan_image():
    if 'image' not in request.files:
        return make_response(False, error="No image uploaded", status_code=400)
    uploaded_image = request.files['image']
    if uploaded_image.filename == '':
        return make_response(False, error="Empty filename", status_code=400)
    temp_path = os.path.join(TEMP_FOLDER, uploaded_image.filename)
    try:
        uploaded_image.save(temp_path)
        result = analyze_image_text(temp_path)
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
        image_extensions = {'.jpg', '.jpeg', '.png', '.bmp', '.gif', '.webp'}
        _, ext           = os.path.splitext(uploaded_file.filename)
        ocr_result       = None
        if ext.lower() in image_extensions:
            ocr_result = analyze_image_text(temp_path)
        combined = {
            "file_inspection": file_result,
            "ocr_analysis"   : ocr_result,
            "should_block"   : (
                file_result.get("is_blocked", False) or
                (ocr_result and ocr_result.get("analysis", {}).get("is_scam", False))
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
    ban_user(
        user_id           = data.get("user_id", ""),
        ban_type          = data.get("ban_type", "temporary"),
        reason            = data.get("reason", ""),
        device_id         = data.get("device_id", None),
        banned_by         = data.get("banned_by", "admin"),
        expires_at        = data.get("expires_at", None),
        source_report_id  = data.get("source_report_id", None)
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


# ─────────────────────────────────────────
# ADMIN ENDPOINTS
# ─────────────────────────────────────────

@app.route('/admin/flagged', methods=['GET'])
def admin_flagged():
    """Returns flagged content with message text for admin review."""
    items = get_all_flagged()
    return make_response(True, items)


@app.route('/admin/history', methods=['GET'])
def admin_history():
    """Returns admin activity log (bans, alerts, reviews) — NOT user messages."""
    return make_response(True, get_admin_actions())


@app.route('/admin/stats', methods=['GET'])
def admin_stats():
    """Returns enriched system health stats."""
    base = get_system_stats() or {}
    try:
        pending      = get_pending_reports()
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
    """Admin marks a reported message as scam or not scam. No ban."""
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
    """Admin marks a reported user report as dismissed or actioned."""
    data = request.get_json()
    if not data or "report_id" not in data or "decision" not in data:
        return make_response(False, error="Missing report_id or decision", status_code=400)
    decision = data["decision"]
    if decision not in ['dismissed', 'actioned']:
        return make_response(False, error="decision must be 'dismissed' or 'actioned'", status_code=400)
    review_user_report(data["report_id"], decision, data.get("reviewed_by", "admin"))
    return make_response(True, {"message": f"User report marked as {decision}"})


@app.route('/admin/qr-history', methods=['GET'])
def get_qr_history():
    return make_response(True, get_qr_scan_history())

# ── Confirmed scams collection ────────────────────────────────
@app.route('/admin/confirm-scam', methods=['POST'])
def confirm_scam_endpoint():
    """Admin confirms a reported message as scam and categorises it."""
    data = request.get_json()
    if not data:
        return make_response(False, error="Missing data", status_code=400)

    report_id    = data.get('report_id', '')
    message_text = data.get('message_text', '')
    category     = data.get('category', 'Other')
    risk_level   = data.get('risk_level', 'medium')
    notes        = data.get('notes', '')
    confirmed_by = data.get('confirmed_by', 'admin')

    if not message_text:
        return make_response(False, error="message_text required", status_code=400)

    from utils.db_logger import log_admin_action
    try:
        # Write to confirmed_scams collection
        doc_id = firebase.add_document('confirmed_scams', {
            'message_text'  : message_text,
            'category'      : category,
            'risk_level'    : risk_level,
            'notes'         : notes,
            'confirmed_by'  : confirmed_by,
            'source_report_id': report_id,
            'confirmed_at'  : datetime.now(timezone.utc).isoformat(),
        })

        # Update the original report status to confirmed_scam
        if report_id:
            firebase.update_document('reported_messages', report_id, {
                'status'     : 'confirmed_scam',
                'reviewed_by': confirmed_by,
                'reviewed_at': datetime.now(timezone.utc).isoformat(),
            })

        log_admin_action(
            'confirm_scam', confirmed_by,
            target=category,
            details=f"Risk: {risk_level} — {message_text[:80]}"
        )

        return make_response(True, {'doc_id': doc_id, 'message': 'Scam confirmed and catalogued'})
    except Exception as e:
        return make_response(False, error=str(e), status_code=500)


@app.route('/admin/confirmed-scams', methods=['GET'])
def get_confirmed_scams():
    """Returns the confirmed scams database."""
    try:
        items = firebase.query_collection(
            'confirmed_scams',
            order_by='confirmed_at',
            limit=100
        )
        return make_response(True, items)
    except Exception as e:
        return make_response(False, error=str(e), status_code=500)

@app.route('/user/trust/<user_id>', methods=['GET'])
def get_trust_score(user_id):
    result = get_user_trust_score(user_id)
    return make_response(True, result)


# ─────────────────────────────────────────
# REPORT STATUS UPDATE
# ─────────────────────────────────────────

@app.route('/admin/report/update', methods=['POST'])
def update_report_status_endpoint():
    """Admin updates report status to reviewed/dismissed/actioned."""
    data = request.get_json()
    if not data:
        return make_response(False, error="Missing data", status_code=400)

    report_id   = data.get("report_id", "")
    report_type = data.get("report_type", "")  # 'message' or 'user'
    status      = data.get("status", "reviewed")
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


# ─────────────────────────────────────────
# AWARENESS & EDUCATION ENDPOINTS
# ─────────────────────────────────────────

@app.route('/awareness/alert', methods=['POST'])
def create_alert():
    data = request.get_json()
    if not data:
        return make_response(False, error="Missing data", status_code=400)
    title   = data.get("title", "")
    message = data.get("message") or data.get("body", "")
    if not title or not message:
        return make_response(False, error="Missing 'title' or 'message'", status_code=400)
    result = create_security_alert(
        title      = title,
        message    = message,
        severity   = data.get("severity", "medium"),
        created_by = data.get("created_by", "admin"),
        expires_at = data.get("expires_at", None)
    )
    return make_response(True, {"message": "Security alert created", "id": str(result) if result else ""})


@app.route('/awareness/alerts', methods=['GET'])
def get_alerts():
    return make_response(True, get_active_alerts())


# ── FIX: use string not int for Firestore IDs ──
@app.route('/awareness/alert/<string:alert_id>/deactivate', methods=['POST'])
def deactivate_alert_endpoint(alert_id):
    deactivate_alert(alert_id)
    return make_response(True, {"message": "Alert deactivated"})


@app.route('/awareness/alert/<string:alert_id>', methods=['PUT'])
def update_alert_endpoint(alert_id):
    """Admin updates an existing alert."""
    data = request.get_json() or {}
    fields = {}
    if "title"    in data: fields["title"]    = data["title"]
    if "message"  in data: fields["message"]  = data["message"]
    if "body"     in data: fields["message"]  = data["body"]
    if "severity" in data: fields["severity"] = data["severity"]
    if "active"   in data: fields["is_active"] = data["active"]
    if "is_active" in data: fields["is_active"] = data["is_active"]
    if not fields:
        return make_response(False, error="No fields to update", status_code=400)
    try:
        ok = firebase.update_document("security_alerts", alert_id, fields)
        if ok:
            return make_response(True, {"updated": alert_id})
        return make_response(False, error="Update failed")
    except Exception as e:
        return make_response(False, error=str(e), status_code=500)


@app.route('/awareness/alert/<string:alert_id>', methods=['DELETE'])
def delete_alert_endpoint(alert_id):
    """Admin deletes an alert."""
    try:
        ok = firebase.delete_document("security_alerts", alert_id)
        if ok:
            return make_response(True, {"deleted": alert_id})
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
        title         = data["title"],
        drill_message = data["drill_message"],
        target_user   = data.get("target_user", "all"),
        created_by    = data.get("created_by", "admin")
    )
    return make_response(True, {"message": "Phishing drill created"})


# ── FIX: use string not int for Firestore IDs ──
@app.route('/awareness/drill/<string:drill_id>/result', methods=['POST'])
def submit_drill_result(drill_id):
    data = request.get_json()
    if not data or "passed" not in data:
        return make_response(False, error="Missing 'passed' field", status_code=400)
    record_drill_result(drill_id, data["passed"])
    message = "Well done! You correctly identified the phishing attempt." \
        if data["passed"] else \
        "You fell for the drill. Please review our safety tips."
    return make_response(True, {"message": message, "passed": data["passed"]})


@app.route('/awareness/drill/<string:drill_id>', methods=['PUT'])
def update_drill_endpoint(drill_id):
    """Admin updates an existing drill."""
    data = request.get_json() or {}
    fields = {}
    if "title"        in data: fields["title"]        = data["title"]
    if "drill_message" in data: fields["drill_message"] = data["drill_message"]
    if "active"       in data: fields["active"]       = data["active"]
    if not fields:
        return make_response(False, error="No fields to update", status_code=400)
    try:
        ok = firebase.update_document("phishing_drills", drill_id, fields)
        if ok:
            return make_response(True, {"updated": drill_id})
        return make_response(False, error="Update failed")
    except Exception as e:
        return make_response(False, error=str(e), status_code=500)


@app.route('/awareness/drill/<string:drill_id>', methods=['DELETE'])
def delete_drill_endpoint(drill_id):
    """Admin deletes a drill."""
    try:
        ok = firebase.delete_document("phishing_drills", drill_id)
        if ok:
            return make_response(True, {"deleted": drill_id})
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
    title   = data.get("title", "")
    content = data.get("content") or data.get("body", "")
    category = data.get("category", "general")
    if not title or not content:
        return make_response(False, error="Missing 'title' or 'content'", status_code=400)
    add_safety_tip(
        category   = category,
        title      = title,
        content    = content,
        created_by = data.get("created_by", "admin")
    )
    return make_response(True, {"message": "Safety tip added"})


@app.route('/awareness/tips', methods=['GET'])
def get_tips():
    category = request.args.get("category", None)
    return make_response(True, get_safety_tips(category))


@app.route('/awareness/tip/<string:tip_id>', methods=['PUT'])
def update_tip_endpoint(tip_id):
    """Admin updates an existing tip."""
    data = request.get_json() or {}
    fields = {}
    if "title"    in data: fields["title"]   = data["title"]
    if "content"  in data: fields["content"] = data["content"]
    if "body"     in data: fields["content"] = data["body"]
    if "category" in data: fields["category"] = data["category"]
    if "active"   in data: fields["is_active"] = data["active"]
    if "is_active" in data: fields["is_active"] = data["is_active"]
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
    """Admin deletes a tip."""
    try:
        ok = firebase.delete_document("safety_tips", tip_id)
        if ok:
            return make_response(True, {"deleted": tip_id})
        return make_response(False, error="Delete failed")
    except Exception as e:
        return make_response(False, error=str(e), status_code=500)


@app.route('/awareness/feedback', methods=['POST'])
def submit_feedback():
    """User submits feedback.
    Accepts both 'feedback' (Flutter) and 'message' (legacy) field names.
    """
    data = request.get_json()
    if not data:
        return make_response(False, error="Missing data", status_code=400)
    # Accept 'feedback' OR 'message' field
    feedback_text = data.get("feedback") or data.get("message", "")
    if not feedback_text:
        return make_response(False, error="Missing 'feedback' field", status_code=400)
    submit_user_feedback(
        user_id       = data.get("user_id", "anonymous"),
        message       = feedback_text,
        feedback_type = data.get("feedback_type", "general"),
        rating        = data.get("rating", None)
    )
    return make_response(True, {"message": "Feedback submitted successfully"})


@app.route('/awareness/feedback/all', methods=['GET'])
def get_feedback():
    """Admin views all user feedback.
    Normalizes field names so Flutter always finds 'feedback' and 'rating'.
    """
    status = request.args.get("status", None)
    items  = get_user_feedback(status) or []
    normalized = []
    for item in items:
        normalized.append({
            "feedback"  : item.get("message") or item.get("feedback") or item.get("feedback_text") or "",
            "rating"    : item.get("rating", 0),
            "user_id"   : item.get("user_id", ""),
            "timestamp" : item.get("timestamp") or item.get("created_at") or "",
            "id"        : item.get("id", ""),
        })
    return make_response(True, normalized)


@app.route('/awareness/feedback/reply', methods=['POST'])
def reply_to_feedback():
    """Admin replies to a user feedback submission."""
    data = request.get_json()
    if not data or 'feedback_id' not in data or 'reply' not in data:
        return make_response(False, error="Missing feedback_id or reply", status_code=400)
    try:
        ok = firebase.update_document('user_feedback', data['feedback_id'], {
            'admin_reply': data['reply'],
            'replied_by': data.get('replied_by', 'admin'),
            'replied_at': datetime.now(timezone.utc).isoformat(),
            'status': 'replied'
        })
        if ok:
            return make_response(True, {"message": "Reply sent"})
        return make_response(False, error="Update failed")
    except Exception as e:
        return make_response(False, error=str(e), status_code=500)


@app.route('/awareness/feedback/user/<user_id>', methods=['GET'])
def get_user_feedback_by_id(user_id):
    """Returns feedback submitted by a specific user (for their profile view)."""
    from utils.firebase_config import query_collection
    try:
        items = query_collection(
            'user_feedback',
            filters=[('user_id', 'EQUAL', user_id)],
            order_by='submitted_at'
        ) or []
        normalized = [{
            'id': item.get('id', ''),
            'feedback': item.get('message') or item.get('feedback') or '',
            'rating': item.get('rating', 0),
            'status': item.get('status', 'unread'),
            'admin_reply': item.get('admin_reply', ''),
            'replied_at': item.get('replied_at', ''),
            'submitted_at': item.get('submitted_at', ''),
        } for item in items]
        return make_response(True, normalized)
    except Exception as e:
        return make_response(False, error=str(e), status_code=500)


# ─────────────────────────────────────────
# BLOCK USER (Firestore-based, no Flask state needed for block itself,
# but we log the action for admin visibility)
# ─────────────────────────────────────────

@app.route('/user/block', methods=['POST'])
def block_user_endpoint():
    """Logs a block action — actual block enforcement happens in Flutter/Firestore."""
    data = request.get_json()
    if not data or "blocker_id" not in data or "blocked_id" not in data:
        return make_response(False, error="Missing blocker_id or blocked_id", status_code=400)
    from utils.db_logger import log_admin_action
    log_admin_action(
        'user_blocked',
        data["blocker_id"],
        target=data["blocked_id"],
        details="User blocked another user"
    )
    return make_response(True, {"message": "Block logged"})


# ─────────────────────────────────────────
# MY REPORTS (user's own report history)
# ─────────────────────────────────────────

@app.route('/user/my-reports/<user_id>', methods=['GET'])
def get_my_reports_endpoint(user_id):
    """Returns reports filed BY this user (both message and user reports)."""
    from utils.firebase_config import query_collection
    try:
        message_reports = query_collection(
            'reported_messages',
            filters=[('reported_by', 'EQUAL', user_id)],
            order_by='reported_at'
        )
        user_reports = query_collection(
            'reported_users',
            filters=[('reported_by', 'EQUAL', user_id)],
            order_by='reported_at'
        )
        return make_response(True, {
            'message_reports': message_reports,
            'user_reports': user_reports
        })
    except Exception as e:
        return make_response(False, error=str(e), status_code=500)


# ─────────────────────────────────────────
# RUN SERVER
# ─────────────────────────────────────────

if __name__ == "__main__":
    print("=" * 55)
    print(" GeniusTalk Backend Server v2.0")
    print(" Running on http://127.0.0.1:5000")
    print("=" * 55)
    print(" YOUR Endpoints:")
    print("   GET  /health")
    print("   POST /scan/text")
    print("   POST /scan/file")
    print("   POST /scan/image")
    print("   POST /scan/full")
    print(" YY'S Endpoints:")
    print("   POST /scan/keyword")
    print("   POST /scan/qr")
    print("   POST /scan/qr/content")
    print("   POST /scan/link")
    print(" COMBINED:")
    print("   POST /scan/smart")
    print(" COMMUNITY:")
    print("   POST /report/message")
    print("   POST /report/user")
    print(" GOVERNANCE:")
    print("   POST /admin/ban")
    print("   POST /admin/unban")
    print("   GET  /admin/check-ban/<user_id>")
    print("   POST /admin/report/update")
    print(" ADMIN:")
    print("   GET  /admin/flagged")
    print("   GET  /admin/history")
    print("   GET  /admin/stats")
    print("   GET  /admin/banned")
    print("   GET  /admin/reports")
    print("   GET  /admin/qr-history")
    print("   GET  /user/trust/<user_id>")
    print("=" * 55)
    print(" AWARENESS & EDUCATION:")
    print("   POST /awareness/alert")
    print("   GET  /awareness/alerts")
    print("   PUT  /awareness/alert/<id>")
    print("   DEL  /awareness/alert/<id>")
    print("   POST /awareness/drill")
    print("   GET  /awareness/drills")
    print("   PUT  /awareness/drill/<id>")
    print("   DEL  /awareness/drill/<id>")
    print("   POST /awareness/tip")
    print("   GET  /awareness/tips")
    print("   PUT  /awareness/tip/<id>")
    print("   DEL  /awareness/tip/<id>")
    print("   POST /awareness/feedback")
    print("   GET  /awareness/feedback/all")
    print("   POST /awareness/feedback/reply")
    print("   GET  /awareness/feedback/user/<user_id>")
    print("=" * 55)
    print(" USER:")
    print("   POST /user/block")
    print("   GET  /user/my-reports/<user_id>")
    print("=" * 55)
    app.run(debug=True, host='0.0.0.0', port=5000)