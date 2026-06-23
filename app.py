# app.py
# GeniusTalk Complete Backend Server v2.0
# Combined Modules + Language Translation

from flask import Flask, request, jsonify
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# ── Your modules ──
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
    create_security_alert,
    get_active_alerts,
    deactivate_alert,
    create_phishing_drill,
    record_drill_result,
    get_all_drills,
    add_safety_tip,
    get_safety_tips,
    submit_user_feedback,
    get_user_feedback
)

# ── YY's modules ──
from utils.keyword_engine import keyword_scan
from utils.qr_scanner     import scan_qr, analyze_qr_content
from utils.link_verifier  import verify_links

app = Flask(__name__)

# ─────────────────────────────────────────
# CONFIGURATION
# ─────────────────────────────────────────

MAX_FILE_SIZE_MB    = 10
MAX_FILE_SIZE_BYTES = MAX_FILE_SIZE_MB * 1024 * 1024
TEMP_FOLDER         = "temp_uploads"

os.makedirs(TEMP_FOLDER, exist_ok=True)
initialize_database()


# ─────────────────────────────────────────
# HELPER
# ─────────────────────────────────────────

def make_response(success, data=None, error=None, status_code=200):
    """Standard response format for all endpoints."""
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
            "file_inspector",
            "ocr_engine",
            "text_analyzer",
            "translator",
            "keyword_engine",
            "qr_scanner",
            "link_verifier"
        ]
    })


# ─────────────────────────────────────────
# YOUR ENDPOINTS
# ─────────────────────────────────────────

@app.route('/scan/text', methods=['POST'])
def scan_text():
    """Analyzes text using ML model + keywords + tone. Auto translates."""
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
    """Inspects uploaded file for malware. Called before sending attachments."""
    if 'file' not in request.files:
        return make_response(False, error="No file uploaded", status_code=400)

    uploaded_file = request.files['file']
    if uploaded_file.filename == '':
        return make_response(False, error="Empty filename", status_code=400)

    uploaded_file.seek(0, 2)
    file_size = uploaded_file.tell()
    uploaded_file.seek(0)

    if file_size > MAX_FILE_SIZE_BYTES:
        return make_response(False,
            error=f"File too large. Maximum {MAX_FILE_SIZE_MB}MB",
            status_code=413)

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
    """OCR scans image then analyzes for scams."""
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
    """Runs file inspection + OCR together."""
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
                (ocr_result and ocr_result.get(
                    "analysis", {}).get("is_scam", False))
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
    """Analyzes text using keyword engine + phishing ML model."""
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
        "risk_score": score,
        "risk_label": risk_level,
        "is_scam"   : risk_level == "HIGH",
        "summary"   : f"Keyword engine: {len(matches)} matches found",
        "source"    : "keyword_engine"
    })
    return make_response(True, result)


@app.route('/scan/qr', methods=['POST'])
def scan_qr_endpoint():
    """Scans QR code image and analyzes content."""
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
    """Analyzes raw QR content text directly."""
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
    """Checks if a URL is safe before user opens it."""
    data = request.get_json()
    if not data or "text" not in data:
        return make_response(False, error="Missing 'text' field", status_code=400)

    text        = data["text"].strip()
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
    """Runs both ML models + translation. Best accuracy."""
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
        "risk_score": combined_score,
        "risk_label": final_label,
        "is_scam"   : is_scam,
        "summary"   : f"Smart scan: your={your_score}, keyword={friend_score}",
        "source"    : "smart_scan"
    })
    return make_response(True, result)


# ─────────────────────────────────────────
# COMMUNITY DEFENSE ENDPOINTS
# ─────────────────────────────────────────

@app.route('/report/message', methods=['POST'])
def report_message_endpoint():
    """Report a suspicious message."""
    data = request.get_json()
    if not data:
        return make_response(False, error="Missing data", status_code=400)

    report_message(
        reported_by     = data.get("reported_by", "anonymous"),
        message_content = data.get("message_content", ""),
        reason          = data.get("reason", ""),
        risk_score      = data.get("risk_score", 0)
    )
    return make_response(True, {"message": "Report submitted successfully"})


@app.route('/report/user', methods=['POST'])
def report_user_endpoint():
    """Report a suspicious user."""
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
    """Ban a user — temporary or permanent."""
    data = request.get_json()
    if not data:
        return make_response(False, error="Missing data", status_code=400)

    ban_user(
        user_id    = data.get("user_id", ""),
        ban_type   = data.get("ban_type", "temporary"),
        reason     = data.get("reason", ""),
        device_id  = data.get("device_id", None),
        banned_by  = data.get("banned_by", "admin"),
        expires_at = data.get("expires_at", None)
    )
    return make_response(True, {"message": "User banned successfully"})


@app.route('/admin/unban', methods=['POST'])
def unban_user_endpoint():
    """Remove ban from a user."""
    data = request.get_json()
    if not data or "user_id" not in data:
        return make_response(False, error="Missing user_id", status_code=400)

    unban_user(data["user_id"])
    return make_response(True, {"message": "User unbanned successfully"})


@app.route('/admin/check-ban/<user_id>', methods=['GET'])
def check_ban_endpoint(user_id):
    """Check if a user is currently banned."""
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
    """Returns all HIGH risk flagged items."""
    return make_response(True, get_all_flagged())


@app.route('/admin/history', methods=['GET'])
def admin_history():
    """Returns full scan history."""
    return make_response(True, get_scan_history())


@app.route('/admin/stats', methods=['GET'])
def admin_stats():
    """Returns system health stats."""
    return make_response(True, get_system_stats())


@app.route('/admin/banned', methods=['GET'])
def get_banned_list():
    """Returns all active banned users."""
    return make_response(True, get_banned_users())


@app.route('/admin/reports', methods=['GET'])
def get_reports():
    """Returns all pending reports."""
    return make_response(True, get_pending_reports())


@app.route('/admin/qr-history', methods=['GET'])
def get_qr_history():
    """Returns QR scan history."""
    return make_response(True, get_qr_scan_history())

@app.route('/user/trust/<user_id>', methods=['GET'])
def get_trust_score(user_id):
    """Returns trust score for a user. Used in Community Defense Hub."""
    result = get_user_trust_score(user_id)
    return make_response(True, result)

# ─────────────────────────────────────────
# AWARENESS & EDUCATION ENDPOINTS
# ─────────────────────────────────────────

@app.route('/awareness/alert', methods=['POST'])
def create_alert():
    """Admin creates a security alert broadcast."""
    data = request.get_json()
    if not data:
        return make_response(False, error="Missing data", status_code=400)

    if "title" not in data or "message" not in data:
        return make_response(False,
            error="Missing 'title' or 'message'", status_code=400)

    create_security_alert(
        title      = data["title"],
        message    = data["message"],
        severity   = data.get("severity", "medium"),
        created_by = data.get("created_by", "admin"),
        expires_at = data.get("expires_at", None)
    )
    return make_response(True, {"message": "Security alert created"})


@app.route('/awareness/alerts', methods=['GET'])
def get_alerts():
    """Returns all active security alerts."""
    return make_response(True, get_active_alerts())


@app.route('/awareness/alert/<string:alert_id>/deactivate', methods=['POST'])
def deactivate_alert_endpoint(alert_id):
    """Deactivates a security alert."""
    deactivate_alert(alert_id)
    return make_response(True, {"message": "Alert deactivated"})


@app.route('/awareness/drill', methods=['POST'])
def create_drill():
    """Admin creates a phishing drill."""
    data = request.get_json()
    if not data:
        return make_response(False, error="Missing data", status_code=400)

    if "title" not in data or "drill_message" not in data:
        return make_response(False,
            error="Missing 'title' or 'drill_message'", status_code=400)

    create_phishing_drill(
        title        = data["title"],
        drill_message = data["drill_message"],
        target_user  = data.get("target_user", "all"),
        created_by   = data.get("created_by", "admin")
    )
    return make_response(True, {"message": "Phishing drill created"})


@app.route('/awareness/drill/<string:drill_id>/result', methods=['POST'])
def submit_drill_result(drill_id):
    """Records user response to a phishing drill."""
    data = request.get_json()
    if not data or "passed" not in data:
        return make_response(False, error="Missing 'passed' field", status_code=400)

    record_drill_result(drill_id, data["passed"])
    message = "Well done! You correctly identified the phishing attempt." \
        if data["passed"] else \
        "You fell for the drill. Please review our safety tips."
    return make_response(True, {"message": message, "passed": data["passed"]})


@app.route('/awareness/drills', methods=['GET'])
def get_drills():
    """Returns all phishing drills."""
    return make_response(True, get_all_drills())


@app.route('/awareness/tip', methods=['POST'])
def add_tip():
    """Admin adds a safety tip."""
    data = request.get_json()
    if not data:
        return make_response(False, error="Missing data", status_code=400)

    if "title" not in data or "content" not in data or "category" not in data:
        return make_response(False,
            error="Missing 'title', 'content' or 'category'",
            status_code=400)

    add_safety_tip(
        category   = data["category"],
        title      = data["title"],
        content    = data["content"],
        created_by = data.get("created_by", "admin")
    )
    return make_response(True, {"message": "Safety tip added"})


@app.route('/awareness/tips', methods=['GET'])
def get_tips():
    """Returns safety tips. Optional ?category= filter."""
    category = request.args.get("category", None)
    return make_response(True, get_safety_tips(category))


@app.route('/awareness/feedback', methods=['POST'])
def submit_feedback():
    """User submits feedback."""
    data = request.get_json()
    if not data or "message" not in data:
        return make_response(False, error="Missing 'message'", status_code=400)

    submit_user_feedback(
        user_id       = data.get("user_id", "anonymous"),
        message       = data["message"],
        feedback_type = data.get("feedback_type", "general"),
        rating        = data.get("rating", None)
    )
    return make_response(True, {"message": "Feedback submitted successfully"})


@app.route('/awareness/feedback/all', methods=['GET'])
def get_feedback():
    """Admin views all user feedback."""
    status = request.args.get("status", None)
    return make_response(True, get_user_feedback(status))
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
    print("   POST /awareness/drill")
    print("   GET  /awareness/drills")
    print("   POST /awareness/tip")
    print("   GET  /awareness/tips")
    print("   POST /awareness/feedback")
    print("   GET  /awareness/feedback/all")
    app.run(debug=True, host='0.0.0.0', port=5000)