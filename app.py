# app.py
# GeniusTalk Backend Server
# Connects File Inspector + OCR + Text Analyzer into one API
# Flutter calls this server to scan files and images

from email.mime import text

from flask import Flask, request, jsonify
import os
import json
import tempfile
from utils.file_inspector import inspect_file
from utils.text_analyzer import analyze_text, analyze_image_text
from utils.db_logger import (
    initialize_database,
    log_text_scan,
    log_file_scan,
    log_image_scan,
    get_all_flagged,
    get_scan_history,
    get_system_stats
)
app = Flask(__name__)

# ─────────────────────────────────────────
# CONFIGURATION
# ─────────────────────────────────────────

# Maximum file size allowed — 10MB
MAX_FILE_SIZE_MB = 10
MAX_FILE_SIZE_BYTES = MAX_FILE_SIZE_MB * 1024 * 1024

# Temp folder for uploaded files
TEMP_FOLDER = "temp_uploads"
os.makedirs(TEMP_FOLDER, exist_ok=True)
# Initialize database on server start
initialize_database()


# ─────────────────────────────────────────
# HELPER
# ─────────────────────────────────────────

def make_response(success, data=None, error=None, status_code=200):
    """Standard response format for all endpoints."""
    response = {
        "success": success,
        "data"   : data,
        "error"  : error
    }
    return jsonify(response), status_code


# ─────────────────────────────────────────
# HEALTH CHECK
# ─────────────────────────────────────────

@app.route('/health', methods=['GET'])
def health_check():
    """Simple check to confirm server is running."""
    return make_response(True, {
        "status" : "running",
        "version": "1.0.0",
        "modules": [
            "file_inspector",
            "ocr_engine",
            "text_analyzer"
        ]
    })


# ─────────────────────────────────────────
# ENDPOINT 1 — SCAN TEXT
# ─────────────────────────────────────────

@app.route('/scan/text', methods=['POST'])
def scan_text():
    """
    Analyzes a text message for scam indicators.

    Expected JSON body:
    {
        "text": "your message here"
    }

    Returns risk score, label, keywords, URLs found.
    Flutter calls this for every message sent/received.
    """
    data = request.get_json()

    if not data or "text" not in data:
        return make_response(False, error="Missing 'text' field", status_code=400)

    text = data["text"].strip()

    if not text:
        return make_response(False, error="Text cannot be empty", status_code=400)

    result = analyze_text(text, source="direct")
    log_text_scan(text, result)
    return make_response(True, result)


# ─────────────────────────────────────────
# ENDPOINT 2 — SCAN FILE
# ─────────────────────────────────────────

@app.route('/scan/file', methods=['POST'])
def scan_file():
    """
    Inspects an uploaded file for malware indicators.

    Expected: multipart/form-data with file field named 'file'

    Returns risk score, MIME type, extension, block decision.
    Flutter calls this when user tries to send an attachment.
    """
    if 'file' not in request.files:
        return make_response(False, error="No file uploaded", status_code=400)

    uploaded_file = request.files['file']

    if uploaded_file.filename == '':
        return make_response(False, error="Empty filename", status_code=400)

    # Check file size
    uploaded_file.seek(0, 2)  # Seek to end
    file_size = uploaded_file.tell()
    uploaded_file.seek(0)     # Reset

    if file_size > MAX_FILE_SIZE_BYTES:
        return make_response(False,
            error=f"File too large. Maximum size is {MAX_FILE_SIZE_MB}MB",
            status_code=413
        )

    # Save temporarily to disk for inspection
    temp_path = os.path.join(TEMP_FOLDER, uploaded_file.filename)

    try:
        uploaded_file.save(temp_path)
        result = inspect_file(temp_path)
        log_file_scan(uploaded_file.filename, result)
        return make_response(True, result)

    except Exception as e:
        return make_response(False, error=str(e), status_code=500)

    finally:
        # Always clean up temp file after inspection
        if os.path.exists(temp_path):
            os.remove(temp_path)


# ─────────────────────────────────────────
# ENDPOINT 3 — SCAN IMAGE (OCR + Analysis)
# ─────────────────────────────────────────

@app.route('/scan/image', methods=['POST'])
def scan_image():
    """
    Scans an image — extracts text via OCR then analyzes for scams.

    Expected: multipart/form-data with file field named 'image'

    Returns extracted text + full risk analysis.
    Flutter calls this when user receives an image message.
    """
    if 'image' not in request.files:
        return make_response(False, error="No image uploaded", status_code=400)

    uploaded_image = request.files['image']

    if uploaded_image.filename == '':
        return make_response(False, error="Empty filename", status_code=400)

    # Save temporarily
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


# ─────────────────────────────────────────
# ENDPOINT 4 — COMBINED SCAN
# ─────────────────────────────────────────

@app.route('/scan/full', methods=['POST'])
def full_scan():
    """
    Runs both file inspection AND image OCR analysis together.
    Used when Flutter receives any file — checks safety AND extracts text.

    Expected: multipart/form-data with file field named 'file'
    """
    if 'file' not in request.files:
        return make_response(False, error="No file uploaded", status_code=400)

    uploaded_file = request.files['file']
    temp_path = os.path.join(TEMP_FOLDER, uploaded_file.filename)

    try:
        uploaded_file.save(temp_path)

        # Always run file inspection
        file_result = inspect_file(temp_path)

        # Run OCR only if it's an image
        image_extensions = {'.jpg', '.jpeg', '.png', '.bmp', '.gif', '.webp'}
        _, ext = os.path.splitext(uploaded_file.filename)
        ocr_result = None

        if ext.lower() in image_extensions:
            ocr_result = analyze_image_text(temp_path)

        combined = {
            "file_inspection": file_result,
            "ocr_analysis"   : ocr_result,
            # Overall block decision — block if EITHER check says block
            "should_block"   : file_result.get("is_blocked", False) or
                               (ocr_result and ocr_result.get("analysis", {}).get("is_scam", False))
        }

        return make_response(True, combined)

    except Exception as e:
        return make_response(False, error=str(e), status_code=500)

    finally:
        if os.path.exists(temp_path):
            os.remove(temp_path)

# ─────────────────────────────────────────
# ADMIN ENDPOINTS (for friend's dashboard)
# ─────────────────────────────────────────

@app.route('/admin/flagged', methods=['GET'])
def admin_flagged():
    """Returns all flagged HIGH risk items for admin review."""
    data = get_all_flagged()
    return make_response(True, data)


@app.route('/admin/history', methods=['GET'])
def admin_history():
    """Returns full scan history for activity monitoring."""
    data = get_scan_history()
    return make_response(True, data)


@app.route('/admin/stats', methods=['GET'])
def admin_stats():
    """Returns system health stats — total scans, flagged, blocked."""
    data = get_system_stats()
    return make_response(True, data)

# ─────────────────────────────────────────
# RUN SERVER
# ─────────────────────────────────────────

if __name__ == "__main__":
    print("=" * 50)
    print(" GeniusTalk Backend Server")
    print(" Running on http://127.0.0.1:5000")
    print("=" * 50)
    print(" Endpoints:")
    print("   GET  /health")
    print("   POST /scan/text")
    print("   POST /scan/file")
    print("   POST /scan/image")
    print("   POST /scan/full")
    print("=" * 50)
    app.run(debug=True, host='127.0.0.1', port=5000)

    