# utils/file_inspector.py
# Malware & File Inspector Module
# Handles: extension checking, MIME verification, dangerous file detection

import os
import json

try:
    import magic  # detects real MIME type
except ImportError:
    magic = None

# ─────────────────────────────────────────
# DANGEROUS FILE DEFINITIONS
# ─────────────────────────────────────────

# High risk - these are almost always malicious in a messaging context
HIGH_RISK_EXTENSIONS = {
    '.exe', '.bat', '.cmd', '.com', '.pif', '.scr',  # Windows executables
    '.vbs', '.vbe', '.js', '.jse', '.ws', '.wsf',    # Scripts
    '.msi', '.msp', '.mst',                           # Installers
    '.apk', '.ipa',                                   # Mobile apps
    '.ps1', '.psm1', '.psd1',                         # PowerShell
    '.reg',                                           # Registry editor
    '.dll', '.sys', '.drv',                           # System files
}

# Medium risk - can carry malware but also used legitimately
MEDIUM_RISK_EXTENSIONS = {
    '.zip', '.rar', '.7z', '.tar', '.gz',             # Archives (can hide malware)
    '.pdf',                                           # PDF (can have scripts)
    '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', # Office (macros)
    '.iso', '.img',                                   # Disk images
    '.html', '.htm',                                  # Web pages
    '.xml',                                           # XML (can have scripts)
}

# Low risk - generally safe file types
LOW_RISK_EXTENSIONS = {
    '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.webp', # Images
    '.mp4', '.avi', '.mov', '.mkv',                   # Videos
    '.mp3', '.wav', '.aac',                           # Audio
    '.txt',                                           # Plain text
}

# MIME types that should NEVER appear as a sent "document"
DANGEROUS_MIME_TYPES = {
    'application/x-msdownload',       # .exe
    'application/x-executable',
    'application/x-msdos-program',
    'application/x-bat',
    'application/x-sh',               # shell script
    'application/vnd.android.package-archive',  # APK
    'application/x-dex',
}

# ─────────────────────────────────────────
# RISK SCORE CALCULATOR
# ─────────────────────────────────────────

def get_risk_label(score):
    """Convert numeric score to risk label."""
    if score >= 70:
        return "HIGH"
    elif score >= 40:
        return "MEDIUM"
    else:
        return "LOW"


def calculate_extension_score(extension):
    """Return a base risk score based on file extension."""
    ext = extension.lower()
    if ext in HIGH_RISK_EXTENSIONS:
        return 100  # Very dangerous
    elif ext in MEDIUM_RISK_EXTENSIONS:
        return 60  # Moderate risk
    elif ext in LOW_RISK_EXTENSIONS:
        return 20  # Generally safe
    else:
        return 25  # Unknown extension = treat as mildly suspicious


def calculate_mime_score(mime_type):
    """Return a risk score based on detected MIME type."""
    if mime_type in DANGEROUS_MIME_TYPES:
        return 100  # Confirmed dangerous MIME
    elif 'executable' in mime_type or 'script' in mime_type:
        return 90
    elif 'zip' in mime_type or 'compressed' in mime_type:
        return 60
    elif 'pdf' in mime_type or 'office' in mime_type:
        return 45
    elif mime_type.startswith('image/') or mime_type.startswith('audio/') or mime_type.startswith('video/'):
        return 15  # Media files are generally safe
    else:
        return 25  # Unknown MIME = mildly suspicious


# ─────────────────────────────────────────
# MISMATCH CHECKER
# ─────────────────────────────────────────

def check_extension_mime_mismatch(extension, mime_type):
    """
    Checks if the file extension matches the actual MIME type.
    A mismatch means someone renamed a dangerous file to look safe.
    Example: rename virus.exe to photo.jpg — this catches that.
    """
    ext = extension.lower()

    # Expected MIME prefixes for each extension group
    image_exts = {'.jpg', '.jpeg', '.png', '.gif', '.bmp', '.webp'}
    video_exts = {'.mp4', '.avi', '.mov', '.mkv'}
    audio_exts = {'.mp3', '.wav', '.aac'}
    doc_exts   = {'.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx'}

    mismatch = False

    if ext in image_exts and not mime_type.startswith('image/'):
        mismatch = True
    elif ext in video_exts and not mime_type.startswith('video/'):
        mismatch = True
    elif ext in audio_exts and not mime_type.startswith('audio/'):
        mismatch = True
    elif ext in doc_exts and not (
        'pdf' in mime_type or
        'officedocument' in mime_type or
        'msword' in mime_type or
        'ms-excel' in mime_type
    ):
        mismatch = True

    return mismatch


# ─────────────────────────────────────────
# MAIN INSPECTION FUNCTION
# ─────────────────────────────────────────

def inspect_file(file_path):
    """
    Main function — inspects a file and returns full safety report.
    
    Returns a dictionary with:
    - file_name      : name of the file
    - file_size_kb   : size in kilobytes
    - extension      : file extension
    - mime_type      : actual detected MIME type
    - mismatch       : True if extension doesn't match MIME
    - risk_score     : 0-100
    - risk_label     : LOW / MEDIUM / HIGH
    - is_blocked     : True if file should be blocked
    - reason         : explanation of the result
    """

    # ── Basic file info ──
    if not os.path.exists(file_path):
        return {"error": "File not found", "is_blocked": True}

    file_name  = os.path.basename(file_path)
    file_size  = os.path.getsize(file_path) / 1024  # convert to KB
    _, ext     = os.path.splitext(file_name)

    # ── Detect real MIME type ──
    try:
        mime_detector = magic.Magic(mime=True)
        mime_type     = mime_detector.from_file(file_path)
    except Exception:
        mime_type = "unknown"

    # ── Calculate individual scores ──
    ext_score  = calculate_extension_score(ext)
    mime_score = calculate_mime_score(mime_type)
    mismatch   = check_extension_mime_mismatch(ext, mime_type)

    # ── Combine scores ──
    # Weight: MIME type is more reliable than extension (60/40 split)
    combined_score = int((mime_score * 0.6) + (ext_score * 0.4))

    # High-risk extensions and confirmed dangerous MIME types must be treated as high risk
    if ext.lower() in HIGH_RISK_EXTENSIONS or mime_type in DANGEROUS_MIME_TYPES:
        combined_score = 100

    # Mismatch adds a heavy penalty — this is a strong red flag
    if mismatch:
        combined_score = min(100, combined_score + 30)

    # ── Determine safety decision ──
    # Uploads are allowed for all files; download/opening is blocked only for HIGH-risk files.
    download_blocked = (
        combined_score >= 70 or
        mime_type in DANGEROUS_MIME_TYPES or
        ext.lower() in HIGH_RISK_EXTENSIONS
    )
    is_blocked = False

    # ── Build reason message ──
    reasons = []
    if ext.lower() in HIGH_RISK_EXTENSIONS:
        reasons.append(f"Dangerous file extension detected: {ext}")
    if mime_type in DANGEROUS_MIME_TYPES:
        reasons.append(f"Dangerous MIME type detected: {mime_type}")
    if mismatch:
        reasons.append(f"Extension and file type do not match (possible disguise)")
    if not reasons:
        if combined_score >= 70:
            reasons.append("File flagged as high risk based on type analysis")
        elif combined_score >= 40:
            reasons.append("File is moderately suspicious — proceed with caution")
        else:
            reasons.append("File appears safe")

    # ── Final report ──
    report = {
        "file_name"       : file_name,
        "file_size_kb"    : round(file_size, 2),
        "extension"       : ext if ext else "none",
        "mime_type"       : mime_type,
        "mismatch"        : mismatch,
        "risk_score"      : combined_score,
        "risk_label"      : get_risk_label(combined_score),
        "is_blocked"      : is_blocked,
        "download_blocked": download_blocked,
        "allow_download"  : not download_blocked,
        "upload_allowed"  : True,
        "reason"          : " | ".join(reasons)
    }

    return report


# ─────────────────────────────────────────
# QUICK TEST (run this file directly to test)
# ─────────────────────────────────────────

if __name__ == "__main__":
    import sys

    # If you pass a file path as argument, it inspects that file
    # Otherwise it runs a built-in demo test
    if len(sys.argv) > 1:
        result = inspect_file(sys.argv[1])
    else:
        # Demo: create a small fake test file
        test_path = "test_files/test_sample.txt"
        os.makedirs("test_files", exist_ok=True)
        with open(test_path, "w") as f:
            f.write("This is a test file.")
        result = inspect_file(test_path)

    print(json.dumps(result, indent=2))  