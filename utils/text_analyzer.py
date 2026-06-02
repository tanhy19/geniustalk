# utils/text_analyzer.py
# AI Text Analyzer Module
# Handles: scam keyword detection, tone checking, risk scoring
# No API used — pure Python pattern matching + ML-ready structure

import re
import json
import math
import os
import pickle

# ─────────────────────────────────────────
# LOAD ML MODEL
# ─────────────────────────────────────────

ML_MODEL_PATH = "models/scam_classifier.pkl"
_ml_model = None

def load_ml_model():
    """
    Loads the trained ML model from disk.
    Only loads once — reuses same instance after that.
    """
    global _ml_model
    if _ml_model is None:
        if os.path.exists(ML_MODEL_PATH):
            with open(ML_MODEL_PATH, 'rb') as f:
                _ml_model = pickle.load(f)
            print("ML model loaded successfully.")
        else:
            print("Warning: ML model not found. Using keyword detection only.")
    return _ml_model

# Load model when module is imported
load_ml_model()


def get_ml_score(text):
    """
    Gets scam probability from the trained ML model.
    Returns a score 0-100.
    0   = definitely safe
    100 = definitely scam
    """
    model = load_ml_model()

    if model is None:
        return None  # Model not available, fall back to keywords only

    try:
        # Get probability scores for [safe, scam]
        proba      = model.predict_proba([text])[0]
        scam_proba = proba[1]  # probability of being scam
        ml_score   = int(scam_proba * 100)
        return ml_score
    except Exception:
        return None
    
# ─────────────────────────────────────────
# SCAM KEYWORD DATABASE
# ─────────────────────────────────────────

# High risk keywords — strongly indicate scam
HIGH_RISK_KEYWORDS = [
    # Prize / lottery scams
    "you won", "you have won", "winner", "grand prize", "lucky draw",
    "congratulations you win", "claim your prize", "redeem prize",
    "selected winner", "prize money",

    # Urgency pressure
    "act now", "limited time", "expires today", "urgent", "immediately",
    "last chance", "don't miss", "respond now", "within 24 hours",
    "account will be suspended", "account suspended",

    # Financial scams
    "send money", "transfer now", "bank details", "bank account number",
    "wire transfer", "western union", "moneygram", "bitcoin payment",
    "crypto payment", "pay now to claim",

    # Phishing
    "verify your account", "confirm your password", "enter your pin",
    "update your details", "click to verify", "login to confirm",
    "your account has been compromised", "unauthorized access detected",

    # Malaysia specific scams
    "rm10000", "rm 10000", "rm5000", "rm 5000", "maybank2u login",
    "cimb clicks", "touch n go reload", "shopee lucky", "lazada winner",
    "tabung haji", "kwsp login", "lhdn refund",

    # Investment scams
    "guaranteed profit", "100% return", "double your money",
    "investment opportunity", "passive income guaranteed",
    "no risk investment", "forex profit",
]

# Medium risk keywords — suspicious but not definitive
MEDIUM_RISK_KEYWORDS = [
    # Suspicious links
    "bit.ly", "tinyurl", "shorturl", "t.co", "goo.gl",
    "click here", "click link", "tap here", "visit now",

    # Personal info requests
    "ic number", "passport number", "full name and address",
    "date of birth", "mother maiden name", "security question",

    # Vague rewards
    "free gift", "free iphone", "free voucher", "cash reward",
    "bonus credit", "special offer for you", "exclusively for you",

    # Authority impersonation
    "bank negara", "pdrm", "police", "jabatan", "kementerian",
    "official notice", "government grant", "tax refund",

    # Emotional manipulation
    "help me", "i am stuck", "emergency", "stranded",
    "need your help urgently", "dont tell anyone",
]

# Low risk — slightly suspicious words, common in spam
LOW_RISK_KEYWORDS = [
    "free", "win", "prize", "offer", "deal", "discount",
    "promotion", "reward", "bonus", "gift", "lucky",
    "selected", "chosen", "exclusive", "special",
]

# ─────────────────────────────────────────
# SUSPICIOUS URL PATTERNS
# ─────────────────────────────────────────

SUSPICIOUS_URL_PATTERNS = [
    r'bit\.ly\/\S+',
    r'tinyurl\.com\/\S+',
    r'shorturl\.at\/\S+',
    r'https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',  # IP address URLs
    r'\b\w+\.(xyz|win|tk|ml|ga|cf|gq|top|club)\b',    # Suspicious TLDs
    r'https?://\S+login\S+',                            # Fake login pages
    r'https?://\S+verify\S+',                           # Fake verify pages
    r'https?://\S+claim\S+',                            # Fake claim pages
]

# ─────────────────────────────────────────
# TONE ANALYZER
# ─────────────────────────────────────────

def check_message_tone(text):
    """
    Checks the tone of the message.
    Scam messages typically use urgency, pressure, or excitement.
    Returns a tone label and score penalty.
    """
    text_lower = text.lower()

    urgency_words   = ["urgent", "immediately", "now", "quickly", "fast",
                       "hurry", "limited", "expires", "deadline", "asap"]
    excitement_words = ["!!!", "congratulations", "winner", "amazing",
                        "incredible", "wow", "unbelievable", "guaranteed"]
    threat_words    = ["suspended", "blocked", "terminated", "arrested",
                       "legal action", "police", "warrant", "penalty"]

    urgency_count   = sum(1 for w in urgency_words if w in text_lower)
    excitement_count = sum(1 for w in excitement_words if w in text_lower)
    threat_count    = sum(1 for w in threat_words if w in text_lower)

    # Excessive punctuation (!!!???) is a scam signal
    exclamation_count = text.count('!')
    caps_ratio = sum(1 for c in text if c.isupper()) / max(len(text), 1)

    tone_score = 0
    tone_labels = []

    if urgency_count >= 2:
        tone_score += 20
        tone_labels.append("HIGH URGENCY")
    elif urgency_count == 1:
        tone_score += 10
        tone_labels.append("SOME URGENCY")

    if excitement_count >= 2:
        tone_score += 15
        tone_labels.append("OVER EXCITEMENT")
    elif excitement_count == 1:
        tone_score += 7

    if threat_count >= 1:
        tone_score += 25
        tone_labels.append("THREATENING TONE")

    if exclamation_count >= 3:
        tone_score += 10
        tone_labels.append("EXCESSIVE PUNCTUATION")

    if caps_ratio > 0.4:
        tone_score += 10
        tone_labels.append("EXCESSIVE CAPS")

    return {
        "tone_labels" : tone_labels if tone_labels else ["NEUTRAL"],
        "tone_score"  : min(tone_score, 40),  # max 40 points from tone
    }


# ─────────────────────────────────────────
# KEYWORD SCANNER
# ─────────────────────────────────────────

def scan_keywords(text):
    """
    Scans text for scam keywords across all risk levels.
    Returns matched keywords and a score.
    """
    text_lower = text.lower()

    matched_high   = [kw for kw in HIGH_RISK_KEYWORDS if kw in text_lower]
    matched_medium = [kw for kw in MEDIUM_RISK_KEYWORDS if kw in text_lower]
    matched_low    = [kw for kw in LOW_RISK_KEYWORDS if kw in text_lower]

    # Score calculation
    # High keywords are weighted heavily, diminishing returns after 3 matches
    high_score   = min(len(matched_high) * 20, 60)
    medium_score = min(len(matched_medium) * 10, 25)
    low_score    = min(len(matched_low) * 3, 10)

    keyword_score = high_score + medium_score + low_score

    return {
        "matched_high"   : matched_high,
        "matched_medium" : matched_medium,
        "matched_low"    : matched_low,
        "keyword_score"  : min(keyword_score, 70),  # max 70 from keywords
    }


# ─────────────────────────────────────────
# URL SCANNER
# ─────────────────────────────────────────

def scan_urls(text):
    """
    Checks for suspicious URLs embedded in the text.
    """
    found_suspicious = []

    for pattern in SUSPICIOUS_URL_PATTERNS:
        matches = re.findall(pattern, text, re.IGNORECASE)
        found_suspicious.extend(matches)

    url_score = min(len(found_suspicious) * 25, 40)

    return {
        "suspicious_urls" : list(set(found_suspicious)),
        "url_score"       : url_score,
    }


# ─────────────────────────────────────────
# MAIN ANALYSIS FUNCTION
# ─────────────────────────────────────────

def analyze_text(text, source="direct"):
    """
    Main function — analyzes text for scam indicators.

    Parameters:
    - text   : the text to analyze (from message or OCR)
    - source : where the text came from ("direct" or "ocr")

    Returns a dictionary with:
    - risk_score     : 0-100
    - risk_label     : LOW / MEDIUM / HIGH
    - is_scam        : True if HIGH risk
    - matched_keywords: list of detected scam words
    - suspicious_urls : list of suspicious links found
    - tone           : tone analysis result
    - summary        : human readable explanation
    - source         : where text came from
    """

    if not text or len(text.strip()) < 3:
        return {
            "risk_score"      : 0,
            "risk_label"      : "LOW",
            "is_scam"         : False,
            "matched_keywords": [],
            "suspicious_urls" : [],
            "tone"            : {"tone_labels": ["NEUTRAL"], "tone_score": 0},
            "summary"         : "No text to analyze",
            "source"          : source
        }

# ── Run all analyzers ──
    keyword_result = scan_keywords(text)
    url_result     = scan_urls(text)
    tone_result    = check_message_tone(text)
    ml_score       = get_ml_score(text)

    # ── Combine scores ──
    # If ML model is available, use it as primary signal (50%)
    # Keywords, URLs, tone fill the remaining 50%
    if ml_score is not None:
        raw_score = (
            ml_score                        * 0.50 +
            keyword_result["keyword_score"] * 0.25 +
            url_result["url_score"]         * 0.15 +
            tone_result["tone_score"]       * 0.10
        )
    else:
        # Fallback: keyword only mode
        raw_score = (
            keyword_result["keyword_score"] * 0.60 +
            url_result["url_score"]         * 0.25 +
            tone_result["tone_score"]       * 0.15
        )

    # Bonus: 2+ high risk keywords alone is already very suspicious
    if len(keyword_result["matched_high"]) >= 2:
        raw_score += 20

    # Bonus: 3+ high risk keywords is almost certainly a scam
    if len(keyword_result["matched_high"]) >= 3:
        raw_score += 20

    # Bonus: high keywords + suspicious URL together = definite scam
    if keyword_result["matched_high"] and url_result["suspicious_urls"]:
        raw_score += 20

    # Bonus: high urgency tone + high keywords = scam pattern
    if (keyword_result["matched_high"] and
        "HIGH URGENCY" in tone_result["tone_labels"]):
        raw_score += 15

    # Round and cap at 100
    final_score = min(int(raw_score), 100)

    # ── Determine risk label ──
    if final_score >= 70:
        risk_label = "HIGH"
        is_scam    = True
    elif final_score >= 40:
        risk_label = "MEDIUM"
        is_scam    = False
    else:
        risk_label = "LOW"
        is_scam    = False

    # ── Build summary ──
    summary_parts = []

    if keyword_result["matched_high"]:
        summary_parts.append(
            f"High risk keywords detected: {', '.join(keyword_result['matched_high'][:3])}"
        )
    if keyword_result["matched_medium"]:
        summary_parts.append(
            f"Suspicious phrases found: {', '.join(keyword_result['matched_medium'][:3])}"
        )
    if url_result["suspicious_urls"]:
        summary_parts.append(
            f"Suspicious URLs found: {', '.join(url_result['suspicious_urls'][:2])}"
        )
    if "THREATENING TONE" in tone_result["tone_labels"]:
        summary_parts.append("Message uses threatening language")
    if "HIGH URGENCY" in tone_result["tone_labels"]:
        summary_parts.append("Message creates artificial urgency")
    if not summary_parts:
        summary_parts.append("No significant scam indicators detected")

    return {
        "risk_score"       : final_score,
        "risk_label"       : risk_label,
        "is_scam"          : is_scam,
        "ml_score"         : ml_score,
        "matched_keywords" : {
            "high"  : keyword_result["matched_high"],
            "medium": keyword_result["matched_medium"],
            "low"   : keyword_result["matched_low"],
        },
        "suspicious_urls"  : url_result["suspicious_urls"],
        "tone"             : tone_result,
        "summary"          : " | ".join(summary_parts),
        "source"           : source
    }


# ─────────────────────────────────────────
# COMBINED OCR + ANALYSIS FUNCTION
# ─────────────────────────────────────────

def analyze_image_text(image_path):
    """
    Convenience function — runs OCR then immediately analyzes the text.
    This is the main entry point when an image is received in chat.
    """

    import sys
    import os

    sys.path.insert(
        0,
        os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    )

    from utils.ocr_engine import scan_image

    # Step 1: Extract text from image
    ocr_result = scan_image(image_path)

    if ocr_result.get("error"):
        return {
            "ocr_success": False,
            "error": ocr_result["error"],
            "analysis": None
        }

    if not ocr_result["has_text"]:
        return {
            "ocr_success": True,
            "extracted_text": "",
            "error": None,
            "analysis": {
                "risk_score": 0,
                "risk_label": "LOW",
                "is_scam": False,
                "summary": "No text found in image"
            }
        }

    # Step 2: Analyze extracted text
    analysis = analyze_text(
        ocr_result["extracted_text"],
        source="ocr"
    )

    return {
        "ocr_success": True,
        "extracted_text": ocr_result["extracted_text"],
        "image_properties": ocr_result["image_properties"],
        "error": None,
        "analysis": analysis
    }

# ─────────────────────────────────────────
# QUICK TEST
# ─────────────────────────────────────────

if __name__ == "__main__":

    print("=" * 60)
    print("TEST 1 — Obvious scam message")
    print("=" * 60)
    scam_text = "URGENT! You have won RM10,000 in our lucky draw! Click bit.ly/claim-now to verify your account and send your bank details immediately!"
    result = analyze_text(scam_text)
    print(json.dumps(result, indent=2))

    print("\n" + "=" * 60)
    print("TEST 2 — Normal message")
    print("=" * 60)
    normal_text = "Hey, are you free tomorrow? Let's meet for lunch at 1pm."
    result = analyze_text(normal_text)
    print(json.dumps(result, indent=2))

    print("\n" + "=" * 60)
    print("TEST 3 — OCR image analysis (uses test image we created)")
    print("=" * 60)
    result = analyze_image_text("test_files/test_scam_image.png")
    print(json.dumps(result, indent=2))

    print("\n" + "=" * 60)
    print("TEST 4 — Real scam image you uploaded earlier")
    print("=" * 60)
    result = analyze_image_text("test_files/test1.png")
    print(json.dumps(result, indent=2))