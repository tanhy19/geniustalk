# utils/keyword_engine.py
# Keyword Engine Module
# Handles: keyword scanning, tone detection, ML prediction, link verification

import json
import re
import os
import sys

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

try:
    from utils.preprocessing import clean_text
    from utils.link_verifier import verify_links
except ImportError:
    from preprocessing import clean_text
    from link_verifier import verify_links

# ─────────────────────────────────────────
# LOAD KEYWORD DATASET
# ─────────────────────────────────────────

KEYWORDS_PATH = "datasets/scam_keywords.json"

with open(KEYWORDS_PATH, "r") as f:
    KEYWORDS = json.load(f)


# ─────────────────────────────────────────
# LOAD ML MODEL
# ─────────────────────────────────────────

_friend_model      = None
_friend_vectorizer = None


def load_friend_model():
    """Loads friend's phishing model silently if available."""
    global _friend_model, _friend_vectorizer

    model_path      = "models/model.pkl"
    vectorizer_path = "models/vectorizer.pkl"

    if os.path.exists(model_path) and os.path.exists(vectorizer_path):
        import pickle
        with open(model_path, "rb") as f:
            _friend_model = pickle.load(f)
        with open(vectorizer_path, "rb") as f:
            _friend_vectorizer = pickle.load(f)

load_friend_model()


def predict_phishing(text):
    """Uses ML model to predict phishing. Returns 'phishing'/'safe'/None."""
    if _friend_model is None or _friend_vectorizer is None:
        return None
    try:
        cleaned    = clean_text(text)
        vectorized = _friend_vectorizer.transform([cleaned])
        return _friend_model.predict(vectorized)[0]
    except Exception:
        return None


# ─────────────────────────────────────────
# MAIN SCAN FUNCTION
# ─────────────────────────────────────────

def keyword_scan(message):
    """
    Scans message using keywords, tone, ML, and URL analysis.
    Returns: risk_level, total_score, matches, detected_tones
    """
    total_score    = 0
    matches        = []
    detected_tones = []

    # Step 1: URL analysis
    url_score, urls, url_flags = verify_links(message)
    if urls:
        total_score += url_score
        for flag in url_flags:
            matches.append({
                "phrase"  : flag,
                "weight"  : url_score,
                "category": "url_analysis"
            })

    # Step 2: Clean text
    message_clean = clean_text(message)

    # Step 3: ML prediction
    ml_result = predict_phishing(message_clean)
    if ml_result == "phishing":
        total_score += 45
        matches.append({
            "phrase"  : "Message pattern strongly matches known scam examples",
            "weight"  : 45,
            "category": "ml_model"
        })

    # Step 4: Keyword detection
    matched_phrases = set()
    for category, keywords in KEYWORDS.items():
        if category == "tone_detection":
            continue

        sorted_keywords = sorted(
            keywords.items(),
            key=lambda x: len(x[0]),
            reverse=True
        )

        for phrase, weight in sorted_keywords:
            pattern = r'\b' + re.escape(phrase.lower()) + r'\b'
            if re.search(pattern, message_clean):
                overlap = any(
                    phrase in matched or matched in phrase
                    for matched in matched_phrases
                )
                if overlap:
                    continue
                matched_phrases.add(phrase)
                total_score += weight
                matches.append({
                    "phrase"  : phrase,
                    "weight"  : weight,
                    "category": category
                })

    # Step 5: Tone detection
    tone_data = KEYWORDS["tone_detection"]
    for tone, words in tone_data.items():
        for word in words:
            pattern = r'\b' + re.escape(word.lower()) + r'\b'
            if re.search(pattern, message_clean):
                detected_tones.append(tone)
                total_score += 15
                break

    # Step 6: Risk classification
    if total_score >= 70:
        risk_level = "HIGH"
    elif total_score >= 40:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    return risk_level, total_score, matches, detected_tones