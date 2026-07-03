# utils/translator.py
# Language Detection + Translation Module
# Detects message language and translates to English before scanning
# Uses deep-translator (free, no API key needed, needs internet)

from deep_translator import GoogleTranslator
from langdetect import detect, LangDetectException

# ─────────────────────────────────────────
# SUPPORTED LANGUAGES (for reference)
# ─────────────────────────────────────────

LANGUAGE_NAMES = {
    "en": "English",
    "zh-cn": "Chinese (Simplified)",
    "zh-tw": "Chinese (Traditional)",
    "ms": "Malay",
    "hi": "Hindi",
    "ta": "Tamil",
    "ar": "Arabic",
    "th": "Thai",
    "vi": "Vietnamese",
    "id": "Indonesian",
    "ko": "Korean",
    "ja": "Japanese",
    "fr": "French",
    "de": "German",
    "es": "Spanish",
    "pt": "Portuguese",
    "ru": "Russian",
}

# ─────────────────────────────────────────
# LANGUAGE DETECTOR
# ─────────────────────────────────────────

def detect_language(text):
    """
    Detects the language of a text message.
    Returns language code (e.g. 'en', 'zh-cn', 'ms')
    """
    try:
        if not text or len(text.strip()) < 5:
            return "en"  # Too short to detect — assume English

        lang_code = detect(text)
        return lang_code

    except LangDetectException:
        return "en"  # Default to English if detection fails

    except Exception:
        return "en"


def get_language_name(lang_code):
    """Returns human readable language name from code."""
    return LANGUAGE_NAMES.get(lang_code, f"Unknown ({lang_code})")


# ─────────────────────────────────────────
# TRANSLATOR
# ─────────────────────────────────────────

def translate_to_english(text, source_lang="auto"):
    """
    Translates any language text to English.
    Returns translated text or original if translation fails.

    Parameters:
    - text        : the message to translate
    - source_lang : language code or 'auto' for auto detection
    """
    try:
        if not text or len(text.strip()) < 2:
            return text

        translated = GoogleTranslator(
            source=source_lang,
            target='en'
        ).translate(text)

        return translated if translated else text

    except Exception as e:
        # If translation fails, return original text
        # Scam scanner will still work, just less accurate
        print(f"Translation warning: {e}")
        return text


# ─────────────────────────────────────────
# MAIN FUNCTION — DETECT + TRANSLATE
# ─────────────────────────────────────────

def prepare_text_for_scanning(text):
    """
    Main function — detects language, translates to English if needed.
    Returns everything the scanner needs.

    Returns a dictionary with:
    - original_text    : the original message
    - translated_text  : English version (same as original if already English)
    - detected_language: language code
    - language_name    : human readable language name
    - was_translated   : True if translation was performed
    - translation_note : message for Flutter to show user
    """
    result = {
        "original_text"    : text,
        "translated_text"  : text,
        "detected_language": "en",
        "language_name"    : "English",
        "was_translated"   : False,
        "translation_note" : None
    }

    if not text or len(text.strip()) < 5:
        return result

    # Step 1 — Detect language
    lang_code   = detect_language(text)
    lang_name   = get_language_name(lang_code)

    result["detected_language"] = lang_code
    result["language_name"]     = lang_name

    # Step 2 — Translate if not English
    if lang_code != "en":
        translated = translate_to_english(text)
        result["translated_text"] = translated
        result["was_translated"]  = True
        result["translation_note"] = f"Message translated from {lang_name} for scanning"
    else:
        result["translation_note"] = "Message is in English — no translation needed"

    return result


# ─────────────────────────────────────────
# QUICK TEST
# ─────────────────────────────────────────

if __name__ == "__main__":
    import json

    test_messages = [
        # English
        "Congratulations! You won RM10,000! Send bank details now!",
        # Chinese scam
        "恭喜您！您已被选中获得RM10000奖励！请立即点击链接领取",
        # Malay scam
        "Tahniah! Anda telah menang RM5000! Klik pautan untuk tuntut hadiah anda sekarang!",
        # Tamil
        "வாழ்த்துகள்! நீங்கள் RM10000 வெற்றி பெற்றீர்கள்! உங்கள் வங்கி விவரங்களை அனுப்புங்கள்",
        # Hindi
        "बधाई हो! आपने RM10000 जीता है! अभी अपने बैंक विवरण भेजें",
        # Normal English
        "Hey are you free tomorrow for lunch?",
    ]

    for msg in test_messages:
        print("=" * 55)
        print(f"ORIGINAL : {msg[:55]}")
        result = prepare_text_for_scanning(msg)
        print(f"LANGUAGE : {result['language_name']} ({result['detected_language']})")
        print(f"TRANSLATED: {result['was_translated']}")
        if result['was_translated']:
            print(f"ENGLISH  : {result['translated_text'][:55]}")
        print()