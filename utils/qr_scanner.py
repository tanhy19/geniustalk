# utils/qr_scanner.py
# QR Code Scanner Module
# Handles: QR decoding, content analysis, link verification

import os
import cv2
import numpy as np
from PIL import Image
try:
    from utils.link_verifier import verify_links, analyze_url, expand_url
except ImportError:
    from link_verifier import verify_links, analyze_url, expand_url


def _load_image_for_cv2(image_path):
    """Load image for OpenCV; fallback to PIL for formats OpenCV may miss."""
    img = cv2.imread(image_path)
    if img is not None:
        return img

    try:
        pil_img = Image.open(image_path).convert("RGB")
        rgb = np.array(pil_img)
        return cv2.cvtColor(rgb, cv2.COLOR_RGB2BGR)
    except Exception:
        return None


def decode_qr(image_path):
    """Decodes QR code from image using OpenCV. Returns content string or None."""

    def _normalize_data(data):
        if isinstance(data, bytes):
            try:
                return data.decode("utf-8", errors="ignore").strip()
            except Exception:
                return None
        if isinstance(data, str):
            return data.strip() or None
        return None

    def _decode_once(detector, img_variant):
        # 1) Standard single-QR path
        data, _, _ = detector.detectAndDecode(img_variant)
        normalized = _normalize_data(data)
        if normalized:
            return normalized

        # 2) Multi-QR path: return the first non-empty payload
        try:
            ok, decoded_info, _, _ = detector.detectAndDecodeMulti(img_variant)
            if ok and decoded_info:
                for item in decoded_info:
                    normalized = _normalize_data(item)
                    if normalized:
                        return normalized
        except Exception:
            pass

        # 3) Curved QR path (supported in newer OpenCV builds)
        try:
            data, _, _ = detector.detectAndDecodeCurved(img_variant)
            normalized = _normalize_data(data)
            if normalized:
                return normalized
        except Exception:
            pass

        return None

    try:
        img = _load_image_for_cv2(image_path)
        if img is None:
            return None

        detector = cv2.QRCodeDetector()

        # Try original image first for speed.
        data = _decode_once(detector, img)
        if data:
            return data

        # Real-world QR photos often fail due to blur/lighting/skew.
        # Try robust grayscale + contrast + threshold + resizing variants.
        gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
        variants = [
            gray,
            cv2.equalizeHist(gray),
            cv2.GaussianBlur(gray, (3, 3), 0),
            cv2.adaptiveThreshold(
                gray,
                255,
                cv2.ADAPTIVE_THRESH_GAUSSIAN_C,
                cv2.THRESH_BINARY,
                31,
                2,
            ),
        ]

        for scale in (1.5, 2.0, 3.0):
            resized = cv2.resize(gray, None, fx=scale, fy=scale, interpolation=cv2.INTER_CUBIC)
            variants.append(resized)
            variants.append(cv2.equalizeHist(resized))

        kernel = np.ones((3, 3), np.uint8)
        variants.append(cv2.morphologyEx(gray, cv2.MORPH_CLOSE, kernel))

        for variant in variants:
            data = _decode_once(detector, variant)
            if data:
                return data

        return None
    except Exception as e:
        print(f"[decode_qr] failed: {e}")
        return None

def analyze_qr_content(qr_content):
    """
    Analyzes QR code content for safety.
    Returns risk score, label, flags and block decision.
    """
    result = {
        "content"      : qr_content,
        "content_type" : "unknown",
        "risk_score"   : 0,
        "risk_label"   : "LOW",
        "is_blocked"   : False,
        "flags"        : [],
        "expanded_url" : None
    }

    if not qr_content:
        return result

    content_lower = qr_content.lower()

    if content_lower.startswith("http"):
        result["content_type"] = "url"
    elif content_lower.startswith("tel:"):
        result["content_type"] = "phone"
    elif content_lower.startswith("mailto:"):
        result["content_type"] = "email"
    elif content_lower.startswith("smsto:") or content_lower.startswith("sms:"):
        result["content_type"] = "sms"
    else:
        result["content_type"] = "text"

    if result["content_type"] == "url":
        expanded               = expand_url(qr_content)
        result["expanded_url"] = expanded
        score, flags           = analyze_url(expanded)
        result["risk_score"]   = min(score, 100)
        result["flags"].extend(flags)

        link_score, _, link_flags = verify_links(qr_content)
        result["risk_score"] = min(result["risk_score"] + link_score, 100)
        result["flags"].extend(link_flags)

    elif result["content_type"] in ("phone", "sms"):
        number = qr_content.replace("tel:", "").replace("smsto:", "").replace("sms:", "")
        if any(number.startswith(p) for p in ["190", "1900", "900"]):
            result["risk_score"] += 60
            result["flags"].append("Premium rate number detected")
        else:
            result["risk_score"] += 20
            result["flags"].append("QR contains phone number — verify before calling")

    elif result["content_type"] == "text":
        link_score, urls, link_flags = verify_links(qr_content)
        if urls:
            result["risk_score"] += link_score
            result["flags"].extend(link_flags)
            result["content_type"] = "text_with_url"

        suspicious_words = [
            "prize", "winner", "claim", "free", "reward",
            "verify", "login", "password", "bank", "urgent"
        ]
        for word in suspicious_words:
            if word in content_lower:
                result["risk_score"] += 10
                result["flags"].append(f"Suspicious word in QR: {word}")

    score = result["risk_score"]
    if score >= 70:
        result["risk_label"] = "HIGH"
        result["is_blocked"] = True
    elif score >= 40:
        result["risk_label"] = "MEDIUM"
    else:
        result["risk_label"] = "LOW"

    result["flags"] = list(set(result["flags"]))
    return result


def scan_qr(image_path):
    """
    Main function — scans QR image and returns full safety report.
    """
    result = {
        "image_name": os.path.basename(image_path),
        "qr_found"  : False,
        "qr_content": None,
        "analysis"  : None,
        "error"     : None
    }

    if not os.path.exists(image_path):
        result["error"] = "Image file not found"
        return result

    qr_content = decode_qr(image_path)

    if qr_content is None:
        result["error"] = "No QR code detected in image"
        return result

    result["qr_found"]   = True
    result["qr_content"] = qr_content
    result["analysis"]   = analyze_qr_content(qr_content)
    return result