# utils/ocr_engine.py
# Image Text Detection Module
# Handles: image loading, OCR scanning, text extraction, image property checks

import os
import json
import platform
import pytesseract
from PIL import Image, ExifTags
import re

# ─────────────────────────────────────────
# TESSERACT PATH
# ─────────────────────────────────────────

# On Windows (local dev), point at the installed binary if present.
# On Linux (Docker/Render), tesseract is installed via apt-get in the
# Dockerfile and is already on PATH, so tesseract_cmd stays unset there.
if platform.system() == "Windows":
    _default_windows_path = r'C:\Program Files\Tesseract-OCR\tesseract.exe'
    if os.path.exists(_default_windows_path):
        pytesseract.pytesseract.tesseract_cmd = _default_windows_path


# ─────────────────────────────────────────
# SUPPORTED IMAGE FORMATS
# ─────────────────────────────────────────

SUPPORTED_FORMATS = {'.jpg', '.jpeg', '.png', '.bmp', '.gif', '.webp', '.tiff'}


# ─────────────────────────────────────────
# IMAGE PROPERTY CHECKER
# ─────────────────────────────────────────

def check_image_properties(image_path):
    """
    Checks basic image properties.
    Returns a dictionary with image metadata.
    Suspicious properties (e.g. hidden EXIF data, unusual dimensions) are flagged.
    """
    properties = {
        "format"         : None,
        "mode"           : None,
        "width"          : None,
        "height"         : None,
        "has_exif"       : False,
        "exif_data"      : {},
        "is_suspicious"  : False,
        "suspicion_reason": []
    }

    try:
        img = Image.open(image_path)
        properties["format"] = img.format
        properties["mode"]   = img.mode
        properties["width"]  = img.width
        properties["height"] = img.height

        # ── Check EXIF data ──
        # EXIF can contain hidden metadata — we log it for awareness
        try:
            exif_raw = img._getexif()
            if exif_raw:
                properties["has_exif"] = True
                # Convert EXIF tag numbers to readable names
                for tag_id, value in exif_raw.items():
                    tag_name = ExifTags.TAGS.get(tag_id, str(tag_id))
                    # Only store simple string/int values (skip binary blobs)
                    if isinstance(value, (str, int, float)):
                        properties["exif_data"][tag_name] = str(value)
        except (AttributeError, Exception):
            pass  # Not all images have EXIF — that's fine

        # ── Suspicion checks ──

        # Very tiny images can be used to hide text (steganography trick)
        if img.width < 50 or img.height < 50:
            properties["is_suspicious"] = True
            properties["suspicion_reason"].append("Image is unusually small — possible hidden content")

        # Extremely large images are unusual for messaging
        if img.width > 8000 or img.height > 8000:
            properties["is_suspicious"] = True
            properties["suspicion_reason"].append("Image is unusually large")

        # Images with no colour mode are suspicious
        if img.mode not in ('RGB', 'RGBA', 'L', 'P', 'CMYK'):
            properties["is_suspicious"] = True
            properties["suspicion_reason"].append(f"Unusual image colour mode: {img.mode}")

    except Exception as e:
        properties["is_suspicious"] = True
        properties["suspicion_reason"].append(f"Could not read image properties: {str(e)}")

    return properties


# ─────────────────────────────────────────
# TEXT CLEANER
# ─────────────────────────────────────────

def clean_extracted_text(raw_text):
    """
    Cleans up raw OCR output.
    Tesseract sometimes returns messy text with extra spaces/newlines.
    This makes it ready for the AI text analyzer.
    """
    if not raw_text:
        return ""

    # Remove extra whitespace and blank lines
    lines = raw_text.splitlines()
    cleaned_lines = [line.strip() for line in lines if line.strip()]
    cleaned = " ".join(cleaned_lines)

    # Remove non-printable characters
    cleaned = re.sub(r'[^\x20-\x7E\n]', '', cleaned)

    # Collapse multiple spaces into one
    cleaned = re.sub(r' +', ' ', cleaned)

    return cleaned.strip()


# ─────────────────────────────────────────
# MAIN OCR FUNCTION
# ─────────────────────────────────────────

def scan_image(image_path):
    """
    Main function — scans an image and extracts all text from it.

    Returns a dictionary with:
    - image_name        : filename
    - supported         : whether format is supported
    - extracted_text    : cleaned text found in the image
    - text_length       : how many characters were found
    - has_text          : True if any text was detected
    - image_properties  : metadata about the image
    - ready_for_analysis: True if text should be sent to AI analyzer
    - error             : any error message (if failed)
    """

    result = {
        "image_name"        : os.path.basename(image_path),
        "supported"         : False,
        "extracted_text"    : "",
        "text_length"       : 0,
        "has_text"          : False,
        "image_properties"  : {},
        "ready_for_analysis": False,
        "error"             : None
    }

    # ── Check file exists ──
    if not os.path.exists(image_path):
        result["error"] = "Image file not found"
        return result

    # ── Check format is supported ──
    _, ext = os.path.splitext(image_path)
    if ext.lower() not in SUPPORTED_FORMATS:
        result["error"] = f"Unsupported image format: {ext}"
        return result

    result["supported"] = True

    # ── Check image properties first ──
    result["image_properties"] = check_image_properties(image_path)

    # ── Run OCR ──
    try:
        img = Image.open(image_path)

        # Convert to RGB if needed (Tesseract works best with RGB)
        if img.mode not in ('RGB', 'L'):
            img = img.convert('RGB')

        # Extract text using Tesseract
        # config: --psm 3 = automatic page segmentation (best for mixed content)
        raw_text = pytesseract.image_to_string(
            img,
            config='--psm 3 --oem 3'
        )

        # Clean the text
        cleaned_text = clean_extracted_text(raw_text)

        result["extracted_text"] = cleaned_text
        result["text_length"]    = len(cleaned_text)
        result["has_text"]       = len(cleaned_text) > 5  # at least 5 chars = real text

        # Ready for AI analysis if text was found
        result["ready_for_analysis"] = result["has_text"]

    except Exception as e:
        result["error"] = f"OCR failed: {str(e)}"

    return result


# ─────────────────────────────────────────
# BATCH SCAN (scan multiple images at once)
# ─────────────────────────────────────────

def scan_multiple_images(image_paths):
    """
    Scans a list of images and returns results for each.
    Useful when a user sends multiple images in one message.
    """
    results = []
    for path in image_paths:
        results.append(scan_image(path))
    return results


# ─────────────────────────────────────────
# QUICK TEST
# ─────────────────────────────────────────

if __name__ == "__main__":
    import sys

    if len(sys.argv) > 1:
        # Test with a real image passed as argument
        result = scan_image(sys.argv[1])
    else:
        # Create a simple test image with text drawn on it
        from PIL import ImageDraw, ImageFont

        print("Creating test image with text...")
        os.makedirs("test_files", exist_ok=True)

        # Create a white image
        img = Image.new('RGB', (400, 200), color='white')
        draw = ImageDraw.Draw(img)

        # Draw some scam-like text on it
        draw.text((20, 50),  "Congratulations! You won RM10,000!", fill='black')
        draw.text((20, 90),  "Click this link: bit.ly/claim-prize", fill='black')
        draw.text((20, 130), "Send your bank details NOW!", fill='black')

        test_image_path = "test_files/test_scam_image.png"
        img.save(test_image_path)
        print(f"Test image saved to: {test_image_path}")

        result = scan_image(test_image_path)

    print(json.dumps(result, indent=2))