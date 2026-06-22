# GeniusTalk Backend API Documentation v2.0
# For Person 2 (Flutter Developer)
# Server: http://127.0.0.1:5000

---

## How to Start the Backend Server
Keep this terminal open while using Flutter.

---

## Standard Response Format
Every endpoint returns:
```json
{
  "success": true,
  "data": { ... },
  "error": null
}
```
On error:
```json
{
  "success": false,
  "data": null,
  "error": "Error message here"
}
```

---

## Risk Score System
| Score  | Label  | Colour | Action               |
|--------|--------|--------|----------------------|
| 0–39   | LOW    | Green  | Allow                |
| 40–69  | MEDIUM | Orange | Show warning         |
| 70–100 | HIGH   | Red    | Block + Alert user   |

---

## Language Translation
All text scan endpoints automatically:
1. Detect the message language
2. Translate to English if needed
3. Scan the English version
4. Return translation info alongside scan result

Supported languages include English, Chinese, Malay,
Hindi, Tamil, Arabic, Thai, Vietnamese, and more.

---

## ENDPOINT 1 — Health Check
**GET** `/health`

Response:
```json
{
  "success": true,
  "data": {
    "status": "running",
    "version": "2.0.0",
    "modules": ["file_inspector", "ocr_engine",
                "text_analyzer", "translator",
                "keyword_engine", "qr_scanner",
                "link_verifier"]
  }
}
```

---

## ENDPOINT 2 — Scan Text Message
**POST** `/scan/text`
**Content-Type:** application/json

Call this for every message sent or received.
Automatically translates non-English messages.

Request:
```json
{ "text": "message content here" }
```

Response:
```json
{
  "success": true,
  "data": {
    "risk_score": 87,
    "risk_label": "HIGH",
    "is_scam": true,
    "ml_score": 82,
    "matched_keywords": {
      "high": ["you won", "bank details"],
      "medium": [],
      "low": []
    },
    "suspicious_urls": [],
    "tone": {
      "tone_labels": ["HIGH URGENCY"],
      "tone_score": 30
    },
    "summary": "High risk keywords detected: you won, bank details",
    "source": "direct",
    "translation": {
      "original_text": "恭喜！您赢了！",
      "detected_language": "zh-cn",
      "language_name": "Chinese (Simplified)",
      "was_translated": true,
      "translation_note": "Message translated from Chinese (Simplified) for scanning"
    }
  }
}
```

Flutter usage:
- `is_scam == true` → show red warning banner
- `risk_label == MEDIUM` → show orange caution icon
- `was_translated == true` → show "Translated from X" label
- `risk_label == LOW` → show nothing

---

## ENDPOINT 3 — Scan File Attachment
**POST** `/scan/file`
**Content-Type:** multipart/form-data
**Field:** `file`

Call this BEFORE sending any file.

Response:
```json
{
  "success": true,
  "data": {
    "file_name": "document.pdf",
    "file_size_kb": 245.5,
    "extension": ".pdf",
    "mime_type": "application/pdf",
    "mismatch": false,
    "risk_score": 50,
    "risk_label": "MEDIUM",
    "is_blocked": false,
    "reason": "File is moderately suspicious"
  }
}
```

Flutter usage:
- `is_blocked == true` → block file, show red alert
- `risk_label == MEDIUM` → warn user, ask to confirm
- `risk_label == LOW` → allow normally

---

## ENDPOINT 4 — Scan Image (OCR)
**POST** `/scan/image`
**Content-Type:** multipart/form-data
**Field:** `image`

Extracts text from image then checks for scams.

Response:
```json
{
  "success": true,
  "data": {
    "ocr_success": true,
    "extracted_text": "Congratulations you win grand prize!",
    "image_properties": {
      "format": "PNG",
      "width": 865,
      "height": 484,
      "is_suspicious": false
    },
    "analysis": {
      "risk_score": 84,
      "risk_label": "HIGH",
      "is_scam": true,
      "summary": "High risk keywords detected"
    }
  }
}
```

Flutter usage:
- `analysis.is_scam == true` → overlay warning on image
- Show `extracted_text` so user knows what was detected

---

## ENDPOINT 5 — Full Scan (File + OCR)
**POST** `/scan/full`
**Content-Type:** multipart/form-data
**Field:** `file`

Runs file safety check AND text extraction together.

Response:
```json
{
  "success": true,
  "data": {
    "file_inspection": { "risk_score": 10, "is_blocked": false },
    "ocr_analysis": { "analysis": { "is_scam": true } },
    "should_block": true
  }
}
```

Flutter usage:
- `should_block == true` → block immediately

---

## ENDPOINT 6 — Keyword Scan
**POST** `/scan/keyword`
**Content-Type:** application/json

Uses keyword database + phishing ML model.
Good for double-checking suspicious messages.

Request:
```json
{ "text": "message here" }
```

Response:
```json
{
  "success": true,
  "data": {
    "risk_level": "HIGH",
    "score": 140,
    "is_scam": true,
    "matches": [
      { "phrase": "you won", "weight": 35, "category": "reward_scam" }
    ],
    "detected_tones": ["urgency"],
    "translation": {
      "detected_language": "en",
      "was_translated": false
    },
    "warning_message": "This message appears highly suspicious."
  }
}
```

---

## ENDPOINT 7 — QR Code Scan (Image)
**POST** `/scan/qr`
**Content-Type:** multipart/form-data
**Field:** `image`

Scans QR code image, decodes content, checks safety.

Response:
```json
{
  "success": true,
  "data": {
    "image_name": "qrcode.png",
    "qr_found": true,
    "qr_content": "https://bit.ly/free-prize",
    "analysis": {
      "content_type": "url",
      "risk_score": 100,
      "risk_label": "HIGH",
      "is_blocked": true,
      "flags": ["Shortened URL detected", "Phishing keyword: prize"]
    }
  }
}
```

Flutter usage:
- `qr_found == false` → show "No QR code detected"
- `analysis.is_blocked == true` → block, show HIGH risk alert
- `analysis.risk_label == MEDIUM` → warn before opening

---

## ENDPOINT 8 — QR Content Scan (Text)
**POST** `/scan/qr/content`
**Content-Type:** application/json

When Flutter decodes QR itself and sends content as text.

Request:
```json
{ "content": "https://bit.ly/free-prize" }
```

Response: same as `/scan/qr` analysis section.

---

## ENDPOINT 9 — Link Scanner
**POST** `/scan/link`
**Content-Type:** application/json

Checks if a URL is safe before user opens it.

Request:
```json
{ "text": "https://bit.ly/claim-prize" }
```

Response:
```json
{
  "success": true,
  "data": {
    "urls_found": ["https://bit.ly/claim-prize"],
    "risk_score": 65,
    "risk_label": "MEDIUM",
    "is_dangerous": false,
    "flags": ["Shortened URL detected", "Phishing keyword: claim"]
  }
}
```

---

## ENDPOINT 10 — Smart Scan (Best Accuracy)
**POST** `/scan/smart`
**Content-Type:** application/json

Runs BOTH ML models + keyword engine + translation.
Use this for maximum accuracy on suspicious messages.

Request:
```json
{ "text": "message here" }
```

Response:
```json
{
  "success": true,
  "data": {
    "combined_score": 95,
    "combined_label": "HIGH",
    "is_scam": true,
    "translation": {
      "detected_language": "zh-cn",
      "language_name": "Chinese (Simplified)",
      "was_translated": true
    },
    "your_analysis": { "risk_score": 87, "risk_label": "HIGH" },
    "keyword_analysis": { "risk_level": "HIGH", "score": 140 }
  }
}
```

Flutter usage:
- Use `combined_label` as the final verdict
- Show both scores if you want to display detail

---

## ADMIN ENDPOINTS

### GET `/admin/stats`
```json
{
  "data": {
    "total_scans": 42,
    "total_flagged": 8,
    "total_blocked": 3,
    "last_updated": "2026-06-06T10:00:00"
  }
}
```

### GET `/admin/flagged`
Returns all HIGH risk items for admin review screen.

### GET `/admin/history`
Returns all scan history for activity monitoring.

---

## Flutter Setup

Add to `pubspec.yaml`:
```yaml
dependencies:
  http: ^1.2.0
```

## Flutter Example — Scan text message
```dart
import 'package:http/http.dart' as http;
import 'dart:convert';

Future<Map<String, dynamic>> scanMessage(String text) async {
  final response = await http.post(
    Uri.parse('http://127.0.0.1:5000/scan/text'),
    headers: {'Content-Type': 'application/json'},
    body: jsonEncode({'text': text}),
  );
  final data = jsonDecode(response.body);
  return data['data'];
}

// Usage:
// final result = await scanMessage(messageText);
// if (result['is_scam'] == true) { showScamWarning(); }
// if (result['translation']['was_translated']) {
//   showTranslationBadge(result['translation']['language_name']);
// }
```

## Flutter Example — Scan file
```dart
Future<Map<String, dynamic>> scanFile(File file) async {
  final request = http.MultipartRequest(
    'POST',
    Uri.parse('http://127.0.0.1:5000/scan/file'),
  );
  request.files.add(
    await http.MultipartFile.fromPath('file', file.path)
  );
  final response = await request.send();
  final body     = await response.stream.bytesToString();
  final data     = jsonDecode(body);
  return data['data'];
}

// Usage:
// final result = await scanFile(selectedFile);
// if (result['is_blocked'] == true) { blockFileUpload(); }
```

## Flutter Example — Smart scan
```dart
Future<Map<String, dynamic>> smartScan(String text) async {
  final response = await http.post(
    Uri.parse('http://127.0.0.1:5000/scan/smart'),
    headers: {'Content-Type': 'application/json'},
    body: jsonEncode({'text': text}),
  );
  final data = jsonDecode(response.body);
  return data['data'];
}

// Usage:
// final result = await smartScan(messageText);
// final label  = result['combined_label'];
// final translated = result['translation']['was_translated'];
```