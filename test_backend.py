# test_backend.py
# GeniusTalk Backend Test Interface
# Run this on ANY computer to test all endpoints
# Usage: python test_backend.py

import requests
import json
import os
import sys

SERVER_IP   = "127.0.0.1"
SERVER_PORT = "5000"
BASE_URL = "https://geniustalk-backend.onrender.com"

# Allow passing Render URL as argument
if len(sys.argv) > 1:
    BASE_URL = sys.argv[1].rstrip('/')
    print(f"Using server: {BASE_URL}")


# ─────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────

def print_header(title):
    print("\n" + "=" * 55)
    print(f"  {title}")
    print("=" * 55)


def print_result(response):
    try:
        data = response.json()
        print(json.dumps(data, indent=2))
    except Exception:
        print(response.text)


def post_json(endpoint, body):
    try:
        r = requests.post(
            f"{BASE_URL}{endpoint}",
            json=body,
            timeout=60
        )
        print_result(r)
    except requests.exceptions.ConnectionError:
        print(f"❌ Cannot connect to {BASE_URL}")
        print("   Make sure the server is running.")
    except Exception as e:
        print(f"❌ Error: {e}")


def get_endpoint(endpoint):
    try:
        r = requests.get(
            f"{BASE_URL}{endpoint}",
            timeout=15
        )
        print_result(r)
    except requests.exceptions.ConnectionError:
        print(f"❌ Cannot connect to {BASE_URL}")
        print("   Make sure the server is running.")
    except Exception as e:
        print(f"❌ Error: {e}")


def post_file(endpoint, field, file_path):
    try:
        if not os.path.exists(file_path):
            print(f"❌ File not found: {file_path}")
            return
        with open(file_path, 'rb') as f:
            r = requests.post(
                f"{BASE_URL}{endpoint}",
                files={field: f},
                timeout=15
            )
        print_result(r)
    except requests.exceptions.ConnectionError:
        print(f"❌ Cannot connect to {BASE_URL}")
    except Exception as e:
        print(f"❌ Error: {e}")


# ─────────────────────────────────────────
# TEST FUNCTIONS
# ─────────────────────────────────────────

def test_health():
    print_header("HEALTH CHECK")
    get_endpoint("/health")


def test_scan_text():
    print_header("SCAN TEXT MESSAGE")
    print("Enter a message to scan (or press Enter for default test):")
    msg = input("> ").strip()
    if not msg:
        msg = "URGENT! You won RM10,000! Send bank details now!"
        print(f"Using default: {msg}")
    post_json("/scan/text", {"text": msg})


def test_scan_text_chinese():
    print_header("SCAN CHINESE MESSAGE")
    msg = "恭喜您！您已被选中获得RM10000奖励！请立即点击链接领取"
    print(f"Testing: {msg}")
    post_json("/scan/text", {"text": msg})


def test_scan_text_safe():
    print_header("SCAN SAFE MESSAGE")
    msg = "Hey are you free tomorrow for lunch?"
    print(f"Testing: {msg}")
    post_json("/scan/text", {"text": msg})


def test_scan_keyword():
    print_header("KEYWORD ENGINE SCAN")
    print("Enter a message to scan (or press Enter for default):")
    msg = input("> ").strip()
    if not msg:
        msg = "Congratulations! You won RM5000 lucky draw prize!"
        print(f"Using default: {msg}")
    post_json("/scan/keyword", {"text": msg})


def test_scan_smart():
    print_header("SMART SCAN (Both ML Models)")
    print("Enter a message to scan (or press Enter for default):")
    msg = input("> ").strip()
    if not msg:
        msg = "Your account will be suspended! Verify at bit.ly/verify-now"
        print(f"Using default: {msg}")
    post_json("/scan/smart", {"text": msg})


def test_scan_file():
    print_header("SCAN FILE")
    print("Enter file path (or press Enter for default test):")
    print("Default will test: test_files/virus.exe")
    path = input("> ").strip()
    if not path:
        path = "test_files/virus.exe"
    post_file("/scan/file", "file", path)


def test_scan_safe_file():
    print_header("SCAN SAFE FILE")
    path = "test_files/test_sample.txt"
    print(f"Testing: {path}")
    post_file("/scan/file", "file", path)


def test_scan_image():
    print_header("SCAN IMAGE (OCR)")
    print("Enter image path (or press Enter for default):")
    print("Default will test: test_files/test1.png")
    path = input("> ").strip()
    if not path:
        path = "test_files/test1.png"
    post_file("/scan/image", "image", path)


def test_scan_full():
    print_header("FULL SCAN (File + OCR)")
    print("Enter image path (or press Enter for default):")
    path = input("> ").strip()
    if not path:
        path = "test_files/test1.png"
    post_file("/scan/full", "file", path)


def test_scan_link():
    print_header("SCAN LINK")
    print("Enter URL or text with link (or press Enter for default):")
    text = input("> ").strip()
    if not text:
        text = "Click here: bit.ly/free-prize-claim"
        print(f"Using default: {text}")
    post_json("/scan/link", {"text": text})


def test_scan_qr_content():
    print_header("SCAN QR CONTENT")
    print("Enter QR content/URL (or press Enter for default):")
    content = input("> ").strip()
    if not content:
        content = "https://bit.ly/free-prize-claim"
        print(f"Using default: {content}")
    post_json("/scan/qr/content", {"content": content})


def test_report_message():
    print_header("REPORT MESSAGE")
    print("Enter message to report (or press Enter for default):")
    msg = input("> ").strip()
    if not msg:
        msg = "You won RM10000! Send bank details now!"
        print(f"Using default: {msg}")
    print("Enter your user ID (or press Enter for 'testuser'):")
    user = input("> ").strip() or "testuser"
    post_json("/report/message", {
        "reported_by"    : user,
        "message_content": msg,
        "reason"         : "Suspected scam message",
        "risk_score"     : 85
    })


def test_report_user():
    print_header("REPORT USER")
    print("Enter user ID to report (or press Enter for 'scammer123'):")
    target = input("> ").strip() or "scammer123"
    print("Enter your user ID (or press Enter for 'testuser'):")
    reporter = input("> ").strip() or "testuser"
    post_json("/report/user", {
        "reported_by"  : reporter,
        "reported_user": target,
        "reason"       : "Sending scam messages repeatedly"
    })


def test_ban_user():
    print_header("BAN USER")
    print("Enter user ID to ban (or press Enter for 'scammer123'):")
    user = input("> ").strip() or "scammer123"
    print("Ban type — enter 'temporary' or 'permanent' (default: temporary):")
    ban_type = input("> ").strip() or "temporary"
    post_json("/admin/ban", {
        "user_id"   : user,
        "ban_type"  : ban_type,
        "reason"    : "Repeated scam message sending",
        "expires_at": "2026-08-01" if ban_type == "temporary" else None
    })


def test_check_ban():
    print_header("CHECK BAN STATUS")
    print("Enter user ID to check (or press Enter for 'scammer123'):")
    user = input("> ").strip() or "scammer123"
    get_endpoint(f"/admin/check-ban/{user}")


def test_unban_user():
    print_header("UNBAN USER")
    print("Enter user ID to unban (or press Enter for 'scammer123'):")
    user = input("> ").strip() or "scammer123"
    post_json("/admin/unban", {"user_id": user})


def test_trust_score():
    print_header("VIEW TRUST SCORE")
    print("Enter user ID (or press Enter for 'scammer123'):")
    user = input("> ").strip() or "scammer123"
    get_endpoint(f"/user/trust/{user}")


def test_create_alert():
    print_header("CREATE SECURITY ALERT")
    print("Enter alert title (or press Enter for default):")
    title = input("> ").strip() or "QR Code Scam Warning"
    print("Enter alert message (or press Enter for default):")
    msg = input("> ").strip() or "Beware of fake QR codes at petrol stations and malls"
    print("Severity — low/medium/high/critical (default: high):")
    severity = input("> ").strip() or "high"
    post_json("/awareness/alert", {
        "title"   : title,
        "message" : msg,
        "severity": severity
    })


def test_get_alerts():
    print_header("VIEW ACTIVE ALERTS")
    get_endpoint("/awareness/alerts")


def test_create_drill():
    print_header("CREATE PHISHING DRILL")
    print("Enter drill title (or press Enter for default):")
    title = input("> ").strip() or "Maybank Phishing Test"
    print("Enter drill message (or press Enter for default):")
    msg = input("> ").strip() or \
        "URGENT! Your Maybank account is suspended! Verify at bit.ly/maybank-verify NOW!"
    post_json("/awareness/drill", {
        "title"        : title,
        "drill_message": msg,
        "target_user"  : "all"
    })


def test_drill_result():
    print_header("SUBMIT DRILL RESULT")
    print("Enter drill ID (or press Enter for '1'):")
    drill_id = input("> ").strip() or "1"
    print("Did user PASS the drill? (y/n, default: y):")
    passed = input("> ").strip().lower() != "n"
    post_json(f"/awareness/drill/{drill_id}/result", {"passed": passed})


def test_get_drills():
    print_header("VIEW ALL DRILLS")
    get_endpoint("/awareness/drills")


def test_add_tip():
    print_header("ADD SAFETY TIP")
    print("Category (phishing/malware/qr_scam/general, default: phishing):")
    cat = input("> ").strip() or "phishing"
    print("Enter tip title (or press Enter for default):")
    title = input("> ").strip() or "Never share your OTP"
    print("Enter tip content (or press Enter for default):")
    content = input("> ").strip() or \
        "No legitimate bank or government agency will ever ask for your OTP via SMS or call."
    post_json("/awareness/tip", {
        "category"  : cat,
        "title"     : title,
        "content"   : content
    })


def test_get_tips():
    print_header("VIEW SAFETY TIPS")
    print("Filter by category? (phishing/malware/qr_scam/general or press Enter for all):")
    cat = input("> ").strip()
    endpoint = f"/awareness/tips?category={cat}" if cat else "/awareness/tips"
    get_endpoint(endpoint)


def test_submit_feedback():
    print_header("SUBMIT USER FEEDBACK")
    print("Enter user ID (or press Enter for 'testuser'):")
    user = input("> ").strip() or "testuser"
    print("Enter feedback message (or press Enter for default):")
    msg = input("> ").strip() or "The scam detection is very accurate and helpful!"
    print("Rating 1-5 (or press Enter for 5):")
    rating_input = input("> ").strip()
    rating = int(rating_input) if rating_input.isdigit() else 5
    print("Type (general/false_positive/false_negative/suggestion, default: general):")
    ftype = input("> ").strip() or "general"
    post_json("/awareness/feedback", {
        "user_id"      : user,
        "message"      : msg,
        "feedback_type": ftype,
        "rating"       : rating
    })


def test_get_feedback():
    print_header("VIEW USER FEEDBACK")
    get_endpoint("/awareness/feedback/all")


def test_admin_stats():
    print_header("ADMIN STATS")
    get_endpoint("/admin/stats")


def test_admin_flagged():
    print_header("ADMIN FLAGGED ITEMS")
    get_endpoint("/admin/flagged")


def test_admin_history():
    print_header("ADMIN SCAN HISTORY")
    get_endpoint("/admin/history")


def test_admin_banned():
    print_header("ADMIN BANNED LIST")
    get_endpoint("/admin/banned")


def test_admin_reports():
    print_header("ADMIN PENDING REPORTS")
    get_endpoint("/admin/reports")


def test_admin_qr_history():
    print_header("QR SCAN HISTORY")
    get_endpoint("/admin/qr-history")


# ─────────────────────────────────────────
# RUN ALL TESTS AUTOMATICALLY
# ─────────────────────────────────────────

def run_all_tests():
    print_header("RUNNING ALL TESTS AUTOMATICALLY")
    print("This will test all endpoints with default values.")
    print("No input needed — just watch the results.\n")

    tests = [
        ("Health Check",          lambda: get_endpoint("/health")),
        ("Scan English Scam",     lambda: post_json("/scan/text", {"text": "URGENT! You won RM10000! Send bank details now!"})),
        ("Scan Safe Message",     lambda: post_json("/scan/text", {"text": "Hey are you free tomorrow for lunch?"})),
        ("Scan Keyword Engine",   lambda: post_json("/scan/keyword", {"text": "Congratulations! Lucky draw winner RM5000!"})),
        ("Smart Scan",            lambda: post_json("/scan/smart", {"text": "Your account suspended! Verify at bit.ly/verify"})),
        ("Scan Link",             lambda: post_json("/scan/link", {"text": "bit.ly/free-prize-claim"})),
        ("Scan QR Content",       lambda: post_json("/scan/qr/content", {"content": "https://bit.ly/free-prize"})),
        ("Report Message",        lambda: post_json("/report/message", {"reported_by": "auto_test", "message_content": "Win RM10000!", "reason": "Scam", "risk_score": 90})),
        ("Report User",           lambda: post_json("/report/user", {"reported_by": "auto_test", "reported_user": "bad_user", "reason": "Scam messages"})),
        ("Ban User",              lambda: post_json("/admin/ban", {"user_id": "bad_user", "ban_type": "temporary", "reason": "Scam", "expires_at": "2026-08-01"})),
        ("Check Ban",             lambda: get_endpoint("/admin/check-ban/bad_user")),
        ("Trust Score",           lambda: get_endpoint("/user/trust/bad_user")),
        ("Create Alert",          lambda: post_json("/awareness/alert", {"title": "Test Alert", "message": "This is a test", "severity": "medium"})),
        ("Get Alerts",            lambda: get_endpoint("/awareness/alerts")),
        ("Create Drill",          lambda: post_json("/awareness/drill", {"title": "Test Drill", "drill_message": "URGENT! Verify your account!"})),
        ("Drill Result Pass",     lambda: post_json("/awareness/drill/1/result", {"passed": True})),
        ("Add Safety Tip",        lambda: post_json("/awareness/tip", {"category": "general", "title": "Stay Safe", "content": "Never share OTP"})),
        ("Get Tips",              lambda: get_endpoint("/awareness/tips")),
        ("Submit Feedback",       lambda: post_json("/awareness/feedback", {"user_id": "auto_test", "message": "Great app!", "rating": 5})),
        ("Get Feedback",          lambda: get_endpoint("/awareness/feedback/all")),
        ("Admin Stats",           lambda: get_endpoint("/admin/stats")),
        ("Admin Flagged",         lambda: get_endpoint("/admin/flagged")),
        ("Admin History",         lambda: get_endpoint("/admin/history")),
        ("Admin Banned",          lambda: get_endpoint("/admin/banned")),
        ("Admin Reports",         lambda: get_endpoint("/admin/reports")),
    ]

    passed = 0
    failed = 0

    for name, test_fn in tests:
        print(f"\n▶ Testing: {name}")
        print("-" * 40)
        try:
            test_fn()
            passed += 1
        except Exception as e:
            print(f"❌ FAILED: {e}")
            failed += 1

    print("\n" + "=" * 55)
    print(f" AUTO TEST COMPLETE")
    print(f" Passed : {passed}/{len(tests)}")
    print(f" Failed : {failed}/{len(tests)}")
    print("=" * 55)


# ─────────────────────────────────────────
# MAIN MENU
# ─────────────────────────────────────────

def main():
    print("\n" + "=" * 55)
    print(" GENIUSTALK BACKEND TEST INTERFACE")
    print(f" Server: {BASE_URL}")
    print("=" * 55)

    menu = {
        # Health
        "0" : ("Health Check",               test_health),

        # Text scanning
        "1" : ("Scan Text (custom input)",    test_scan_text),
        "2" : ("Scan English Scam (default)", lambda: post_json("/scan/text", {"text": "URGENT! You won RM10000! Send bank details now!"})),
        "3" : ("Scan Chinese Scam",           test_scan_text_chinese),
        "4" : ("Scan Safe Message",           test_scan_text_safe),
        "5" : ("Keyword Engine Scan",         test_scan_keyword),
        "6" : ("Smart Scan (Both Models)",    test_scan_smart),

        # File scanning
        "7" : ("Scan File (custom path)",     test_scan_file),
        "8" : ("Scan Dangerous File (exe)",   lambda: post_file("/scan/file", "file", "test_files/virus.exe")),
        "9" : ("Scan Safe File (txt)",        test_scan_safe_file),

        # Image scanning
        "10": ("Scan Image OCR",              test_scan_image),
        "11": ("Full Scan (File + OCR)",      test_scan_full),

        # Link and QR
        "12": ("Scan Link",                   test_scan_link),
        "13": ("Scan QR Content",             test_scan_qr_content),

        # Community Defense
        "14": ("Report Message",              test_report_message),
        "15": ("Report User",                 test_report_user),
        "16": ("Ban User",                    test_ban_user),
        "17": ("Unban User",                  test_unban_user),
        "18": ("Check Ban Status",            test_check_ban),
        "19": ("View Trust Score",            test_trust_score),

        # Awareness
        "20": ("Create Security Alert",       test_create_alert),
        "21": ("View Active Alerts",          test_get_alerts),
        "22": ("Create Phishing Drill",       test_create_drill),
        "23": ("Submit Drill Result",         test_drill_result),
        "24": ("View All Drills",             test_get_drills),
        "25": ("Add Safety Tip",              test_add_tip),
        "26": ("View Safety Tips",            test_get_tips),
        "27": ("Submit User Feedback",        test_submit_feedback),
        "28": ("View User Feedback",          test_get_feedback),

        # Admin
        "29": ("Admin Stats",                 test_admin_stats),
        "30": ("Admin Flagged Items",         test_admin_flagged),
        "31": ("Admin Scan History",          test_admin_history),
        "32": ("Admin Banned List",           test_admin_banned),
        "33": ("Admin Pending Reports",       test_admin_reports),
        "34": ("QR Scan History",             test_admin_qr_history),

        # Auto
        "A" : ("Run ALL Tests Automatically", run_all_tests),
    }

    while True:
        print("\n" + "─" * 55)
        print(" MENU — Enter number to test, A for all, Q to quit")
        print("─" * 55)

        # Print menu in columns
        print("\n [SCANNING]")
        for k in ["0","1","2","3","4","5","6"]:
            print(f"   {k:>2}. {menu[k][0]}")

        print("\n [FILE & IMAGE]")
        for k in ["7","8","9","10","11"]:
            print(f"   {k:>2}. {menu[k][0]}")

        print("\n [LINK & QR]")
        for k in ["12","13"]:
            print(f"   {k:>2}. {menu[k][0]}")

        print("\n [COMMUNITY DEFENSE]")
        for k in ["14","15","16","17","18","19"]:
            print(f"   {k:>2}. {menu[k][0]}")

        print("\n [AWARENESS & EDUCATION]")
        for k in ["20","21","22","23","24","25","26","27","28"]:
            print(f"   {k:>2}. {menu[k][0]}")

        print("\n [ADMIN]")
        for k in ["29","30","31","32","33","34"]:
            print(f"   {k:>2}. {menu[k][0]}")

        print("\n   A. Run ALL Tests Automatically")
        print("   Q. Quit")

        choice = input("\nEnter choice: ").strip().upper()

        if choice == "Q":
            print("\nGoodbye!")
            break
        elif choice in menu:
            menu[choice][1]()
        else:
            print("Invalid choice. Try again.")


if __name__ == "__main__":
    # Check if server IP was passed as argument
    if len(sys.argv) > 1:
        SERVER_IP = "127.0.0.1"
        BASE_URL  = f"http://{SERVER_IP}:{SERVER_PORT}"
        print(f"Using server: {BASE_URL}")
    main()