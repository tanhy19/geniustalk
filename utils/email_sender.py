import os
import requests


BREVO_API_URL = 'https://api.brevo.com/v3/smtp/email'


def _send_otp_email(recipient_email, otp_code, expires_at=None, purpose='unlock'):
    """
    Shared Brevo API sender for both unlock-account OTPs and login-MFA OTPs.
    Required env vars:
      BREVO_API_KEY, BREVO_FROM_EMAIL
    """
    api_key = (os.getenv('BREVO_API_KEY') or '').strip()
    from_email = (os.getenv('BREVO_FROM_EMAIL') or '').strip()
    from_name = (os.getenv('BREVO_FROM_NAME') or 'GeniusTalk Security').strip()

    if not api_key or not from_email:
        return {
            'success': False,
            'error': 'Email service is not configured (BREVO_API_KEY/BREVO_FROM_EMAIL).',
        }

    recipient = (recipient_email or '').strip().lower()
    if not recipient:
        return {'success': False, 'error': 'Recipient email is required.'}

    if purpose == 'login':
        subject = 'GeniusTalk Login Verification Code'
        intro = 'A login to your GeniusTalk account requires verification.'
    else:
        subject = 'GeniusTalk Account Unlock OTP'
        intro = 'We received a request to unlock your GeniusTalk account.'

    body_lines = [intro, '', f'Your verification code is: {otp_code}']
    if expires_at:
        body_lines.append(f'This code expires at: {expires_at}')
    body_lines.extend([
        '',
        'If this was not you, please ignore this email and consider changing your password.',
    ])
    text_content = '\n'.join(body_lines)
    html_content = '<br>'.join(line if line else '&nbsp;' for line in body_lines)

    payload = {
        'sender': {'name': from_name, 'email': from_email},
        'to': [{'email': recipient}],
        'subject': subject,
        'htmlContent': f'<html><body><p>{html_content}</p></body></html>',
        'textContent': text_content,
    }

    headers = {
        'accept': 'application/json',
        'api-key': api_key,
        'content-type': 'application/json',
    }

    try:
        response = requests.post(BREVO_API_URL, json=payload, headers=headers, timeout=20)
        if response.status_code in (200, 201):
            return {'success': True}

        try:
            error_detail = response.json().get('message', response.text)
        except Exception:
            error_detail = response.text

        return {
            'success': False,
            'error': f'Failed to send OTP email (Brevo {response.status_code}): {error_detail}',
        }
    except requests.exceptions.RequestException as e:
        return {'success': False, 'error': f'Failed to send OTP email: {e}'}


def send_unlock_otp_email(recipient_email, otp_code, expires_at=None):
    return _send_otp_email(recipient_email, otp_code, expires_at, purpose='unlock')


def send_login_otp_email(recipient_email, otp_code, expires_at=None):
    return _send_otp_email(recipient_email, otp_code, expires_at, purpose='login')
