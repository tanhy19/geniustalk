import os
import smtplib
from email.message import EmailMessage


def _bool_env(name, default=False):
    value = (os.getenv(name) or '').strip().lower()
    if not value:
        return default
    return value in {'1', 'true', 'yes', 'on'}


def send_unlock_otp_email(recipient_email, otp_code, expires_at=None):
    """
    Sends account unlock OTP to recipient using SMTP.
    Required env vars:
      SMTP_HOST, SMTP_PORT, SMTP_FROM_EMAIL
    Optional:
      SMTP_USER, SMTP_PASSWORD, SMTP_USE_TLS(true/false)
    """
    smtp_host = (os.getenv('SMTP_HOST') or '').strip()
    smtp_port_raw = (os.getenv('SMTP_PORT') or '587').strip()
    smtp_user = (os.getenv('SMTP_USER') or '').strip()
    smtp_password = (os.getenv('SMTP_PASSWORD') or '').strip()
    from_email = (os.getenv('SMTP_FROM_EMAIL') or smtp_user).strip()
    use_tls = _bool_env('SMTP_USE_TLS', default=True)

    if not smtp_host or not from_email:
        return {
            'success': False,
            'error': 'Email service is not configured (SMTP_HOST/SMTP_FROM_EMAIL).',
        }

    try:
        smtp_port = int(smtp_port_raw)
    except Exception:
        return {
            'success': False,
            'error': 'Invalid SMTP_PORT configuration.',
        }

    recipient = (recipient_email or '').strip().lower()
    if not recipient:
        return {'success': False, 'error': 'Recipient email is required.'}

    subject = 'GeniusTalk Account Unlock OTP'
    body_lines = [
        'We received a request to unlock your GeniusTalk account.',
        '',
        f'Your OTP code is: {otp_code}',
    ]
    if expires_at:
        body_lines.append(f'This code expires at: {expires_at}')
    body_lines.extend([
        '',
        'If you did not request this, please ignore this email.',
    ])

    message = EmailMessage()
    message['Subject'] = subject
    message['From'] = from_email
    message['To'] = recipient
    message.set_content('\n'.join(body_lines))

    try:
        with smtplib.SMTP(smtp_host, smtp_port, timeout=20) as server:
            if use_tls:
                server.starttls()
            if smtp_user:
                server.login(smtp_user, smtp_password)
            server.send_message(message)
        return {'success': True}
    except Exception as e:
        return {'success': False, 'error': f'Failed to send OTP email: {e}'}
