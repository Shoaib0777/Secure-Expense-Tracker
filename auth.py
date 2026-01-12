"""
Authentication Module for Secure Expense Tracker
Implements: Password Hashing (bcrypt), Email OTP, JWT Sessions
Security Domains: Authentication, Access Control
"""

import bcrypt
import jwt
import secrets
import random
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timedelta
from functools import wraps
from flask import request, jsonify
import os

# JWT Configuration
JWT_SECRET = secrets.token_hex(32)
JWT_ALGORITHM = "HS256"
JWT_EXPIRATION_HOURS = 24

# Email Configuration (Gmail SMTP)
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587
EMAIL_ADDRESS = os.environ.get("EMAIL_ADDRESS", "shoebmansuri78690@gmail.com")
EMAIL_PASSWORD = os.environ.get("EMAIL_PASSWORD", "mntgzlsctpbgzkwa")

# OTP Storage (in production, use Redis)
otp_store = {}  # Format: {email: {"code": "123456", "expires": datetime, "attempts": 0}}
OTP_EXPIRATION_MINUTES = 10
MAX_OTP_ATTEMPTS = 3

# Roles
ROLES = {
    "user": 1,
    "auditor": 2,
    "admin": 3
}


# ============== Password Hashing (bcrypt) ==============

def hash_password(plain_password: str) -> str:
    """Hash a password using bcrypt with automatic salt generation."""
    salt = bcrypt.gensalt(rounds=12)
    hashed = bcrypt.hashpw(plain_password.encode('utf-8'), salt)
    return hashed.decode('utf-8')


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a password against its bcrypt hash."""
    try:
        return bcrypt.checkpw(
            plain_password.encode('utf-8'),
            hashed_password.encode('utf-8')
        )
    except Exception:
        return False


# ============== Email OTP ==============

def generate_otp_code() -> str:
    """Generate a 6-digit OTP code."""
    return str(random.randint(100000, 999999))


def send_otp_email(to_email: str, otp_code: str, username: str) -> bool:
    """
    Send OTP code via email using Gmail SMTP.
    Returns True if successful, False otherwise.
    """
    print(f"DEBUG: EMAIL_ADDRESS = '{EMAIL_ADDRESS}'")
    print(f"DEBUG: EMAIL_PASSWORD = {'[SET]' if EMAIL_PASSWORD else '[NOT SET]'}")

    if not EMAIL_ADDRESS or not EMAIL_PASSWORD:
        print("ERROR: Email credentials not configured!")
        print("Set EMAIL_ADDRESS and EMAIL_PASSWORD environment variables")
        return False

    try:
        # Create message
        msg = MIMEMultipart('alternative')
        msg['Subject'] = 'Your Secure Expense Tracker Login Code'
        msg['From'] = EMAIL_ADDRESS
        msg['To'] = to_email

        # HTML email body
        html = f"""
        <html>
          <body style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
            <div style="background: linear-gradient(135deg, #4361ee 0%, #7c3aed 100%); padding: 20px; text-align: center;">
              <h1 style="color: white; margin: 0;">🔒 Secure Expense Tracker</h1>
            </div>
            <div style="padding: 30px; background-color: #f8f9fa;">
              <h2 style="color: #333;">Hello {username}!</h2>
              <p style="color: #666; font-size: 16px;">Your login verification code is:</p>
              <div style="background-color: white; padding: 20px; text-align: center; border-radius: 10px; margin: 20px 0;">
                <h1 style="color: #4361ee; font-size: 48px; letter-spacing: 10px; margin: 0;">{otp_code}</h1>
              </div>
              <p style="color: #666; font-size: 14px;">This code will expire in <strong>10 minutes</strong>.</p>
              <p style="color: #999; font-size: 12px; margin-top: 30px;">
                If you didn't request this code, please ignore this email.
              </p>
            </div>
            <div style="background-color: #e9ecef; padding: 15px; text-align: center;">
              <p style="color: #6c757d; font-size: 12px; margin: 0;">
                Secure Expense Tracker - COSC4206 & COSC4607
              </p>
            </div>
          </body>
        </html>
        """

        # Plain text fallback
        text = f"""
        Secure Expense Tracker - Login Code

        Hello {username}!

        Your verification code is: {otp_code}

        This code will expire in 10 minutes.

        If you didn't request this code, please ignore this email.
        """

        msg.attach(MIMEText(text, 'plain'))
        msg.attach(MIMEText(html, 'html'))

        # Send email
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
            server.send_message(msg)

        print(f"SUCCESS: OTP email sent to {to_email}")
        return True

    except Exception as e:
        print(f"ERROR: Failed to send OTP email: {e}")
        return False


def store_otp(email: str, code: str):
    """Store OTP code with expiration."""
    otp_store[email] = {
        "code": code,
        "expires": datetime.utcnow() + timedelta(minutes=OTP_EXPIRATION_MINUTES),
        "attempts": 0
    }


def verify_otp(email: str, code: str) -> tuple:
    """
    Verify OTP code.
    Returns (is_valid, error_message)
    """
    if email not in otp_store:
        return False, "No OTP found. Please request a new code."

    otp_data = otp_store[email]

    # Check expiration
    if datetime.utcnow() > otp_data["expires"]:
        del otp_store[email]
        return False, "OTP expired. Please request a new code."

    # Check attempts
    if otp_data["attempts"] >= MAX_OTP_ATTEMPTS:
        del otp_store[email]
        return False, "Too many failed attempts. Please request a new code."

    # Verify code
    if otp_data["code"] == code:
        del otp_store[email]  # Remove used OTP
        return True, None
    else:
        otp_data["attempts"] += 1
        return False, f"Invalid code. {MAX_OTP_ATTEMPTS - otp_data['attempts']} attempts remaining."


def clear_otp(email: str):
    """Clear OTP for an email."""
    if email in otp_store:
        del otp_store[email]


# ============== JWT Token Management ==============

def generate_jwt_token(user_id: str, username: str, role: str) -> str:
    """Generate a JWT token for authenticated user."""
    payload = {
        "user_id": user_id,
        "username": username,
        "role": role,
        "exp": datetime.utcnow() + timedelta(hours=JWT_EXPIRATION_HOURS),
        "iat": datetime.utcnow()
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def decode_jwt_token(token: str) -> dict:
    """Decode and verify a JWT token."""
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None


# ============== Authentication Middleware ==============

def get_current_user():
    """Extract current user from JWT token in Authorization header."""
    auth_header = request.headers.get("Authorization", "")

    if not auth_header.startswith("Bearer "):
        return None

    token = auth_header.split(" ")[1]
    return decode_jwt_token(token)


def require_auth(f):
    """Decorator: Require valid JWT authentication."""
    @wraps(f)
    def decorated(*args, **kwargs):
        user = get_current_user()
        if not user:
            return jsonify({"error": "Authentication required"}), 401
        request.current_user = user
        return f(*args, **kwargs)
    return decorated


def require_role(*allowed_roles):
    """Decorator: Require specific role(s) for access."""
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            user = get_current_user()
            if not user:
                return jsonify({"error": "Authentication required"}), 401

            if user.get("role") not in allowed_roles:
                return jsonify({"error": "Access denied. Insufficient permissions."}), 403

            request.current_user = user
            return f(*args, **kwargs)
        return decorated
    return decorator


# ============== Brute Force Protection ==============

login_attempts = {}
MAX_ATTEMPTS = 5
LOCKOUT_MINUTES = 15


def check_brute_force(username: str) -> tuple:
    """Check if user is locked out due to too many failed attempts."""
    if username not in login_attempts:
        return False, 0

    attempts, lockout_time = login_attempts[username]

    if lockout_time and datetime.utcnow() < lockout_time:
        remaining = (lockout_time - datetime.utcnow()).seconds // 60
        return True, remaining + 1

    if lockout_time and datetime.utcnow() >= lockout_time:
        login_attempts[username] = (0, None)
        return False, 0

    return False, 0


def record_failed_attempt(username: str):
    """Record a failed login attempt."""
    if username not in login_attempts:
        login_attempts[username] = (1, None)
    else:
        attempts, _ = login_attempts[username]
        attempts += 1

        if attempts >= MAX_ATTEMPTS:
            lockout_time = datetime.utcnow() + timedelta(minutes=LOCKOUT_MINUTES)
            login_attempts[username] = (attempts, lockout_time)
        else:
            login_attempts[username] = (attempts, None)


def clear_failed_attempts(username: str):
    """Clear failed attempts after successful login."""
    if username in login_attempts:
        del login_attempts[username]


# ============== Audit Logging ==============

def log_security_event(db, event_type: str, user_id: str, details: dict):
    """Log security events to Firestore for audit trail."""
    try:
        log_entry = {
            "event_type": event_type,
            "user_id": user_id,
            "details": details,
            "ip_address": request.remote_addr,
            "user_agent": request.headers.get("User-Agent", ""),
            "timestamp": datetime.utcnow()
        }
        db.collection("security_logs").add(log_entry)
    except Exception as e:
        print(f"Failed to log security event: {e}")
