"""
Secure Cloud Expense Tracker
COSC4206: Topics in Computing Science (Cloud Computing)
COSC4607: Security and Protection

Security Features:
- Authentication: bcrypt password hashing, Email OTP, JWT sessions
- Access Control: Role-Based Access Control (User, Auditor, Admin)
- Cryptography: AES-256 encryption for sensitive data
- Data Security: Input validation, audit logging
"""

from flask import Flask, request, jsonify, send_from_directory, Response
from flask_cors import CORS
from datetime import datetime
import os
import uuid
import csv
from io import BytesIO, StringIO

from firebase_config import init_firebase
from ocr_utils import extract_text_from_image, parse_receipt_text
from auth import (
    hash_password, verify_password,
    generate_otp_code, send_otp_email, store_otp, verify_otp, clear_otp,
    generate_jwt_token, decode_jwt_token, get_current_user,
    require_auth, require_role,
    check_brute_force, record_failed_attempt, clear_failed_attempts,
    log_security_event, ROLES
)
from encryption import encrypt_expense_data, decrypt_expense_data

app = Flask(__name__, static_folder="static", template_folder="templates")
CORS(app)

db, bucket = init_firebase()


# ============== Helper Functions ==============

def _apply_filters(expenses, filters):
    """Apply filters to expense list."""
    result = []
    for exp in expenses:
        if filters.get("category"):
            if exp.get("category", "").lower() != filters["category"].lower():
                continue
        exp_date = exp.get("date", "")
        if filters.get("from_date") and exp_date:
            if exp_date < filters["from_date"]:
                continue
        if filters.get("to_date") and exp_date:
            if exp_date > filters["to_date"]:
                continue
        exp_amount = float(exp.get("amount", 0) or 0)
        if filters.get("min_amount") is not None:
            if exp_amount < filters["min_amount"]:
                continue
        if filters.get("max_amount") is not None:
            if exp_amount > filters["max_amount"]:
                continue
        if filters.get("month") and exp_date:
            if not exp_date.startswith(filters["month"]):
                continue
        result.append(exp)
    return result


def _parse_filter_params(args):
    """Parse filter parameters from request."""
    filters = {}
    if args.get("category", "").strip():
        filters["category"] = args.get("category").strip()
    if args.get("from", "").strip():
        filters["from_date"] = args.get("from").strip()
    if args.get("to", "").strip():
        filters["to_date"] = args.get("to").strip()
    if args.get("min_amount", "").strip():
        try:
            filters["min_amount"] = float(args.get("min_amount"))
        except ValueError:
            pass
    if args.get("max_amount", "").strip():
        try:
            filters["max_amount"] = float(args.get("max_amount"))
        except ValueError:
            pass
    if args.get("month", "").strip():
        filters["month"] = args.get("month").strip()
    return filters


def upload_receipt_to_storage(file_obj, content_type, original_filename):
    """Upload receipt to Firebase Storage."""
    unique_name = f"{uuid.uuid4()}_{original_filename}"
    blob = bucket.blob(f"receipts/{unique_name}")
    blob.upload_from_file(file_obj, content_type=content_type)
    blob.make_public()
    return blob.public_url


# ============== Static Routes ==============

@app.route("/")
def index():
    return send_from_directory("templates", "index.html")


@app.route("/static/<path:path>")
def send_static(path):
    return send_from_directory("static", path)


# ============== Authentication Endpoints ==============

@app.route("/api/auth/signup", methods=["POST"])
def api_signup():
    """
    Register a new user.
    Required: username, email, password
    Optional: role (default: user)
    """
    try:
        data = request.get_json()
        username = data.get("username", "").strip()
        email = data.get("email", "").strip().lower()
        password = data.get("password", "")
        role = data.get("role", "user")

        # Validation
        if not username or len(username) < 3:
            return jsonify({"error": "Username must be at least 3 characters"}), 400
        if not email or "@" not in email:
            return jsonify({"error": "Valid email is required"}), 400
        if not password or len(password) < 8:
            return jsonify({"error": "Password must be at least 8 characters"}), 400
        if role not in ROLES:
            role = "user"

        # Check if username/email already exists
        existing_user = db.collection("users").where("username", "==", username).limit(1).stream()
        if any(existing_user):
            return jsonify({"error": "Username already taken"}), 400

        existing_email = db.collection("users").where("email", "==", email).limit(1).stream()
        if any(existing_email):
            return jsonify({"error": "Email already registered"}), 400

        # Create user document
        user_doc = {
            "username": username,
            "email": email,
            "password_hash": hash_password(password),
            "role": role,
            "otp_enabled": True,  # Email OTP is enabled by default
            "created_at": datetime.utcnow(),
            "last_login": None,
            "is_active": True
        }

        doc_ref = db.collection("users").add(user_doc)
        user_id = doc_ref[1].id

        # Log signup event
        log_security_event(db, "user_signup", user_id, {"username": username, "role": role})

        return jsonify({
            "success": True,
            "message": "Account created successfully. You will receive OTP codes via email during login.",
            "user_id": user_id
        })

    except Exception as e:
        print(f"Signup error: {e}")
        return jsonify({"error": str(e)}), 500


@app.route("/api/auth/login", methods=["POST"])
def api_login():
    """
    Authenticate user with Email OTP.
    Step 1: Send username + password -> OTP sent to email
    Step 2: Send username + password + otp_code -> JWT token returned
    """
    try:
        data = request.get_json()
        username = data.get("username", "").strip()
        password = data.get("password", "")
        otp_code = data.get("otp_code", "").strip()

        if not username or not password:
            return jsonify({"error": "Username and password required"}), 400

        # Check brute force lockout
        is_locked, remaining_mins = check_brute_force(username)
        if is_locked:
            return jsonify({
                "error": f"Account locked due to too many failed attempts. Try again in {remaining_mins} minutes."
            }), 429

        # Find user
        users = list(db.collection("users").where("username", "==", username).limit(1).stream())
        if not users:
            record_failed_attempt(username)
            return jsonify({"error": "Invalid username or password"}), 401

        user_doc = users[0]
        user_data = user_doc.to_dict()
        user_id = user_doc.id

        # Verify password
        if not verify_password(password, user_data.get("password_hash", "")):
            record_failed_attempt(username)
            log_security_event(db, "failed_login", user_id, {"reason": "invalid_password"})
            return jsonify({"error": "Invalid username or password"}), 401

        # Check if account is active
        if not user_data.get("is_active", True):
            return jsonify({"error": "Account is disabled"}), 403

        # Step 1: No OTP code provided - send OTP via email
        if not otp_code:
            # Generate and send OTP
            otp = generate_otp_code()
            email = user_data.get("email", "")

            if send_otp_email(email, otp, username):
                store_otp(email, otp)
                return jsonify({
                    "success": True,
                    "requires_otp": True,
                    "message": f"OTP code sent to {email}. Please check your email.",
                    "email": email
                }), 200
            else:
                return jsonify({"error": "Failed to send OTP email. Please try again."}), 500

        # Step 2: OTP code provided - verify it
        email = user_data.get("email", "")
        is_valid, error_msg = verify_otp(email, otp_code)

        if not is_valid:
            record_failed_attempt(username)
            log_security_event(db, "failed_login", user_id, {"reason": "invalid_otp"})
            return jsonify({"error": error_msg}), 401

        # Clear failed attempts on successful login
        clear_failed_attempts(username)

        # Update last login
        db.collection("users").document(user_id).update({"last_login": datetime.utcnow()})

        # Generate JWT token
        token = generate_jwt_token(user_id, username, user_data.get("role", "user"))

        # Log successful login
        log_security_event(db, "successful_login", user_id, {"username": username})

        return jsonify({
            "success": True,
            "token": token,
            "user": {
                "id": user_id,
                "username": username,
                "email": user_data.get("email"),
                "role": user_data.get("role", "user"),
                "otp_enabled": True
            }
        })

    except Exception as e:
        print(f"Login error: {e}")
        return jsonify({"error": str(e)}), 500


@app.route("/api/auth/request-otp", methods=["POST"])
def api_request_otp():
    """Request a new OTP code to be sent via email."""
    try:
        data = request.get_json()
        email = data.get("email", "").strip().lower()

        if not email or "@" not in email:
            return jsonify({"error": "Valid email is required"}), 400

        # Find user by email
        users = list(db.collection("users").where("email", "==", email).limit(1).stream())
        if not users:
            # Don't reveal if email exists or not (security best practice)
            return jsonify({
                "success": True,
                "message": "If an account exists with this email, an OTP code has been sent."
            }), 200

        user_doc = users[0]
        user_data = user_doc.to_dict()
        username = user_data.get("username", "")

        # Generate and send OTP
        otp = generate_otp_code()

        if send_otp_email(email, otp, username):
            store_otp(email, otp)
            return jsonify({
                "success": True,
                "message": "OTP code sent to your email. Please check your inbox."
            }), 200
        else:
            return jsonify({"error": "Failed to send OTP email. Please try again."}), 500

    except Exception as e:
        print(f"Request OTP error: {e}")
        return jsonify({"error": str(e)}), 500


@app.route("/api/auth/verify-token", methods=["GET"])
@require_auth
def api_verify_token():
    """Verify JWT token and return user info."""
    user = request.current_user
    return jsonify({
        "success": True,
        "user": user
    })


# ============== User Management (Admin Only) ==============

@app.route("/api/admin/users", methods=["GET"])
@require_role("admin")
def api_get_all_users():
    """Get all users (Admin only)."""
    try:
        users = []
        docs = db.collection("users").stream()
        for doc in docs:
            data = doc.to_dict()
            users.append({
                "id": doc.id,
                "username": data.get("username"),
                "email": data.get("email"),
                "role": data.get("role"),
                "is_active": data.get("is_active", True),
                "otp_enabled": data.get("otp_enabled", False),
                "created_at": data.get("created_at"),
                "last_login": data.get("last_login")
            })
        return jsonify({"success": True, "users": users})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/admin/users/<user_id>/role", methods=["PUT"])
@require_role("admin")
def api_update_user_role(user_id):
    """Update user role (Admin only)."""
    try:
        data = request.get_json()
        new_role = data.get("role", "user")

        if new_role not in ROLES:
            return jsonify({"error": "Invalid role"}), 400

        db.collection("users").document(user_id).update({"role": new_role})

        log_security_event(db, "role_change", user_id, {
            "new_role": new_role,
            "changed_by": request.current_user["user_id"]
        })

        return jsonify({"success": True, "message": f"Role updated to {new_role}"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/admin/users/<user_id>/status", methods=["PUT"])
@require_role("admin")
def api_update_user_status(user_id):
    """Enable/disable user account (Admin only)."""
    try:
        data = request.get_json()
        is_active = data.get("is_active", True)

        db.collection("users").document(user_id).update({"is_active": is_active})

        log_security_event(db, "account_status_change", user_id, {
            "is_active": is_active,
            "changed_by": request.current_user["user_id"]
        })

        return jsonify({"success": True, "message": f"Account {'enabled' if is_active else 'disabled'}"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ============== Security Logs (Admin Only) ==============

@app.route("/api/admin/security-logs", methods=["GET"])
@require_role("admin")
def api_get_security_logs():
    """Get security audit logs (Admin only)."""
    try:
        logs = []
        docs = db.collection("security_logs").order_by("timestamp", direction="DESCENDING").limit(100).stream()
        for doc in docs:
            data = doc.to_dict()
            data["id"] = doc.id
            logs.append(data)
        return jsonify({"success": True, "logs": logs})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ============== OCR Endpoint ==============

@app.route("/api/ocr", methods=["POST"])
@require_auth
def api_ocr():
    """OCR endpoint for receipt scanning."""
    if "receipt" not in request.files:
        return jsonify({"error": "No receipt file provided."}), 400

    file = request.files["receipt"]
    if file.filename == "":
        return jsonify({"error": "Empty filename."}), 400

    buffer = BytesIO(file.read())
    buffer.seek(0)

    try:
        text = extract_text_from_image(buffer)
        parsed = parse_receipt_text(text)
        return jsonify({
            "success": True,
            "vendor": parsed.get("vendor", ""),
            "amount": parsed.get("amount", ""),
            "date": parsed.get("date", ""),
            "category": parsed.get("category", ""),
            "raw_text": parsed.get("raw_text", text),
        })
    except Exception as e:
        return jsonify({"error": f"OCR failed: {e}"}), 500


# ============== Expense Endpoints ==============

@app.route("/api/expenses", methods=["POST"])
@require_auth
def api_add_expense():
    """Add new expense (authenticated users only)."""
    try:
        user = request.current_user
        form = request.form

        vendor = form.get("vendor", "").strip()
        amount = form.get("amount", "").strip()
        date_str = form.get("date", "").strip()
        category = form.get("category", "").strip() or "Uncategorized"
        description = form.get("description", "").strip()
        ocr_raw_text = form.get("ocr_raw_text", "").strip()

        if not amount:
            return jsonify({"error": "Amount is required."}), 400

        try:
            amount_val = float(amount)
        except ValueError:
            return jsonify({"error": "Amount must be a number."}), 400

        if date_str:
            try:
                parsed_date = datetime.fromisoformat(date_str)
            except ValueError:
                try:
                    parsed_date = datetime.strptime(date_str, "%Y-%m-%d")
                except Exception:
                    parsed_date = datetime.now()
        else:
            parsed_date = datetime.now()

        receipt_url = ""
        if "receipt" in request.files:
            file = request.files["receipt"]
            if file.filename != "":
                buffer = BytesIO(file.read())
                buffer.seek(0)
                receipt_url = upload_receipt_to_storage(buffer, file.content_type, file.filename)

        expense_doc = {
            "user_id": user["user_id"],
            "username": user["username"],
            "vendor": vendor,
            "amount": amount_val,
            "date": parsed_date.strftime("%Y-%m-%d"),
            "category": category,
            "description": description,
            "receipt_url": receipt_url,
            "ocr_raw_text": ocr_raw_text,
            "created_at": datetime.utcnow(),
        }

        # Encrypt sensitive fields
        encrypted_expense = encrypt_expense_data(expense_doc, user["user_id"])

        db.collection("expenses").add(encrypted_expense)
        return jsonify({"success": True, "message": "Expense saved securely."})

    except Exception as e:
        print(f"Add expense error: {e}")
        return jsonify({"error": str(e)}), 500


@app.route("/api/expenses", methods=["GET"])
@require_auth
def api_get_expenses():
    """Get expenses based on user role."""
    try:
        user = request.current_user
        role = user.get("role", "user")

        # Role-based access control
        if role == "admin" or role == "auditor":
            # Admin and Auditor can see all expenses
            target_user = request.args.get("user_id", "").strip()
            if target_user:
                expenses_ref = db.collection("expenses").where("user_id", "==", target_user)
            else:
                expenses_ref = db.collection("expenses")
        else:
            # Regular users can only see their own expenses
            expenses_ref = db.collection("expenses").where("user_id", "==", user["user_id"])

        docs = expenses_ref.stream()

        expenses = []
        for doc in docs:
            data = doc.to_dict()
            data["id"] = doc.id

            # Decrypt sensitive fields
            decrypted = decrypt_expense_data(data, data.get("user_id", user["user_id"]))
            expenses.append(decrypted)

        # Sort by date
        expenses.sort(key=lambda x: x.get("date", ""), reverse=True)

        # Apply filters
        filters = _parse_filter_params(request.args)
        if filters:
            expenses = _apply_filters(expenses, filters)

        return jsonify({"success": True, "expenses": expenses})

    except Exception as e:
        print(f"Get expenses error: {e}")
        return jsonify({"error": str(e)}), 500


@app.route("/api/dashboard", methods=["GET"])
@require_auth
def api_dashboard():
    """Get dashboard data based on user role."""
    try:
        user = request.current_user
        role = user.get("role", "user")

        # Role-based access
        if role == "admin" or role == "auditor":
            expenses_ref = db.collection("expenses")
        else:
            expenses_ref = db.collection("expenses").where("user_id", "==", user["user_id"])

        docs = list(expenses_ref.stream())

        total_amount = 0.0
        totals_by_category = {}

        for doc in docs:
            data = doc.to_dict()
            # Decrypt
            decrypted = decrypt_expense_data(data, data.get("user_id", user["user_id"]))

            amount = float(decrypted.get("amount", 0) or 0)
            total_amount += amount
            category = decrypted.get("category") or "Uncategorized"
            if not category.strip():
                category = "Uncategorized"
            totals_by_category[category] = totals_by_category.get(category, 0.0) + amount

        category_list = [
            {"category": c, "amount": totals_by_category[c]}
            for c in sorted(totals_by_category.keys())
        ]

        return jsonify({
            "success": True,
            "total_amount": total_amount,
            "totals_by_category": category_list,
            "total_expenses": len(docs)
        })

    except Exception as e:
        print(f"Dashboard error: {e}")
        return jsonify({"error": str(e)}), 500


@app.route("/api/export", methods=["GET"])
@require_auth
def api_export_csv():
    """Export expenses as CSV."""
    try:
        user = request.current_user
        role = user.get("role", "user")

        if role == "admin" or role == "auditor":
            expenses_ref = db.collection("expenses")
        else:
            expenses_ref = db.collection("expenses").where("user_id", "==", user["user_id"])

        docs = expenses_ref.stream()

        expenses = []
        for doc in docs:
            data = doc.to_dict()
            data["id"] = doc.id
            decrypted = decrypt_expense_data(data, data.get("user_id", user["user_id"]))
            expenses.append(decrypted)

        expenses.sort(key=lambda x: x.get("date", ""), reverse=True)

        filters = _parse_filter_params(request.args)
        if filters:
            expenses = _apply_filters(expenses, filters)

        output = StringIO()
        fieldnames = ["id", "username", "vendor", "amount", "date", "category", "description", "receipt_url"]
        writer = csv.DictWriter(output, fieldnames=fieldnames, extrasaction='ignore')
        writer.writeheader()

        for exp in expenses:
            writer.writerow({
                "id": exp.get("id", ""),
                "username": exp.get("username", ""),
                "vendor": exp.get("vendor", ""),
                "amount": exp.get("amount", ""),
                "date": exp.get("date", ""),
                "category": exp.get("category", ""),
                "description": exp.get("description", ""),
                "receipt_url": exp.get("receipt_url", ""),
            })

        output.seek(0)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"expenses_{user['username']}_{timestamp}.csv"

        return Response(
            output.getvalue(),
            mimetype="text/csv",
            headers={"Content-Disposition": f"attachment; filename={filename}"}
        )

    except Exception as e:
        print(f"Export error: {e}")
        return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5001, debug=True)
