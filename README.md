# Secure Cloud-Powered Expense Management System

A Flask expense tracker built around a defence-in-depth security model: multi-factor authentication, role-based access control, and AES-256 field-level encryption of financial data at rest, with OCR receipt parsing on top.

The premise is that a Firestore breach should reveal nothing. Sensitive fields are encrypted before they ever reach the database, with a key derived per user, so an attacker holding the entire collection holds only ciphertext.

Built as a COSC 4607 Security and Protection project at Nipissing University, extending a functional expense tracker originally built for COSC 4206.

---

## Table of Contents

- [Overview](#overview)
- [Threat model](#threat-model)
- [Security architecture](#security-architecture)
- [Authentication](#authentication)
- [Access control](#access-control)
- [Encryption](#encryption)
- [OCR pipeline](#ocr-pipeline)
- [API reference](#api-reference)
- [Tech stack](#tech-stack)
- [Running it](#running-it)
- [Limitations](#limitations)

---

## Overview

Expense tracking applications handle vendor names, amounts, and spending patterns — data that reveals a great deal about a person. Most treat security as login plus HTTPS and store everything else in plaintext.

This project inverts that. Every security decision is enforced server-side at the application layer, so no control can be bypassed by manipulating the interface. The frontend holds no security logic at all.

**~1,341 lines of Python across 15 Flask routes.**

---

## Threat model

Designed against six concrete attacks:

| Threat | Control |
|---|---|
| Credential stuffing / brute force | bcrypt at cost 12, 5-attempt lockout, 15-minute cooldown |
| Stolen password | Mandatory email OTP as second factor |
| Session hijacking | Signed JWTs with 24-hour expiry, held in memory only |
| Horizontal privilege escalation (user reading another user's data) | RBAC enforced per route, plus per-user encryption keys |
| Vertical privilege escalation (user acting as admin) | Role claim embedded in the signed JWT |
| Database breach | AES-256 field-level encryption; Firestore holds only ciphertext |

---

## Security architecture

```
┌────────────────────────────────────────────┐
│  Browser                                    │
│  · login / OTP / dashboard                  │
│  · JWT held in memory (not localStorage)    │
│  · no security logic, no direct cloud access│
└────────────────┬───────────────────────────┘
                 │ HTTPS
                 ▼
┌────────────────────────────────────────────┐
│  Flask application layer                    │
│                                             │
│  ┌──────────────────────────────────────┐  │
│  │ Brute-force gate                      │  │
│  │ 5 attempts → 15 min lockout           │  │
│  └──────────────┬───────────────────────┘  │
│  ┌──────────────▼───────────────────────┐  │
│  │ bcrypt verify (cost 12)               │  │
│  └──────────────┬───────────────────────┘  │
│  ┌──────────────▼───────────────────────┐  │
│  │ Email OTP · 6 digits · 10 min · 3 try │  │
│  └──────────────┬───────────────────────┘  │
│  ┌──────────────▼───────────────────────┐  │
│  │ JWT issue · HS256 · 24 h · role claim │  │
│  └──────────────┬───────────────────────┘  │
│  ┌──────────────▼───────────────────────┐  │
│  │ @require_auth  →  @require_role(...)  │  │
│  └──────────────┬───────────────────────┘  │
│  ┌──────────────▼───────────────────────┐  │
│  │ Encryption engine                     │  │
│  │ AES-256 · PBKDF2 480k · per-user salt │  │
│  └──────────────┬───────────────────────┘  │
│  ┌──────────────▼───────────────────────┐  │
│  │ Audit logger (IP, UA, timestamp)      │  │
│  └──────────────┬───────────────────────┘  │
└─────────────────┼──────────────────────────┘
                  ▼
┌────────────────────────────────────────────┐
│  Firestore (ciphertext) · Firebase Storage  │
└────────────────────────────────────────────┘
```

The browser never talks to Firebase directly. Every read and write is mediated by the backend, which eliminates the entire class of vulnerability where client-side SDK rules are misconfigured and expose the database.

---

## Authentication

Three independent factors, each one useless to an attacker on its own.

**Passwords** are hashed with bcrypt at **cost factor 12**, four times the work of the common default of 10. bcrypt salts automatically and verifies in constant time, defeating both rainbow tables and timing attacks.

**One-time passwords** are 6 digits, delivered by email over SMTP, valid for **10 minutes**, and limited to **3 attempts** before invalidation. A stolen password alone does not grant access.

**Sessions** are stateless JWTs signed with HS256, carrying `user_id`, `username`, `role`, `iat`, and a **24-hour** expiry. The role travels inside the signed token, so authorisation decisions are cryptographically bound to identity and cannot be forged client-side. Tokens are held in browser memory rather than `localStorage`, limiting exposure to XSS.

**Brute-force mitigation** is separate from OTP throttling: **5 failed login attempts** trigger a **15-minute lockout**, reset on success.

Two different limits, easy to confuse: OTP entry allows 3 attempts, password login allows 5 before lockout.

---

## Access control

Three roles, enforced by decorator:

| Role | Own expenses | All user data | User management | Audit logs |
|---|---|---|---|---|
| User | read / write | — | — | — |
| Auditor | read / write | read only | — | — |
| Admin | read / write | read / write | yes | yes |

```python
@app.route("/api/admin/users", methods=["GET"])
@require_role("admin")
def list_users():
    ...
```

`@require_auth` validates the token signature and expiry. `@require_role(...)` checks the role claim. Because both run server-side before any handler logic, hiding a button in the UI is a convenience, not a security boundary.

---

## Encryption

Sensitive fields — vendor, description, amount — are encrypted before storage.

```
plaintext + user_id
        │
        ▼
   generate 16-byte random salt
        │
        ▼
   PBKDF2-HMAC-SHA256
   480,000 iterations → 32-byte key
        │
        ▼
   Fernet (AES-256-CBC + HMAC-SHA256)
        │
        ▼
   store as  "salt_b64:ciphertext_b64"
```

Design decisions worth noting:

**480,000 iterations** matches the OWASP 2023 recommendation for PBKDF2-HMAC-SHA256. High enough to make offline brute force expensive, low enough to keep per-field encryption around 2 ms.

**A fresh 16-byte salt per record**, stored alongside the ciphertext. This means two users recording an identical expense produce completely different ciphertext, so an attacker cannot infer content by matching identical values across the database.

**Per-user key derivation** limits blast radius. Compromising one user's key exposes one user's data.

**Fernet** rather than raw AES, because it provides authenticated encryption. Tampered ciphertext fails to decrypt rather than silently returning corrupted plaintext.

**A deliberate exception:** date and category are stored in plaintext. Encrypting them would make server-side filtering by month or category impossible without decrypting every record on every query. Neither field is meaningfully sensitive in isolation, and the tradeoff buys a usable filtering and dashboard experience. This is a conscious decision, not an oversight.

**Receipt integrity** is protected by hashing each uploaded image with SHA-256 and storing the hash separately in Firestore, so tampering with a stored file is detectable.

---

## OCR pipeline

```
receipt image
     │
     ├─ pytesseract → raw text
     │
     └─ parse_receipt_text()
          ├─ vendor    first-line analysis
          ├─ amount    regex over currency formats
          ├─ date      multi-format regex
          └─ category  keyword matching → detect_category()
                │
                ▼
        pre-filled form for user review
```

Extraction is deliberately advisory. Parsed values populate the form; the user confirms or corrects before anything is saved. OCR on receipts is unreliable enough — faded thermal print, curled paper, multi-column layouts — that treating its output as authoritative would corrupt the dataset.

Raw OCR text is retained on the record so a mis-parse can be traced back to what the engine actually read.

---

## API reference

15 routes.

| Method | Route | Auth | Purpose |
|---|---|---|---|
| GET | `/` | — | application shell |
| GET | `/static/<path>` | — | static assets |
| POST | `/api/auth/signup` | — | register |
| POST | `/api/auth/login` | — | password verify, trigger OTP |
| POST | `/api/auth/request-otp` | — | resend OTP |
| GET | `/api/auth/verify-token` | JWT | validate session |
| GET | `/api/admin/users` | admin | list users |
| PUT | `/api/admin/users/<id>/role` | admin | change role |
| PUT | `/api/admin/users/<id>/status` | admin | enable / disable account |
| GET | `/api/admin/security-logs` | admin | audit trail |
| POST | `/api/ocr` | JWT | extract fields from receipt |
| POST | `/api/expenses` | JWT | create expense (encrypts on write) |
| GET | `/api/expenses` | JWT | list with filters (decrypts on read) |
| GET | `/api/dashboard` | JWT | aggregate totals by category and month |
| GET | `/api/export` | JWT | CSV export of filtered set |

---

## Tech stack

**Backend** — Python, Flask, PyJWT, bcrypt, `cryptography` (Fernet, PBKDF2HMAC), pytesseract

**Frontend** — HTML, CSS, JavaScript single-page interface, Chart.js

**Cloud** — Firebase Firestore (encrypted documents), Firebase Storage (receipt images)

**Email** — SMTP over TLS for OTP delivery

---

## Running it

### Prerequisites

- Python 3.9+
- Tesseract OCR installed and on `PATH`
- A Firebase project with Firestore and Storage enabled
- An SMTP account for OTP email

### Setup

```bash
git clone https://github.com/Shoaib0777/Secure-Expense-Tracker.git
cd Secure-Expense-Tracker

python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate

pip install -r requirements.txt
```

Place your Firebase service account JSON in the project root and configure `.env`:

```
FIREBASE_CREDENTIALS=firebase-credentials.json
FIREBASE_STORAGE_BUCKET=your-bucket.appspot.com
JWT_SECRET_KEY=<long random string>
MASTER_ENCRYPTION_KEY=<long random string>
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=your@email.com
SMTP_PASSWORD=<app password>
```

`ocr_utils.py` currently hardcodes a Windows Tesseract path. On macOS or Linux, change `pytesseract.pytesseract.tesseract_cmd` to your install location or remove the line if Tesseract is already on `PATH`.

```bash
python app.py
```

Runs at `http://localhost:5000`.

---

## Limitations

- `MASTER_ENCRYPTION_KEY` lives in the environment. Production would use a managed KMS with rotation.
- OTP state is held in server memory, so it does not survive a restart and will not work across multiple instances. Redis or Firestore would fix this.
- OTP delivery is email only. TOTP or SMS would be stronger.
- No key rotation. Rotating the master key would require re-encrypting every record.
- Date and category are plaintext by design, as explained above.
- Testing is manual across roles and edge cases; there is no automated suite.
- OCR accuracy degrades on faded, curved, or multi-column receipts.

---

## Acknowledgements

Built for COSC 4607 Security and Protection at Nipissing University, supervised by Dr. Adegoke Ojeniyi, extending the expense management system from COSC 4206 Topics in Computing Science.

---

**Shoeb Mansuri** · [GitHub](https://github.com/Shoaib0777) · [LinkedIn](https://linkedin.com/in/shoeb-a-mansuri)
