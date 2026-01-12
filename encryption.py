"""
Encryption Module for Secure Expense Tracker
Implements: AES-256 encryption for sensitive data fields
Security Domains: Cryptography, Data Security and Privacy
"""

import os
import base64
import secrets
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# Master encryption key (in production, load from secure environment variable)
# This key is used to derive user-specific keys
MASTER_KEY = os.environ.get("ENCRYPTION_MASTER_KEY", secrets.token_hex(32))


def _derive_key(user_id: str, salt: bytes = None) -> tuple:
    """
    Derive a Fernet key from user_id using PBKDF2.
    Returns (key, salt) - salt should be stored with encrypted data.
    """
    if salt is None:
        salt = os.urandom(16)

    # Combine master key and user_id for key derivation
    key_material = f"{MASTER_KEY}:{user_id}".encode()

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=480000,  # OWASP recommended minimum
    )

    key = base64.urlsafe_b64encode(kdf.derive(key_material))
    return key, salt


def encrypt_field(plain_text: str, user_id: str) -> str:
    """
    Encrypt a sensitive field using AES-256 (Fernet).
    Returns base64 encoded string: salt:encrypted_data

    Args:
        plain_text: The text to encrypt
        user_id: User ID for key derivation (each user has unique key)

    Returns:
        Encrypted string in format "salt_b64:encrypted_b64"
    """
    if not plain_text:
        return ""

    try:
        key, salt = _derive_key(user_id)
        fernet = Fernet(key)

        encrypted = fernet.encrypt(plain_text.encode('utf-8'))

        # Combine salt and encrypted data
        salt_b64 = base64.urlsafe_b64encode(salt).decode('utf-8')
        encrypted_b64 = encrypted.decode('utf-8')

        return f"{salt_b64}:{encrypted_b64}"
    except Exception as e:
        print(f"Encryption error: {e}")
        return plain_text  # Fallback to plain text on error


def decrypt_field(encrypted_text: str, user_id: str) -> str:
    """
    Decrypt a sensitive field.

    Args:
        encrypted_text: The encrypted string (salt_b64:encrypted_b64)
        user_id: User ID for key derivation

    Returns:
        Decrypted plain text
    """
    if not encrypted_text:
        return ""

    # Check if data is encrypted (contains salt separator)
    if ":" not in encrypted_text:
        return encrypted_text  # Return as-is if not encrypted

    try:
        salt_b64, encrypted_b64 = encrypted_text.split(":", 1)
        salt = base64.urlsafe_b64decode(salt_b64.encode('utf-8'))

        key, _ = _derive_key(user_id, salt)
        fernet = Fernet(key)

        decrypted = fernet.decrypt(encrypted_b64.encode('utf-8'))
        return decrypted.decode('utf-8')
    except Exception as e:
        print(f"Decryption error: {e}")
        return encrypted_text  # Return as-is on error


def encrypt_expense_data(expense: dict, user_id: str) -> dict:
    """
    Encrypt sensitive fields in an expense document.
    Fields encrypted: amount, vendor, description

    Args:
        expense: Expense dictionary
        user_id: User ID for key derivation

    Returns:
        Expense dictionary with encrypted fields
    """
    encrypted = expense.copy()

    # Fields to encrypt
    sensitive_fields = ["amount", "vendor", "description"]

    for field in sensitive_fields:
        if field in encrypted and encrypted[field]:
            # Convert amount to string for encryption
            value = str(encrypted[field])
            encrypted[field] = encrypt_field(value, user_id)

    # Mark as encrypted for identification
    encrypted["_encrypted"] = True

    return encrypted


def decrypt_expense_data(expense: dict, user_id: str) -> dict:
    """
    Decrypt sensitive fields in an expense document.

    Args:
        expense: Expense dictionary (possibly encrypted)
        user_id: User ID for key derivation

    Returns:
        Expense dictionary with decrypted fields
    """
    # Check if data is encrypted
    if not expense.get("_encrypted", False):
        return expense

    decrypted = expense.copy()

    # Fields to decrypt
    sensitive_fields = ["amount", "vendor", "description"]

    for field in sensitive_fields:
        if field in decrypted and decrypted[field]:
            decrypted[field] = decrypt_field(str(decrypted[field]), user_id)

    # Convert amount back to float
    if "amount" in decrypted:
        try:
            decrypted["amount"] = float(decrypted["amount"])
        except (ValueError, TypeError):
            decrypted["amount"] = 0.0

    return decrypted


# ============== Utility Functions ==============

def generate_encryption_key() -> str:
    """
    Generate a new random Fernet key.
    Useful for generating master keys.
    """
    return Fernet.generate_key().decode('utf-8')


def is_encrypted(value: str) -> bool:
    """
    Check if a value appears to be encrypted (contains salt separator).
    """
    if not value or not isinstance(value, str):
        return False
    return ":" in value and len(value) > 50


# ============== Demo/Testing ==============

if __name__ == "__main__":
    # Test encryption/decryption
    test_user = "test_user_123"

    print("Testing Encryption Module")
    print("=" * 50)

    # Test field encryption
    original = "This is sensitive data: $1234.56"
    encrypted = encrypt_field(original, test_user)
    decrypted = decrypt_field(encrypted, test_user)

    print(f"Original:  {original}")
    print(f"Encrypted: {encrypted[:50]}...")
    print(f"Decrypted: {decrypted}")
    print(f"Match: {original == decrypted}")

    print("\n" + "=" * 50)

    # Test expense encryption
    expense = {
        "amount": 99.99,
        "vendor": "Walmart",
        "description": "Grocery shopping",
        "category": "Groceries",
        "date": "2024-01-15"
    }

    encrypted_expense = encrypt_expense_data(expense, test_user)
    decrypted_expense = decrypt_expense_data(encrypted_expense, test_user)

    print("Original Expense:")
    print(expense)
    print("\nEncrypted Expense:")
    print({k: v[:30] + "..." if isinstance(v, str) and len(v) > 30 else v
           for k, v in encrypted_expense.items()})
    print("\nDecrypted Expense:")
    print(decrypted_expense)
