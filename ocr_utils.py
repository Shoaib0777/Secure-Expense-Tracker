from PIL import Image
import pytesseract
import re
from io import BytesIO

pytesseract.pytesseract.tesseract_cmd = r"C:\Program Files\Tesseract-OCR\tesseract.exe"


def extract_text_from_image(file_stream) -> str:
    """
    Takes a file-like object (e.g., BytesIO) and returns OCR text.
    """
    image = Image.open(file_stream)
    text = pytesseract.image_to_string(image)
    return text


def detect_category(vendor: str, raw_text: str) -> str:
    """
    Auto-detect expense category based on vendor name and receipt text.
    Returns the guessed category or empty string if no match.
    """
    # Combine vendor and raw_text for searching (lowercase)
    search_text = f"{vendor} {raw_text}".lower()

    # Category rules: (keywords, category)
    category_rules = [
        # Transport
        (["uber", "lyft", "taxi", "cab", "transit", "bus", "subway", "metro pass", "parking", "gas station", "shell", "esso", "petro"], "Transport"),

        # Groceries
        (["walmart", "metro", "no frills", "loblaws", "costco", "sobeys", "freshco", "food basics", "whole foods", "trader joe", "safeway", "kroger", "aldi", "supermarket", "grocery"], "Groceries"),

        # Food / Restaurants
        (["mcdonald", "burger king", "wendy", "tim horton", "starbucks", "subway", "pizza", "restaurant", "cafe", "coffee", "doordash", "ubereats", "skip the dishes", "grubhub", "chipotle", "kfc", "taco bell", "domino"], "Food"),

        # Bills / Utilities
        (["netflix", "spotify", "apple music", "amazon prime", "disney+", "hulu", "hydro", "electric", "water bill", "internet", "rogers", "bell", "telus", "phone bill", "insurance", "utility"], "Bills"),

        # Shopping
        (["amazon", "ebay", "best buy", "target", "ikea", "home depot", "canadian tire", "winners", "marshalls", "h&m", "zara", "gap", "nike", "adidas", "apple store", "electronics"], "Shopping"),

        # Rent
        (["rent", "lease", "landlord", "property", "apartment"], "Rent"),
    ]

    for keywords, category in category_rules:
        for keyword in keywords:
            if keyword in search_text:
                return category

    return ""  # No match found


def parse_receipt_text(text: str):
    """
    Very naive parsing:
    - Vendor: first non-empty line
    - Total: largest number with decimal
    - Date: first thing that looks like a date (dd/mm/yyyy, yyyy-mm-dd, etc.)
    - Category: auto-detected based on vendor/text keywords
    """
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    vendor = lines[0] if lines else ""

    # Find all numbers with decimal (e.g. 12.34, 123.45)
    amount_pattern = r"\d+\.\d{2}"
    amounts = re.findall(amount_pattern, text)
    total = ""
    if amounts:
        # Take the largest as "total"
        total = max(amounts, key=lambda x: float(x))

    # Very simple date regex patterns
    date_patterns = [
        r"\d{4}-\d{2}-\d{2}",        # yyyy-mm-dd
        r"\d{2}/\d{2}/\d{4}",        # dd/mm/yyyy or mm/dd/yyyy
        r"\d{2}-\d{2}-\d{4}",        # dd-mm-yyyy or mm-dd-yyyy
    ]

    date = ""
    for pattern in date_patterns:
        m = re.search(pattern, text)
        if m:
            date = m.group(0)
            break

    # Auto-detect category based on vendor and text
    category = detect_category(vendor, text)

    return {
        "vendor": vendor,
        "amount": total,
        "date": date,
        "category": category,
        "raw_text": text
    }
