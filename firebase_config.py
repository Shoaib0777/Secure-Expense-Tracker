import os
import firebase_admin
from firebase_admin import credentials, firestore, storage

# Path to your Firebase service account JSON file
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
FIREBASE_CRED_PATH = os.path.join(BASE_DIR, "serviceAccountKey.json")

# TODO: Replace this with your actual Firebase Storage bucket name
FIREBASE_STORAGE_BUCKET = "expense-tracker-dce60.firebasestorage.app"


def init_firebase():
    """
    Initialize Firebase app (if not already initialized) and return
    Firestore client and Storage bucket.
    """
    if not firebase_admin._apps:
        if not os.path.exists(FIREBASE_CRED_PATH):
            raise RuntimeError(
                "serviceAccountKey.json not found. "
                "Download it from Firebase Console and place it in the project root."
            )
        cred = credentials.Certificate(FIREBASE_CRED_PATH)
        firebase_admin.initialize_app(cred, {
            "storageBucket": FIREBASE_STORAGE_BUCKET
        })

    db = firestore.client()
    bucket = storage.bucket()
    return db, bucket
