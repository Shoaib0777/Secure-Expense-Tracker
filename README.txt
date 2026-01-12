Cloud Expense Tracker - Option B (HTML/CSS/JS frontend + Flask API backend)

SETUP STEPS
-----------

1. Create a Firebase project with:
   - Firestore database (in Native mode)
   - Storage bucket

2. Download the service account key JSON from Firebase Console:
   Project Settings -> Service Accounts -> Generate new private key.
   Save it as: serviceAccountKey.json in this project root.

3. Edit firebase_config.py and replace:
   FIREBASE_STORAGE_BUCKET = "YOUR_BUCKET_NAME.appspot.com"
   with your actual bucket, e.g. "my-project-id.appspot.com".

4. Install system Tesseract OCR:
   - Linux: sudo apt install tesseract-ocr
   - macOS (brew): brew install tesseract
   - Windows: download from https://github.com/tesseract-ocr/tesseract
     and ensure the tesseract.exe path is in system PATH.

5. Create virtual environment (optional but recommended) and install Python deps:

   pip install -r requirements.txt

6. Run the app:

   python app.py

7. Open in browser:

   http://127.0.0.1:5000

USAGE
-----

- On first load, you will see a Login screen.
- Enter any username (no password). That username will be used to separate data.
- Use "Add Expense" to:
  * Upload a receipt file (image)
  * Click "Scan Receipt (OCR)" to auto-fill fields from text
  * Edit details if needed
  * Click "Save Expense" to store in Firebase Firestore and upload receipt to Storage.
- "Expenses" tab shows all saved expenses for the current user.
- "Dashboard" shows total spending and totals per category.
