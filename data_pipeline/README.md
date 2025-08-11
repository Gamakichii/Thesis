# Training data source

Your training now reads directly from Firestore in Colab and CI; exporting CSVs is optional. Keep this script only if you want periodic snapshots or offline inspection.

## Setup
1. Install dependencies:
```
pip install -r requirements.txt
```
2. Service account authentication:
- In Firebase console → Project settings → Service accounts → Generate new private key.
- Save the JSON locally and set the environment variable:
  - Windows PowerShell:
    ```powershell
    $env:GOOGLE_APPLICATION_CREDENTIALS = "D:\\Vanderlei\\Thesis\\firebase-sa.json"
    ```
  - CMD:
    ```bat
    set GOOGLE_APPLICATION_CREDENTIALS=C:\path\to\service_account.json
    ```

## Direct Firestore usage (recommended)
In Colab:
```
from google.colab import files
uploaded = files.upload()  # service-account.json
import os
sa = next(iter(uploaded.keys()))
os.environ["GOOGLE_APPLICATION_CREDENTIALS"] = f"/content/{sa}"

from google.cloud import firestore
db = firestore.Client()

APP_ID = "ads-phishing-link"
REPORTS = f"artifacts/{APP_ID}/private_user_reports"
FLAGGED = f"artifacts/{APP_ID}/public/data/flagged_phishing_links"

report_docs = list(db.collection(REPORTS).stream())
flagged_docs = list(db.collection(FLAGGED).stream())
```

Use these docs directly in your feature pipeline instead of a CSV.

## Output
The CSV contains:
- `url`, `normalized_url`, `label` (0 safe, 1 phishing), `source` (fp, fn, flagged), `userId`, `timestamp`.
- Deduplicated on `normalized_url` keeping the latest timestamp.

## Scheduling (Windows)
Create a daily task (adjust paths):
```bat
schtasks /Create /SC DAILY /ST 02:00 /TN "ExportFeedback" /TR "\"C:\\Path\\To\\Python.exe\" D:\\Vanderlei\\Thesis\\Thesis\\data_pipeline\\export_feedback.py --app-id your-app-id --include-flagged --output D:\\Vanderlei\\Thesis\\Thesis\\feedback_dataset.csv"
```

## GitHub Actions (optional)
If you keep scheduled snapshots, the workflow at `.github/workflows/export_feedback.yml` will export a CSV artifact from Firestore.

## Notes
- Ensure Firestore has documents under:
  - `artifacts/{app-id}/private_user_reports`
  - `artifacts/{app-id}/public/data/flagged_phishing_links`
- Rules: allow authenticated writes; deny reads for private; allow public reads for flagged if desired.
