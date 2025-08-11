# Data Export Pipeline

This pipeline exports labeled feedback (false positives/negatives and optional flagged links) from Firestore to a CSV for model retraining.

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
    $env:GOOGLE_APPLICATION_CREDENTIALS = "C:\\path\\to\\service_account.json"
    ```
  - CMD:
    ```bat
    set GOOGLE_APPLICATION_CREDENTIALS=C:\path\to\service_account.json
    ```

## Usage
Run the exporter from the `data_pipeline` directory:
```
python export_feedback.py --app-id your-app-id --include-flagged --output ..\\feedback_dataset.csv
```
- `--app-id` must match the `appId` you use in the extension (e.g., your Firebase project ID or a chosen namespace).
- `--include-flagged` adds public flagged links as weak positives (optional).
- `--output` path for the CSV (defaults to `feedback_dataset.csv`).

## Output
The CSV contains:
- `url`, `normalized_url`, `label` (0 safe, 1 phishing), `source` (fp, fn, flagged), `userId`, `timestamp`.
- Deduplicated on `normalized_url` keeping the latest timestamp.

## Scheduling (Windows)
Create a daily task (adjust paths):
```bat
schtasks /Create /SC DAILY /ST 02:00 /TN "ExportFeedback" /TR "\"C:\\Path\\To\\Python.exe\" D:\\Vanderlei\\Thesis\\Thesis\\data_pipeline\\export_feedback.py --app-id your-app-id --include-flagged --output D:\\Vanderlei\\Thesis\\Thesis\\feedback_dataset.csv"
```

## GitHub Actions
A workflow is included at `.github/workflows/export_feedback.yml` that runs daily and can be triggered manually.

- Add repository secrets:
  - `GCP_SA_KEY`: Paste the entire JSON content of your service account key.
  - `APP_ID`: Your app ID used in Firestore paths (same as in the extension).
- Trigger manually with inputs (optional): `app_id`, `include_flagged`.
- The CSV will be available as an artifact named `feedback-dataset`.

## Notes
- Ensure Firestore has documents under:
  - `artifacts/{app-id}/private/user_reports`
  - `artifacts/{app-id}/public/data/flagged_phishing_links`
- Firestore rules should allow authenticated writes to both, and public read only for the flagged links path.
