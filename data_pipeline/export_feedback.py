import argparse
import os
from typing import List, Dict, Any
from urllib.parse import urlsplit, urlunsplit, parse_qsl, urlencode

import pandas as pd
from google.cloud import firestore


def normalize_url(raw_url: str) -> str:
    """Normalize URLs to improve deduplication and downstream feature generation.

    - Lowercase scheme and host
    - Strip default ports
    - Remove common tracking params (utm_*, fbclid, gclid, ref)
    - Collapse multiple slashes in path
    - Remove trailing slash (except for root)
    """
    if not raw_url:
        return raw_url
    try:
        tracking_params = {"fbclid", "gclid", "msclkid", "ref"}
        parts = urlsplit(raw_url)
        scheme = (parts.scheme or "http").lower()
        netloc = parts.netloc.lower()

        # Strip default ports
        if netloc.endswith(":80") and scheme == "http":
            netloc = netloc[:-3]
        if netloc.endswith(":443") and scheme == "https":
            netloc = netloc[:-4]

        # Clean query params
        query_pairs = parse_qsl(parts.query, keep_blank_values=False)
        cleaned = []
        for k, v in query_pairs:
            if k.startswith("utm_"):
                continue
            if k in tracking_params:
                continue
            cleaned.append((k, v))
        query = urlencode(cleaned, doseq=True)

        # Normalize path
        path = parts.path or "/"
        while "//" in path:
            path = path.replace("//", "/")
        if path != "/" and path.endswith("/"):
            path = path[:-1]

        return urlunsplit((scheme, netloc, path, query, ""))
    except Exception:
        return raw_url


def to_rows_from_reports(doc: Dict[str, Any]) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    t = doc.get("type")
    payload = doc.get("payload", {})
    uid = doc.get("userId")
    ts = doc.get("timestamp")
    if t == "false_positive":
        links = payload.get("links", []) or []
        for url in links:
            rows.append({
                "url": url,
                "normalized_url": normalize_url(url),
                "label": 0,
                "source": "fp",
                "userId": uid,
                "timestamp": ts,
            })
    elif t == "false_negative":
        url = payload.get("url")
        if url:
            rows.append({
                "url": url,
                "normalized_url": normalize_url(url),
                "label": 1,
                "source": "fn",
                "userId": uid,
                "timestamp": ts,
            })
    elif t == "true_positive":
        links = payload.get("links", []) or []
        for url in links:
            rows.append({
                "url": url,
                "normalized_url": normalize_url(url),
                "label": 1,
                "source": "tp",
                "userId": uid,
                "timestamp": ts,
            })
    elif t == "true_negative":
        links = payload.get("links", []) or []
        for url in links:
            rows.append({
                "url": url,
                "normalized_url": normalize_url(url),
                "label": 0,
                "source": "tn",
                "userId": uid,
                "timestamp": ts,
            })
    return rows


def to_rows_from_flagged(doc: Dict[str, Any]) -> Dict[str, Any]:
    url = doc.get("url")
    return {
        "url": url,
        "normalized_url": normalize_url(url),
        "label": 1,  # weak positive (optional)
        "source": "flagged",
        "userId": doc.get("userId"),
        "timestamp": doc.get("timestamp"),
    }


def export_feedback(app_id: str, include_flagged: bool) -> pd.DataFrame:
    db = firestore.Client()

    # Private user reports (collection path must have odd number of segments)
    reports_path = f"artifacts/{app_id}/private_user_reports"
    report_docs = db.collection(reports_path).stream()
    report_rows: List[Dict[str, Any]] = []
    for d in report_docs:
        report_rows.extend(to_rows_from_reports(d.to_dict()))

    frames = [pd.DataFrame(report_rows)]

    # Optional: public flagged links (weak positives)
    if include_flagged:
        flagged_path = f"artifacts/{app_id}/public/data/flagged_phishing_links"
        flagged_docs = db.collection(flagged_path).stream()
        flagged_rows = [to_rows_from_flagged(d.to_dict()) for d in flagged_docs]
        frames.append(pd.DataFrame(flagged_rows))

    if not frames:
        return pd.DataFrame(columns=["url", "normalized_url", "label", "source", "userId", "timestamp"]) 

    df = pd.concat(frames, ignore_index=True)

    # Sort and deduplicate by normalized_url
    if not df.empty:
        df = df.sort_values(by=["timestamp", "source"]).drop_duplicates(subset=["normalized_url"], keep="last")

    return df


def main():
    parser = argparse.ArgumentParser(description="Export labeled feedback data from Firestore to CSV")
    parser.add_argument("--app-id", default=os.environ.get("APP_ID", "default-app-id"), help="App ID used in Firestore paths (artifacts/{app-id}/...)")
    parser.add_argument("--output", default="feedback_dataset.csv", help="Output CSV path")
    parser.add_argument("--include-flagged", action="store_true", help="Include public flagged links as weak positives")
    args = parser.parse_args()

    df = export_feedback(app_id=args.app_id, include_flagged=args.include_flagged)
    df.to_csv(args.output, index=False)
    print(f"Saved {args.output} with {len(df)} rows")


if __name__ == "__main__":
    main()

 