import numpy as np
import pandas as pd
import pickle
from flask import Flask, request, jsonify
from flask_cors import CORS
import tensorflow as tf
import re
import tldextract
import json
import os
from google.oauth2 import service_account
from google.cloud import firestore

# --- Define the base directory for model artifacts ---
HERE = os.path.dirname(os.path.abspath(__file__))

# --- Initialize App ---
app = Flask(__name__)
CORS(app, origins=["*"])  # Allow all origins for Chrome extension

# Azure Container App will inject PORT
PORT = int(os.environ.get("PORT", 8000))

# --- Model Loading ---
MODEL_LOAD_ERROR = None
autoencoder_model = None
scaler = None
autoencoder_threshold = None
gnn_probs = None
post_node_map = None

try:
    # Load Autoencoder model (.keras)
    model_path = os.path.join(HERE, "phishing_autoencoder_model.keras")
    try:
        import keras  # Keras 3
        os.environ.setdefault("KERAS_BACKEND", "tensorflow")
        autoencoder_model = keras.models.load_model(model_path)
        print("✅ Loaded autoencoder model with Keras 3.")
    except Exception as e_k3:
        print(f"⚠️ Keras 3 load failed, trying tf.keras: {e_k3}")
        autoencoder_model = tf.keras.models.load_model(model_path)
        print("✅ Loaded autoencoder model with tf.keras.")

    # Load Scaler (try scaler.pkl then scaler_final.pkl)
    for sp in [os.path.join(HERE, "scaler.pkl"), os.path.join(HERE, "scaler_final.pkl")]:
        if os.path.exists(sp):
            with open(sp, "rb") as f:
                scaler = pickle.load(f)
                print(f"✅ Loaded scaler from {sp}.")
                break
    if scaler is None:
        raise RuntimeError("Scaler file not found.")

    # Load Threshold
    threshold_path = os.path.join(HERE, "autoencoder_threshold.txt")
    if os.path.exists(threshold_path):
        with open(threshold_path, "r") as f:
            autoencoder_threshold = float(f.read())
        print("✅ Loaded autoencoder threshold.")
    else:
        raise RuntimeError("autoencoder_threshold.txt missing.")

    # Load GNN artifacts if present
    gnn_probs_path = os.path.join(HERE, "gnn_probs.npy")
    post_node_map_path = os.path.join(HERE, "post_node_map.json")
    if os.path.exists(gnn_probs_path) and os.path.exists(post_node_map_path):
        gnn_probs = np.load(gnn_probs_path)
        with open(post_node_map_path, "r") as f:
            post_node_map = json.load(f)
        print("✅ Loaded real-graph GCN artifacts.")
    else:
        print("⚠️ GNN artifacts not found, continuing without them.")

except Exception as e:
    MODEL_LOAD_ERROR = str(e)
    print(f"❌ Error loading models: {e}")

# --- Firestore Client ---
fs_db = None
try:
    google_creds = os.environ.get("GOOGLE_APPLICATION_CREDENTIALS_JSON")
    if google_creds:
        creds_info = json.loads(google_creds)
        creds = service_account.Credentials.from_service_account_info(creds_info)
        fs_db = firestore.Client(credentials=creds, project=creds_info["project_id"])
        print("✅ Firestore client initialized from environment variable.")
    else:
        # Fallback to local file
        for sa_path in [
            os.path.join(HERE, "firebase-sa.json"),
            os.path.join(HERE, "service-account.json"),
            os.path.join(HERE, "gcp-sa.json"),
        ]:
            if os.path.exists(sa_path):
                creds = service_account.Credentials.from_service_account_file(sa_path)
                fs_db = firestore.Client(credentials=creds, project=creds.project_id)
                print(f"✅ Firestore client initialized from file: {os.path.basename(sa_path)}")
                break
        if fs_db is None:
            print("⚠️ No Firestore credentials found. Firestore writes disabled.")
except Exception as ee:
    print(f"⚠️ Firestore init failed: {ee}")

def _compute_lexical_subset(url: str) -> dict:
    u = url or ""
    parts = tldextract.extract(u)
    domain = ".".join([p for p in [parts.subdomain, parts.domain, parts.suffix] if p])
    path_q = u.split(domain, 1)[-1] if domain and domain in u else ""
    shorteners = {"bit.ly","tinyurl.com","t.co","goo.gl","ow.ly","is.gd","cutt.ly","lnkd.in","buff.ly"}

    feats = {
        "qty_dot_url": u.count("."),
        "qty_hyphen_url": u.count("-"),
        "qty_underline_url": u.count("_"),
        "qty_slash_url": u.count("/"),
        "qty_questionmark_url": u.count("?"),
        "qty_equal_url": u.count("="),
        "qty_at_url": u.count("@"),
        "qty_and_url": u.count("&"),
        "qty_exclamation_url": u.count("!"),
        "qty_space_url": u.count(" "),
        "qty_tilde_url": u.count("~"),
        "qty_comma_url": u.count(","),
        "qty_plus_url": u.count("+"),
        "qty_asterisk_url": u.count("*"),
        "qty_hashtag_url": u.count("#"),
        "qty_dollar_url": u.count("$"),
        "qty_percent_url": u.count("%"),
        "length_url": len(u),
        "url_shortened": int((parts.domain + "." + (parts.suffix or "")).lower() in shorteners),
        "qty_dot_domain": domain.count("."),
        "qty_hyphen_domain": domain.count("-"),
        "qty_underline_domain": domain.count("_"),
        "domain_length": len(domain),
        "domain_in_ip": int(bool(re.match(r"^\d+\.\d+\.\d+\.\d+$", domain))),
    }
    # Directory/file breakdown approx
    directory = path_q.rsplit("/", 1)[0] if "/" in path_q else ""
    filepart = path_q.rsplit("/", 1)[-1] if "/" in path_q else path_q
    for prefix, s in [("directory", directory), ("file", filepart)]:
        feats[f"qty_dot_{prefix}"] = s.count(".")
        feats[f"qty_hyphen_{prefix}"] = s.count("-")
        feats[f"qty_underline_{prefix}"] = s.count("_")
        feats[f"qty_slash_{prefix}"] = s.count("/")
        feats[f"qty_questionmark_{prefix}"] = s.count("?")
        feats[f"qty_equal_{prefix}"] = s.count("=")
        feats[f"qty_at_{prefix}"] = s.count("@")
        feats[f"qty_and_{prefix}"] = s.count("&")
        feats[f"qty_exclamation_{prefix}"] = s.count("!")
        feats[f"qty_space_{prefix}"] = s.count(" ")
        feats[f"qty_tilde_{prefix}"] = s.count("~")
        feats[f"qty_comma_{prefix}"] = s.count(",")
        feats[f"qty_plus_{prefix}"] = s.count("+")
        feats[f"qty_asterisk_{prefix}"] = s.count("*")
        feats[f"qty_hashtag_{prefix}"] = s.count("#")
        feats[f"qty_dollar_{prefix}"] = s.count("$")
        feats[f"qty_percent_{prefix}"] = s.count("%")
        feats[f"{prefix}_length"] = len(s)
    return feats

def extract_features_for_urls(urls):
    """Return DataFrame with columns matching scaler.feature_names_in_. Missing features are filled with scaler.mean_."""
    expected_cols = list(getattr(scaler, 'feature_names_in_', []))
    if not expected_cols:
        # Fallback to 111 dims
        expected_cols = [f"f{i}" for i in range(111)]
    base_means = getattr(scaler, 'mean_', np.zeros(len(expected_cols)))

    rows = []
    for u in urls:
        feats = _compute_lexical_subset(u)
        # Start with means to avoid missing keys
        row_vals = {col: float(base_means[i]) for i, col in enumerate(expected_cols)}
        # Override with computed where names match expected
        for k, v in feats.items():
            if k in row_vals:
                row_vals[k] = float(v)
        rows.append(row_vals)
    return pd.DataFrame(rows, columns=expected_cols)

# Health check endpoint
@app.route('/')
def health_check():
    return jsonify({'status': 'healthy', 'service': 'dakugumen-phishing-detector'})

# Readiness endpoint with diagnostic info
@app.route('/ready')
def ready_check():
    return jsonify({
        'models_ready': bool(autoencoder_model is not None and scaler is not None and autoencoder_threshold is not None),
        'error': MODEL_LOAD_ERROR,
    }), (200 if autoencoder_model is not None and scaler is not None and autoencoder_threshold is not None else 503)

# --- API Endpoints ---
@app.route('/predict', methods=['POST'])
def predict():
    if autoencoder_model is None or scaler is None or autoencoder_threshold is None:
        return jsonify({'error': 'Models not ready'}), 500
    
    data = request.get_json()
    url, post_id = data.get('url'), data.get('post_id')
    if not url or not post_id:
        return jsonify({'error': 'Missing "url" or "post_id"'}), 400

    try:
        # 1. Content Score
        features = extract_features_for_urls([url])
        scaled_features = scaler.transform(features)
        error = np.mean(np.square(scaled_features - autoencoder_model.predict(scaled_features, verbose=0)))
        content_score = min(error / (autoencoder_threshold * 2), 1.0)
        
        # 2. Structural Score from precomputed artifacts (default 0.5 if missing)
        structural_score = 0.5
        if post_node_map is not None and gnn_probs is not None:
            idx = post_node_map.get(str(post_id))
            if idx is not None and 0 <= idx < len(gnn_probs):
                structural_score = float(gnn_probs[idx])

        # 3. Fuse Scores
        final_score = (content_score * 0.6) + (structural_score * 0.4)
        is_phishing = final_score > 0.5
        
        used_gcn = bool(post_node_map is not None and gnn_probs is not None)
        print(f"URL: {url} | content={content_score:.2f} gcn={structural_score:.2f} final={final_score:.2f} | phishing={is_phishing} gcn_used={used_gcn}")
        return jsonify({'is_phishing': is_phishing, 'used_gcn': used_gcn, 'final_score': final_score})

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/predict_batch', methods=['POST'])
def predict_batch():
    if autoencoder_model is None or scaler is None or autoencoder_threshold is None:
        return jsonify({'error': 'Models not ready'}), 500

    data = request.get_json() or {}
    items = data.get('items') or []  # list of {url, post_id}
    if not isinstance(items, list) or len(items) == 0:
        return jsonify({'predictions': []})

    try:
        urls = [it.get('url') for it in items]
        post_ids = [it.get('post_id') for it in items]

        # 1. Content Scores (vectorized)
        feats = extract_features_for_urls(urls)
        scaled = scaler.transform(feats)
        recon = autoencoder_model.predict(scaled, verbose=0)
        errors = np.mean(np.square(scaled - recon), axis=1)
        content_scores = np.minimum(errors / (autoencoder_threshold * 2), 1.0)

        # 2. Structural Scores from artifacts (or 0.5 if unavailable)
        if post_node_map is not None and gnn_probs is not None:
            idxs = [post_node_map.get(str(pid), None) for pid in post_ids]
            structural_scores = np.array([
                float(gnn_probs[i]) if (i is not None and 0 <= i < len(gnn_probs)) else 0.5
                for i in idxs
            ], dtype=float)
        else:
            structural_scores = np.full(len(post_ids), 0.5, dtype=float)

        # 3. Fuse Scores
        final_scores = (0.6 * content_scores) + (0.4 * structural_scores)
        preds = (final_scores > 0.5).tolist()

        used_gcn = bool(post_node_map is not None and gnn_probs is not None)
        return jsonify({'predictions': [
            { 'url': url, 'post_id': pid, 'is_phishing': pred, 'used_gcn': used_gcn }
            for url, pid, pred in zip(urls, post_ids, preds)
        ]})

    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Server-side report/graph endpoints remain the same...
def _fs_ok():
    return fs_db is not None

@app.route('/report', methods=['POST'])
def report():
    if not _fs_ok():
        return jsonify({'error': 'Firestore not configured on server'}), 500
    body = request.get_json() or {}
    app_id = body.get('app_id')
    rtype = body.get('type')
    payload = body.get('payload') or {}
    user_id = body.get('userId') or 'anon'
    if not app_id or not rtype:
        return jsonify({'error': 'Missing app_id or type'}), 400
    try:
        col = fs_db.collection(f"artifacts/{app_id}/private_user_reports")
        col.add({'type': rtype, 'payload': payload, 'userId': user_id, 'timestamp': firestore.SERVER_TIMESTAMP})
        return jsonify({'status': 'ok'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/flag', methods=['POST'])
def flag():
    if not _fs_ok():
        return jsonify({'error': 'Firestore not configured on server'}), 500
    body = request.get_json() or {}
    app_id = body.get('app_id')
    url = body.get('url')
    user_id = body.get('userId') or 'anon'
    if not app_id or not url:
        return jsonify({'error': 'Missing app_id or url'}), 400
    try:
        col = fs_db.collection(f"artifacts/{app_id}/public/data/flagged_phishing_links")
        col.add({'url': url, 'userId': user_id, 'timestamp': firestore.SERVER_TIMESTAMP})
        return jsonify({'status': 'ok'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Add other endpoints (graph_ingest, graph_click) as in original...
# [Include remaining endpoints from your original app.py]

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=80)

