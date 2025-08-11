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

# --- Initialize App and Load Models ---
app = Flask(__name__)
CORS(app)

try:
    # Load Keras autoencoder model (matches file present in repo)
    autoencoder_model = tf.keras.models.load_model('phishing_autoencoder_model.keras')
    with open('scaler.pkl', 'rb') as f: scaler = pickle.load(f)
    with open('autoencoder_threshold.txt', 'r') as f: autoencoder_threshold = float(f.read())
    # Try to load precomputed real-graph artifacts first
    gnn_probs = None
    post_node_map = None
    if os.path.exists('gnn_probs.npy') and os.path.exists('post_node_map.json'):
        try:
            gnn_probs = np.load('gnn_probs.npy')
            with open('post_node_map.json', 'r') as f:
                post_node_map = json.load(f)
            print('✅ Loaded real-graph GCN artifacts (gnn_probs.npy, post_node_map.json).')
        except Exception as e:
            print('❌ Failed loading real-graph artifacts:', e)

    # No simulation fallback: if not found, we will default structural score to 0.5
    print("✅ All models loaded successfully.")
except Exception as e:
    print(f"❌ Error loading models: {e}")
    autoencoder_model, scaler, autoencoder_threshold = None, None, None
    post_node_map, gnn_probs = None, None

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

# --- API Endpoint ---
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
        
        print(f"URL: {url} | Final Score: {final_score:.2f} -> Phishing: {is_phishing}")
        return jsonify({'is_phishing': is_phishing})

    except Exception as e:
        return jsonify({'error': str(e)}), 500


# --- Batch Prediction Endpoint ---
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

        return jsonify({'predictions': [
            { 'url': url, 'post_id': pid, 'is_phishing': pred }
            for url, pid, pred in zip(urls, post_ids, preds)
        ]})

    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)