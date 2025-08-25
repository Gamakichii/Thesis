import numpy as np
import pandas as pd
import pickle
from flask import Flask, request, jsonify
from flask_cors import CORS
import tensorflow as tf
import re
from urllib.parse import urlparse, urlunparse, parse_qsl, urlencode
import tldextract
import requests
import json
import os
import collections
from dotenv import load_dotenv
from google.oauth2 import service_account
from datetime import datetime, timedelta
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
effective_autoencoder_threshold = None
gnn_probs = None
post_node_map = None
models_last_loaded_at = None
classifier = None
classifier_meta = None

# Simple LRU cache for resolved shorteners
RESOLVED_SHORTENER_CACHE = {}
RESOLVED_SHORTENER_ORDER = collections.deque()
RESOLVED_SHORTENER_MAX = int(os.environ.get('SHORTENER_CACHE_MAX', '1024'))


def load_models():
    """Load model artifacts from disk and set global variables.
    This can be called at startup or via the /reload_models endpoint.
    """
    global MODEL_LOAD_ERROR, autoencoder_model, scaler, autoencoder_threshold, effective_autoencoder_threshold, gnn_probs, post_node_map, models_last_loaded_at
    MODEL_LOAD_ERROR = None
    autoencoder_model = None
    scaler = None
    autoencoder_threshold = None
    effective_autoencoder_threshold = None
    gnn_probs = None
    post_node_map = None
    try:
        # Load .env if present so env vars can be configured via file
        try:
            load_dotenv(os.path.join(HERE, '.env'))
        except Exception:
            pass
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

        # Apply optional multiplier from env var
        try:
            multiplier = float(os.environ.get('AE_THRESHOLD_MULTIPLIER', '1.0'))
        except Exception:
            multiplier = 1.0
        effective_autoencoder_threshold = float(autoencoder_threshold * multiplier)
        print(f"Effective AE threshold set to {effective_autoencoder_threshold} (multiplier={multiplier})")

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

        # Load fusion configuration if present (preferred over env defaults)
        fusion_path = os.path.join(HERE, "fusion_config.json")
        if os.path.exists(fusion_path):
            try:
                with open(fusion_path, "r") as f:
                    cfg = json.load(f)
                # Allow notebook-produced config to set AE threshold and AE weight
                if cfg.get('ae_threshold') is not None:
                    try:
                        autoencoder_threshold = float(cfg.get('ae_threshold'))
                        print("✅ Loaded ae_threshold from fusion_config.json")
                    except Exception:
                        print("⚠️ Invalid ae_threshold in fusion_config.json; ignoring")
                if cfg.get('fusion_weight_ae') is not None:
                    # set AE_WEIGHT env var default if not already set
                    os.environ.setdefault('AE_WEIGHT', str(cfg.get('fusion_weight_ae')))
                    print("✅ Loaded fusion_weight_ae from fusion_config.json into AE_WEIGHT env var")
                print("✅ Loaded fusion_config.json")
            except Exception as e:
                print("⚠️ Failed to load fusion_config.json:", e)

        # Load optional supervised classifier if present
        clf_path = os.path.join(HERE, 'phishing_classifier.pkl')
        meta_path = os.path.join(HERE, 'classifier_meta.json')
        try:
            if os.path.exists(clf_path) and os.path.exists(meta_path):
                with open(clf_path, 'rb') as f:
                    classifier = pickle.load(f)
                with open(meta_path, 'r') as f:
                    classifier_meta = json.load(f)
                print('✅ Loaded supervised classifier and meta.')
            else:
                print('No supervised classifier artifact found.')
        except Exception as e:
            print('Error loading classifier artifact:', e)

        models_last_loaded_at = __import__('datetime').datetime.utcnow().isoformat() + 'Z'

    except Exception as e:
        MODEL_LOAD_ERROR = str(e)
        print(f"❌ Error loading models: {e}")


# Load models at startup
load_models()

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
    # Normalize URL: remove common tracking query params that can inflate lexical features
    try:
        raw = url or ""
        p = urlparse(raw)
        if p.query:
            # Remove fbclid and utm_* params
            q = parse_qsl(p.query, keep_blank_values=True)
            q_filtered = [(k, v) for k, v in q if not (k.lower() == 'fbclid' or k.lower().startswith('utm_'))]
            new_query = urlencode(q_filtered)
            p = p._replace(query=new_query)
        u = urlunparse(p)
    except Exception:
        u = url or ""
    parts = tldextract.extract(u)
    # Known shortener domains (used to decide whether to attempt resolution)
    shorteners = {"bit.ly","tinyurl.com","t.co","goo.gl","ow.ly","is.gd","cutt.ly","lnkd.in","buff.ly"}
    # If URL is a known shortener, optionally resolve to the final destination to extract better features
    short_domain = (parts.domain + ('.' + parts.suffix if parts.suffix else '')).lower()
    resolve_short = os.environ.get('RESOLVE_SHORTENERS', '1') in ('1', 'true', 'yes')
    if resolve_short and short_domain in shorteners:
        final_url = None
        try:
            # Use LRU cache to avoid repeated network calls
            if u in RESOLVED_SHORTENER_CACHE:
                final_url = RESOLVED_SHORTENER_CACHE[u]
            else:
                try:
                    r = requests.head(u, allow_redirects=True, timeout=3)
                    final_url = r.url if r and getattr(r, 'url', None) else u
                except Exception:
                    try:
                        r = requests.get(u, allow_redirects=True, timeout=5)
                        final_url = r.url if r and getattr(r, 'url', None) else u
                    except Exception:
                        final_url = u
                # update LRU cache
                try:
                    RESOLVED_SHORTENER_CACHE[u] = final_url
                    RESOLVED_SHORTENER_ORDER.append(u)
                    if len(RESOLVED_SHORTENER_ORDER) > RESOLVED_SHORTENER_MAX:
                        old = RESOLVED_SHORTENER_ORDER.popleft()
                        RESOLVED_SHORTENER_CACHE.pop(old, None)
                except Exception:
                    pass
        except Exception:
            final_url = u

        # Replace u and recompute parts for final URL if resolution changed
        if final_url and final_url != u:
            try:
                u = final_url
                parts = tldextract.extract(u)
                domain = ".".join([p for p in [parts.subdomain, parts.domain, parts.suffix] if p])
                path_q = u.split(domain, 1)[-1] if domain and domain in u else ""
            except Exception:
                pass
    domain = ".".join([p for p in [parts.subdomain, parts.domain, parts.suffix] if p])
    path_q = u.split(domain, 1)[-1] if domain and domain in u else ""
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
    # Prefer explicit feature names saved with the scaler
    expected_cols = list(getattr(scaler, 'feature_names_in_', []))
    # If scaler lacks feature_names_in_ (older pickle / sklearn mismatch),
    # fall back to the legacy lexical feature list used by the pre-train notebook.
    if not expected_cols:
        # Use the exact lexical feature list from the updated pre-train notebook
        expected_cols = [
            'qty_dot_url', 'qty_hyphen_url', 'qty_underline_url', 'qty_slash_url', 
            'qty_questionmark_url', 'qty_equal_url', 'qty_at_url', 'qty_and_url', 
            'qty_exclamation_url', 'qty_space_url', 'qty_tilde_url', 'qty_comma_url', 
            'qty_plus_url', 'qty_asterisk_url', 'qty_hashtag_url', 'qty_dollar_url', 
            'qty_percent_url', 'qty_dot_domain', 'qty_hyphen_domain', 'qty_underline_domain', 
            'qty_at_domain', 'qty_vowels_domain', 'domain_length', 'domain_in_ip', 
            'server_client_domain'
        ]
        # If scaler knows the expected number of features, and it differs from
        # the legacy list length, try to honor scaler.n_features_in_ by padding
        n_in = getattr(scaler, 'n_features_in_', None)
        if isinstance(n_in, int) and n_in != len(expected_cols):
            # If scaler expects fewer dims, truncate; if more, pad with generic names
            if n_in < len(expected_cols):
                expected_cols = expected_cols[:n_in]
            else:
                expected_cols = expected_cols + [f"f{i}" for i in range(len(expected_cols), n_in)]
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
        recon = autoencoder_model.predict(scaled_features, verbose=0)
        error = float(np.mean(np.square(scaled_features - recon)))
        # Use effective threshold (multiplier-aware) if available
        thr = effective_autoencoder_threshold if effective_autoencoder_threshold is not None else autoencoder_threshold
        content_score = float(min(error / (thr * 2), 1.0))
        
        # 2. Structural Score from precomputed artifacts (default 0.5 if missing)
        structural_score = 0.5
        if post_node_map is not None and gnn_probs is not None:
            idx = post_node_map.get(str(post_id))
            if idx is not None and 0 <= idx < len(gnn_probs):
                structural_score = float(gnn_probs[idx])

        # 3. Fuse Scores (AE weight configurable via AE_WEIGHT env var)
        try:
            ae_weight = float(os.environ.get('AE_WEIGHT', '0.6'))
        except Exception:
            ae_weight = 0.6
        final_score = float((content_score * ae_weight) + (structural_score * (1.0 - ae_weight)))
        decision_cutoff = float(os.environ.get('FINAL_SCORE_CUTOFF', '0.5'))
        is_phishing = bool(final_score > decision_cutoff)
        
        used_gcn = bool(post_node_map is not None and gnn_probs is not None)
        # 4. Optional supervised classifier override/score
        classifier_prob = None
        try:
            if classifier is not None and classifier_meta is not None:
                # Build classifier feature vector: [content_score, gcn_prob] + scaled_features
                gcn_p = structural_score
                clf_vec = np.concatenate(([content_score, gcn_p], scaled_features[0])).reshape(1, -1)
                classifier_prob = float(classifier.predict_proba(clf_vec)[0,1])
                # If classifier strongly predicts phishing, bump final score
                if classifier_prob > float(os.environ.get('CLASSIFIER_OVERRIDE_THRESHOLD', '0.75')):
                    final_score = max(final_score, classifier_prob)
        except Exception as e:
            print('Classifier scoring failed:', e)
        # Detailed log for debugging
        print(f"URL: {url} | recon_error={error:.6f} content={content_score:.3f} gcn={structural_score:.3f} final={final_score:.3f} | phishing={is_phishing} gcn_used={used_gcn}")
        return jsonify({'is_phishing': is_phishing, 'used_gcn': used_gcn, 'final_score': final_score, 'reconstruction_error': error, 'content_score': content_score, 'ae_threshold_used': thr, 'ae_weight': ae_weight, 'final_score_cutoff': decision_cutoff, 'classifier_prob': classifier_prob})

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
        # Use effective threshold if available
        thr = effective_autoencoder_threshold if effective_autoencoder_threshold is not None else autoencoder_threshold
        content_scores = np.minimum(errors / (thr * 2), 1.0)

        # 2. Structural Scores from artifacts (or 0.5 if unavailable)
        if post_node_map is not None and gnn_probs is not None:
            idxs = [post_node_map.get(str(pid), None) for pid in post_ids]
            structural_scores = np.array([
                float(gnn_probs[i]) if (i is not None and 0 <= i < len(gnn_probs)) else 0.5
                for i in idxs
            ], dtype=float)
        else:
            structural_scores = np.full(len(post_ids), 0.5, dtype=float)

        # 3. Fuse Scores (configurable AE weight)
        try:
            ae_weight = float(os.environ.get('AE_WEIGHT', '0.6'))
        except Exception:
            ae_weight = 0.6
        final_scores = (ae_weight * content_scores) + ((1.0 - ae_weight) * structural_scores)
        decision_cutoff = float(os.environ.get('FINAL_SCORE_CUTOFF', '0.5'))
        preds = (final_scores > decision_cutoff).tolist()

        used_gcn = bool(post_node_map is not None and gnn_probs is not None)
        # Log detailed per-item diagnostics
        for u, pid, err, csc, gsc, fin, pr in zip(urls, post_ids, errors, content_scores, structural_scores, final_scores, preds):
            print(f"BATCH URL: {u} | recon_error={float(err):.6f} content={float(csc):.3f} gcn={float(gsc):.3f} final={float(fin):.3f} | phishing={bool(pr)}")

        return jsonify({'predictions': [
            { 'url': url, 'post_id': pid, 'is_phishing': bool(pred), 'used_gcn': used_gcn, 'reconstruction_error': float(err), 'content_score': float(csc), 'final_score': float(fin), 'ae_threshold_used': thr, 'ae_weight': ae_weight, 'final_score_cutoff': decision_cutoff }
            for url, pid, pred, err, csc, fin in zip(urls, post_ids, preds, errors.tolist(), content_scores.tolist(), final_scores.tolist())
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
    # Ensure payload always contains canonical keys so downstream consumers (notebooks) see them
    try:
        payload.setdefault('postId', payload.get('postId') or payload.get('post_id') or None)
        payload.setdefault('url', payload.get('url') or None)
    except Exception:
        payload = payload or {}
    user_id = body.get('userId') or 'anon'
    if not app_id or not rtype:
        return jsonify({'error': 'Missing app_id or type'}), 400
    try:
        col = fs_db.collection(f"artifacts/{app_id}/private_user_reports")
        # Compute label (1=phishing, 0=benign) to make downstream consumers' life easier
        try:
            label_val = 1 if rtype in ('true_positive', 'false_negative') else 0
        except Exception:
            label_val = None
        # Persist doc with normalized payload and label
        col.add({
            'type': rtype,
            'payload': payload,
            'userId': user_id,
            'url': payload.get('url'),
            'postId': payload.get('postId'),
            'label': label_val,
            'timestamp': firestore.SERVER_TIMESTAMP
        })
        return jsonify({'status': 'ok'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/report_bulk', methods=['POST'])
def report_bulk():
    """Accept a batch of report objects and store them in Firestore.
    Expected JSON: { "items": [ {"app_id":..., "type":..., "payload":..., "userId":...}, ... ] }
    """
    if not _fs_ok():
        return jsonify({'error': 'Firestore not configured on server'}), 500
    data = request.get_json() or {}
    items = data.get('items') or []
    if not isinstance(items, list) or len(items) == 0:
        return jsonify({'status': 'ok', 'written': 0})
    written = 0
    try:
        for it in items:
            app_id = it.get('app_id')
            rtype = it.get('type')
            payload = it.get('payload') or {}
            try:
                payload.setdefault('postId', payload.get('postId') or payload.get('post_id') or None)
                payload.setdefault('url', payload.get('url') or None)
            except Exception:
                payload = payload or {}
            user_id = it.get('userId') or 'anon'
            if not app_id or not rtype:
                continue
            col = fs_db.collection(f"artifacts/{app_id}/private_user_reports")
            try:
                label_val = 1 if rtype in ('true_positive', 'false_negative') else 0
            except Exception:
                label_val = None
            col.add({'type': rtype, 'payload': payload, 'userId': user_id, 'url': payload.get('url'), 'postId': payload.get('postId'), 'label': label_val, 'timestamp': firestore.SERVER_TIMESTAMP})
            written += 1
        return jsonify({'status': 'ok', 'written': written})
    except Exception as e:
        return jsonify({'error': str(e), 'written': written}), 500


@app.route('/review_queue', methods=['POST'])
def review_queue():
    """Accept a single review item or batch and store to Firestore under artifacts/{app_id}/review_queue"""
    if not _fs_ok():
        return jsonify({'error': 'Firestore not configured on server'}), 500
    data = request.get_json() or {}
    items = []
    # Accept either single dict or list under 'items'
    if isinstance(data, dict) and data.get('items'):
        items = data.get('items')
    elif isinstance(data, list):
        items = data
    elif isinstance(data, dict):
        items = [data]

    written = 0
    try:
        for it in items:
            app_id = it.get('app_id') or it.get('appId') or (it.get('app_id') or it.get('appId'))
            payload = it.get('payload') or it
            user_id = it.get('userId') or it.get('user_id') or 'anon'
            if not app_id:
                continue
            # Build a dedupe key from postId and url if present
            postId = None
            url = None
            try:
                postId = payload.get('postId') or payload.get('post_id')
            except Exception:
                postId = None
            try:
                url = payload.get('url')
            except Exception:
                url = None

            # Compute document id hash to dedupe
            import hashlib
            key_parts = [str(app_id)]
            if postId is not None:
                key_parts.append(str(postId))
            if url is not None:
                key_parts.append(str(url))
            doc_key_raw = '|'.join(key_parts)
            doc_id = hashlib.sha256(doc_key_raw.encode('utf-8')).hexdigest()

            col = fs_db.collection(f"artifacts/{app_id}/review_queue")
            doc_ref = col.document(doc_id)
            try:
                existing = doc_ref.get()
                if existing.exists:
                    # Already queued; skip to avoid duplicates
                    continue
                else:
                    # optional TTL: set expires_at if REVIEW_TTL_DAYS configured
                    expires_days = int(os.environ.get('REVIEW_TTL_DAYS', '0') or '0')
                    expires_at = None
                    if expires_days > 0:
                        expires_at = datetime.utcnow() + timedelta(days=expires_days)
                    payload_doc = {'payload': payload, 'userId': user_id, 'timestamp': firestore.SERVER_TIMESTAMP, 'processed': False}
                    if expires_at is not None:
                        payload_doc['expires_at'] = expires_at
                    doc_ref.set(payload_doc)
                    written += 1
            except Exception:
                # Fallback to add if document operations fail
                add_doc = {'payload': payload, 'userId': user_id, 'timestamp': firestore.SERVER_TIMESTAMP, 'processed': False}
                try:
                    expires_days = int(os.environ.get('REVIEW_TTL_DAYS', '0') or '0')
                    if expires_days > 0:
                        add_doc['expires_at'] = datetime.utcnow() + timedelta(days=expires_days)
                except Exception:
                    pass
                col.add(add_doc)
                written += 1
        return jsonify({'status': 'ok', 'written': written})
    except Exception as e:
        return jsonify({'error': str(e), 'written': written}), 500


@app.route('/reload_models', methods=['POST'])
def reload_models_endpoint():
    # security: restrict in production; for now anyone can call
    load_models()
    if MODEL_LOAD_ERROR:
        return jsonify({'status': 'error', 'message': MODEL_LOAD_ERROR}), 500
    return jsonify({'status': 'ok', 'models_last_loaded_at': models_last_loaded_at})


@app.route('/model_info', methods=['GET'])
def model_info():
    info = {
        'models_ready': bool(autoencoder_model is not None and scaler is not None and autoencoder_threshold is not None),
        'autoencoder_threshold': autoencoder_threshold,
        'effective_ae_threshold': effective_autoencoder_threshold,
        'scaler_type': type(scaler).__name__ if scaler is not None else None,
        'gnn_loaded': bool(gnn_probs is not None and post_node_map is not None),
        'models_last_loaded_at': models_last_loaded_at,
    }
    return jsonify(info)


@app.route('/debug/recent_reports', methods=['GET'])
def debug_recent_reports():
    """Return recent user reports and a small summary (counts per type/label).
    For safety this endpoint should be restricted in production; currently available for local debugging only.
    Query params: ?limit=50
    """
    if not _fs_ok():
        return jsonify({'error': 'Firestore not configured on server'}), 500
    try:
        limit = int(request.args.get('limit', '50'))
    except Exception:
        limit = 50
    try:
        col = fs_db.collection(f"artifacts/ads-phishing-link/private_user_reports")
        docs = list(col.order_by('timestamp', direction=firestore.Query.DESCENDING).limit(limit).stream())
        items = []
        counts_by_type = {}
        counts_by_label = { '0': 0, '1': 0, 'null': 0 }
        for d in docs:
            dd = d.to_dict()
            rtype = dd.get('type')
            payload = dd.get('payload') or {}
            label = dd.get('label') if 'label' in dd else (1 if rtype in ('true_positive', 'false_negative') else 0)
            counts_by_type[rtype] = counts_by_type.get(rtype, 0) + 1
            counts_by_label[str(label) if label is not None else 'null'] = counts_by_label.get(str(label), 0) + 1
            items.append({ 'id': d.id, 'type': rtype, 'label': label, 'url': dd.get('url') or payload.get('url'), 'postId': dd.get('postId') or payload.get('postId'), 'payload': payload, 'ts': dd.get('timestamp') })
        return jsonify({ 'count': len(items), 'by_type': counts_by_type, 'by_label': counts_by_label, 'items': items })
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
    app.run(host="0.0.0.0", port=8080)

