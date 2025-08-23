# preload_models.py
import os
import json
import numpy as np

# optional imports (keras/tf); attempt safe imports
keras = None
tf = None
try:
    import keras
except Exception:
    keras = None
try:
    import tensorflow as tf_
    tf = tf_
except Exception:
    tf = None

import pickle
import joblib

AUTOENCODER_MODEL_PATH = "phishing_autoencoder_model.keras"
CLASSIFIER_MODEL_PATH = "phishing_classifier_model.keras"
SCALER_PATH = "scaler.pkl"
THRESHOLD_PATH = "autoencoder_threshold.txt"
NODE_MAP_PATH = "post_node_map.json"
GNN_PROBS_PATH = "gnn_probs.npy"

print("🔄 Preloading models...")

def safe_load_keras_model(path):
    if not os.path.exists(path):
        print(f"⚠️ Not found: {path}")
        return None
    # try keras first, fallback to tf.keras
    if keras:
        try:
            m = keras.models.load_model(path)
            print(f"✅ Loaded (keras) {path}")
            return m
        except Exception as e:
            print(f"⚠️ keras failed for {path}: {e}")
    if tf:
        try:
            m = tf.keras.models.load_model(path)
            print(f"✅ Loaded (tf.keras) {path}")
            return m
        except Exception as e:
            print(f"⚠️ tf.keras failed for {path}: {e}")
    print(f"⚠️ Could not load Keras model at {path}")
    return None

# autoencoder
try:
    autoencoder = safe_load_keras_model(AUTOENCODER_MODEL_PATH)
except Exception as e:
    print("⚠️ Autoencoder load exception:", e)

# classifier (optional)
try:
    classifier = safe_load_keras_model(CLASSIFIER_MODEL_PATH)
except Exception as e:
    print("⚠️ Classifier load exception:", e)

# scaler
try:
    if os.path.exists(SCALER_PATH):
        try:
            scaler = joblib.load(SCALER_PATH)
            print("✅ Scaler loaded (joblib).")
        except Exception:
            with open(SCALER_PATH, "rb") as f:
                scaler = pickle.load(f)
            print("✅ Scaler loaded (pickle).")
    else:
        print("⚠️ Scaler file not found:", SCALER_PATH)
except Exception as e:
    print("⚠️ Failed to load scaler:", e)

# threshold
try:
    if os.path.exists(THRESHOLD_PATH):
        with open(THRESHOLD_PATH, "r") as f:
            threshold = float(f.read().strip())
        print("✅ Autoencoder threshold loaded:", threshold)
    else:
        print("⚠️ Threshold file not found:", THRESHOLD_PATH)
except Exception as e:
    print("⚠️ Failed to load threshold:", e)

# node map + gnn probs
try:
    if os.path.exists(NODE_MAP_PATH):
        with open(NODE_MAP_PATH, "r") as f:
            node_map = json.load(f)
        print("✅ Node map loaded")
    else:
        print("⚠️ Node map not found:", NODE_MAP_PATH)
except Exception as e:
    print("⚠️ Node map load failed:", e)

try:
    if os.path.exists(GNN_PROBS_PATH):
        gnn_probs = np.load(GNN_PROBS_PATH, allow_pickle=True)
        print("✅ GNN probabilities loaded")
    else:
        print("⚠️ gnn_probs.npy not found")
except Exception as e:
    print("⚠️ GNN probs load failed:", e)

print("🎉 Preload finished — models attempted.")
