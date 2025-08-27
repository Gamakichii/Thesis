import tensorflow as tf
import joblib
import keras
import numpy as np
import json
import os

# Paths to your models and preprocessors
AUTOENCODER_MODEL_PATH = "phishing_autoencoder_model.keras"
CLASSIFIER_MODEL_PATH = "phishing_classifier_model.keras"
SCALER_PATH = "scaler.pkl"
THRESHOLD_PATH = "autoencoder_threshold.txt"
NODE_MAP_PATH = "post_node_map.json"
GNN_PROBS_PATH = "gnn_probs.npy"

print("🔄 Preloading models...")

# --- Keras models ---
try:
    autoencoder = keras.models.load_model(AUTOENCODER_MODEL_PATH)
    print("✅ Autoencoder loaded")
except Exception as e:
    print(f"⚠️ Failed to load autoencoder: {e}")

try:
    classifier = keras.models.load_model(CLASSIFIER_MODEL_PATH)
    print("✅ Classifier loaded")
except Exception as e:
    print(f"⚠️ Failed to load classifier: {e}")

# --- Scaler ---
try:
    scaler = joblib.load(SCALER_PATH)
    print("✅ Scaler loaded")
except Exception as e:
    print(f"⚠️ Failed to load scaler: {e}")

# --- Threshold ---
try:
    with open(THRESHOLD_PATH, "r") as f:
        threshold = float(f.read().strip())
    print(f"✅ Autoencoder threshold loaded: {threshold}")
except Exception as e:
    print(f"⚠️ Failed to load threshold: {e}")

# --- Node map ---
try:
    with open(NODE_MAP_PATH, "r") as f:
        node_map = json.load(f)
    print("✅ Node map loaded")
except Exception as e:
    print(f"⚠️ Failed to load node map: {e}")

# --- GNN probabilities (optional, just precomputed .npy) ---
try:
    if os.path.exists(GNN_PROBS_PATH):
        gnn_probs = np.load(GNN_PROBS_PATH, allow_pickle=True)
        print("✅ GNN probabilities loaded")
except Exception as e:
    print(f"⚠️ Failed to load GNN probabilities: {e}")

print("🎉 Preload finished — models are ready.")
