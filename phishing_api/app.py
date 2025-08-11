import numpy as np
import pandas as pd
import pickle
from flask import Flask, request, jsonify
from flask_cors import CORS
import tensorflow as tf
import torch
import torch.nn.functional as F
from torch_geometric.nn import GCNConv

# --- NEW: Import the real feature extractor ---
from feature_extractor import extract_features_from_url
from gnn_simulation import get_simulated_graph_data

# --- Initialize App and Load Models (Same as before) ---
app = Flask(__name__)
CORS(app)

try:
    autoencoder_model = tf.keras.models.load_model('phishing_autoencoder_model.h5')
    with open('scaler.pkl', 'rb') as f: scaler = pickle.load(f)
    with open('autoencoder_threshold.txt', 'r') as f: autoencoder_threshold = float(f.read())
    
    class GCN(torch.nn.Module):
        def __init__(self,num_features,num_classes):
            super(GCN,self).__init__()
            self.conv1=GCNConv(num_features,16)
            self.conv2=GCNConv(16,num_classes)
        def forward(self,data):
            x,edge_index=data.x,data.edge_index
            x=F.relu(self.conv1(x,edge_index))
            x=F.dropout(x,training=self.training)
            x=self.conv2(x,edge_index)
            return F.log_softmax(x,dim=1)
            
    gnn_model = GCN(num_features=1, num_classes=2)
    gnn_model.load_state_dict(torch.load('gnn_model.pth'))
    gnn_model.eval()
    graph_data = get_simulated_graph_data()
    print("✅ All models loaded successfully.")
except Exception as e:
    print(f"❌ Error loading models: {e}")
    autoencoder_model, gnn_model = None, None

# --- API Endpoint (Now uses the real extractor) ---
@app.route('/predict', methods=['POST'])
def predict():
    if not all([autoencoder_model, gnn_model]):
        return jsonify({'error': 'Models not loaded'}), 500
    
    data = request.get_json()
    url = data.get('url')
    post_id = data.get('post_id')
    if not url or not post_id:
        return jsonify({'error': 'Missing "url" or "post_id"'}), 400

    try:
        # --- 1. Content Score from Autoencoder ---
        # Use the real feature extractor instead of the placeholder
        features_df = extract_features_from_url(url)
        
        scaled_features = scaler.transform(features_df)
        reconstruction = autoencoder_model.predict(scaled_features, verbose=0)
        error = np.mean(np.square(scaled_features - reconstruction), axis=1)[0]
        content_score = min(error / (autoencoder_threshold * 2), 1.0)
        
        # --- 2. Structural Score from GNN ---
        with torch.no_grad():
            node_id = int(post_id.split('-').pop()) % 2000 + 500 # Simulate mapping
            probs = torch.exp(gnn_model(graph_data))
            structural_score = probs[node_id][1].item()

        # --- 3. Fuse Scores ---
        final_score = (content_score * 0.6) + (structural_score * 0.4)
        is_phishing = final_score > 0.5
        
        print(f"URL: {url} | Final Score: {final_score:.2f} -> Phishing: {is_phishing}")
        return jsonify({'is_phishing': is_phishing})

    except Exception as e:
        print(f"Prediction Error: {e}")
        return jsonify({'error': 'Failed to process URL.'}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)