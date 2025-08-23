# debug_recon.py
import numpy as np
from pprint import pprint
from app import extract_features_for_urls, autoencoder_threshold, autoencoder_model, scaler

# Edit these URLs to test
urls = [
    "https://bit.ly/fake-login-scam?fbclid=EXAMPLE",
    "https://www.abs-cbn.com/news/regions/2025/8/20/more-flood-control-projects-collapse-in-oriental-mindoro-0105?fbclid=EXAMPLE"
]

print("autoencoder_threshold:", autoencoder_threshold)
print("scaler type:", type(scaler))
if hasattr(scaler, 'feature_names_in_'):
    fnames = list(getattr(scaler, 'feature_names_in_'))
    print("n features in scaler:", len(fnames))
    print("first 30 feature names:", fnames[:30])
else:
    fnames = [f"f{i}" for i in range(111)]
    print("scaler has no feature_names_in_, using fallback names length:", len(fnames))

feats = extract_features_for_urls(urls)
print("\nRaw features (first URL):")
pprint(feats.iloc[0].to_dict())

scaled = scaler.transform(feats)
print("\nScaled (first URL) first 30 dims:")
print(scaled[0][:30].tolist())

recon = autoencoder_model.predict(scaled, verbose=0)
errors = np.mean((scaled - recon)**2, axis=1)
print("\nReconstruction errors:", errors.tolist())

# per-feature squared diffs for first URL
sqdiff = (scaled[0] - recon[0])**2
top_idx = np.argsort(-sqdiff)[:20]
print("\nTop feature reconstruction errors (index, name, sqdiff, scaled_val, recon_val):")
for i in top_idx:
    name = fnames[i] if i < len(fnames) else f"f{i}"
    print(i, name, float(sqdiff[i]), float(scaled[0,i]), float(recon[0,i]))

# Compute scores as server does
content_scores = np.minimum(errors / (autoencoder_threshold * 2), 1.0)
structural_scores = np.full(len(urls), 0.5)
final_scores = 0.6 * content_scores + 0.4 * structural_scores
print("\ncontent_scores:", content_scores.tolist())
print("final_scores:", final_scores.tolist())
print("is_phishing:", (final_scores > 0.5).tolist())