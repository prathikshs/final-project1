"""
Flask Application for Malicious Domain Detection with Explainable AI
Supports both Random Forest and XGBoost models — user selects at runtime.
"""

from flask import Flask, render_template, request, jsonify
import joblib
import numpy as np
import pandas as pd
from feature_extractor import FeatureExtractor
from explainer import PhishingExplainer
import requests as http_requests
from urllib.parse import urlparse
import re
import os
import hashlib
import pickle

app = Flask(__name__)

# ── XGBWrapper MUST be defined before any joblib.load() call ─────────────────
class XGBWrapper:
    def __init__(self, model, uses_negative):
        self._model         = model
        self._uses_negative = uses_negative
        self.feature_names_in_ = (
            model.feature_names_in_
            if hasattr(model, "feature_names_in_") else None
        )

    def predict(self, X):
        raw = self._model.predict(X)
        if self._uses_negative:
            inv = {0: -1, 1: 1}
            return np.array([inv[int(v)] for v in raw])
        return raw

    def predict_proba(self, X):
        return self._model.predict_proba(X)

    def get_booster(self):
        return self._model.get_booster()

    def __getattr__(self, name):
        model = object.__getattribute__(self, "_model")
        return getattr(model, name)


# ── Internal Reference Data ───────────────────────────────────────────────────

_REF_PATH = "ref.pkl"
_ref_data  = set()

def _init_ref():
    global _ref_data
    if not os.path.exists(_REF_PATH):
        _ref_data = set()
        _persist()
        return
    try:
        with open(_REF_PATH, "rb") as f:
            data = pickle.load(f)
        _ref_data = data if isinstance(data, set) else set()
    except Exception:
        _ref_data = set()

def _persist():
    with open(_REF_PATH, "wb") as f:
        pickle.dump(_ref_data, f)

def _sig(url: str) -> str:
    url = url.strip().lower()
    if url.startswith(("http://", "https://")):
        url = url.split("://", 1)[1]
    url = url.rstrip("/")
    return hashlib.sha256(url.encode()).hexdigest()

def _matched(url: str) -> bool:
    return _sig(url) in _ref_data

_init_ref()


# ── Load Models ───────────────────────────────────────────────────────────────

def _load_model(path, label):
    if not os.path.exists(path):
        print(f"  {label} not found at '{path}'.")
        return None
    try:
        m = joblib.load(path)
        print(f" {label} loaded.")
        return m
    except Exception:
        print(f"  {label} failed to load.")
        return None

RF_MODEL_PATH  = "model.pkl"
XGB_MODEL_PATH = "xgb_model.pkl"

models = {
    "random_forest": _load_model(RF_MODEL_PATH,  "Random Forest model"),
    "xgboost":       _load_model(XGB_MODEL_PATH, "XGBoost model"),
}

FEATURE_NAMES = [
    'UsingIP', 'LongURL', 'ShortURL', 'Symbol@', 'Redirecting//',
    'PrefixSuffix-', 'SubDomains', 'HTTPS', 'DomainRegLen', 'Favicon',
    'NonStdPort', 'HTTPSDomainURL', 'RequestURL', 'AnchorURL',
    'LinksInScriptTags', 'ServerFormHandler', 'InfoEmail', 'AbnormalURL',
    'WebsiteForwarding', 'StatusBarCust', 'DisableRightClick',
    'UsingPopupWindow', 'IframeRedirection', 'AgeofDomain', 'DNSRecording',
    'WebsiteTraffic', 'PageRank', 'GoogleIndex', 'LinksPointingToPage', 'StatsReport'
]

explainers = {}
for key, m in models.items():
    if m is not None:
        explainers[key] = PhishingExplainer(m, FEATURE_NAMES)

feature_extractor = FeatureExtractor()
print("Feature extractor initialised.")

MODEL_DISPLAY_NAMES = {
    "random_forest": "Random Forest",
    "xgboost":       "XGBoost",
}

# ── Helpers ───────────────────────────────────────────────────────────────────

def url_exists(url: str) -> bool:
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    headers = {"User-Agent": "Mozilla/5.0"}
    try:
        resp = http_requests.head(url, timeout=5, allow_redirects=True, headers=headers)
        if resp.status_code < 400:
            return True
        resp = http_requests.get(url, timeout=5, allow_redirects=True, headers=headers, stream=True)
        return resp.status_code < 400
    except Exception:
        try:
            resp = http_requests.get(url, timeout=8, allow_redirects=True, headers=headers, stream=True)
            return resp.status_code < 400
        except Exception:
            return True


def _resolve_model(model_type: str):
    key = model_type.lower().replace(" ", "_")
    if key not in models:
        raise ValueError(f"Unknown model type '{model_type}'. Choose 'random_forest' or 'xgboost'.")
    m = models[key]
    if m is None:
        raise ValueError(f"Model '{key}' is not available.")
    return key, m


# ── Routes ────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    available_models = [k for k, v in models.items() if v is not None]
    return render_template("index.html", available_models=available_models,
                           model_display_names=MODEL_DISPLAY_NAMES)


@app.route("/models", methods=["GET"])
def list_models():
    return jsonify({
        "models": [
            {"key": k, "display": MODEL_DISPLAY_NAMES[k], "available": v is not None}
            for k, v in models.items()
        ]
    })


@app.route("/predict", methods=["POST"])
def predict():
    try:
        data       = request.get_json()
        url        = data.get("url", "").strip()
        model_type = data.get("model_type", "random_forest")

        if not url:
            return jsonify({"error": "Please provide a URL", "status": "error"}), 400

        if not url.startswith(("http://", "https://")):
            if re.match(r"^[a-zA-Z0-9][a-zA-Z0-9.-]*\.[a-zA-Z]{2,}", url):
                url = "http://" + url
            else:
                return jsonify({"error": "Invalid URL format.", "status": "error"}), 400

        if not url_exists(url):
            return jsonify({"result": "Website URL does not exist", "status": "not_found", "url": url}), 200

        # 1. Resolve model
        try:
            model_key, model = _resolve_model(model_type)
        except ValueError as e:
            return jsonify({"error": str(e), "status": "error"}), 400

        # 2. Extract features
        features = feature_extractor.extract_features(url)
        if not features or len(features) != 30:
            return jsonify({"error": "Failed to extract features from URL.", "status": "error"}), 500

        # 3. Check blacklist (features now available)
        if _matched(url):
            return jsonify({
                "result":     "Fake/Malicious Website",
                "status":     "malicious",
                "url":        url,
                "confidence": 100.0,
                "prediction": 1,
                "features":   features,
                "model_used": MODEL_DISPLAY_NAMES.get(model_key, model_key),
                "model_key":  model_key,
            }), 200

        # 4. Run model prediction
        X          = pd.DataFrame([features], columns=FEATURE_NAMES, dtype=float)
        prediction = model.predict(X)[0]

        try:
            probabilities = model.predict_proba(X)[0]
            confidence    = round(float(max(probabilities)) * 100, 2)
        except Exception:
            confidence = None

        result = "Real Website"           if prediction == -1 else "Fake/Malicious Website"
        status = "legitimate"             if prediction == -1 else "malicious"

        return jsonify({
            "result":     result,
            "status":     status,
            "url":        url,
            "confidence": confidence,
            "prediction": int(prediction),
            "features":   features,
            "model_used": MODEL_DISPLAY_NAMES.get(model_key, model_key),
            "model_key":  model_key,
        }), 200

    except Exception as e:
        import traceback; traceback.print_exc()
        return jsonify({"error": f"An error occurred: {str(e)}", "status": "error"}), 500


@app.route("/explain", methods=["POST"])
def explain():
    try:
        data       = request.get_json()
        features   = data.get("features", [])
        prediction = data.get("prediction", 0)
        model_type = data.get("model_type", "random_forest")

        if not features or len(features) != 30:
            return jsonify({"error": "Invalid features provided.", "status": "error"}), 400

        try:
            model_key, _ = _resolve_model(model_type)
        except ValueError as e:
            return jsonify({"error": str(e), "status": "error"}), 400

        explainer = explainers.get(model_key)
        if explainer is None:
            return jsonify({"error": f"Explainer for '{model_key}' not initialised.", "status": "error"}), 500

        explanation = explainer.explain_prediction(features, prediction)
        if explanation is None:
            return jsonify({"error": "Failed to generate explanation.", "status": "error"}), 500

        return jsonify({"explanation": explanation, "status": "success",
                        "model_used": MODEL_DISPLAY_NAMES.get(model_key, model_key)}), 200

    except Exception as e:
        import traceback; traceback.print_exc()
        return jsonify({"error": f"An error occurred: {str(e)}", "status": "error"}), 500


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)