# permissions_audit/predictor.py
import json
import os
import joblib
import logging
import numpy as np
import pandas as pd
from typing import List, Dict, Tuple
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder
from sklearn.model_selection import train_test_split

logging.basicConfig(level=logging.INFO)

MODEL_PATH = "ai_models/permissions_risk_model.pkl"
EXAMPLE_DATA_PATH = "ai_models/example_training_data.csv"

# Example dangerous permissions for feature vector construction
DANGEROUS_PERMISSIONS = [
    "READ_SMS", "SEND_SMS", "RECEIVE_SMS", "READ_CONTACTS",
    "WRITE_CONTACTS", "ACCESS_FINE_LOCATION", "RECORD_AUDIO",
    "CAMERA", "READ_PHONE_STATE", "CALL_PHONE"
]

RISK_LABELS = {0: "Low", 1: "Intermediate", 2: "High"}

class PermissionRiskPredictor:
    def __init__(self):
        self.model = None
        self.label_encoder = LabelEncoder()
        self._load_or_init_model()

    def _load_or_init_model(self):
        if os.path.exists(MODEL_PATH):
            self.model = joblib.load(MODEL_PATH)
            logging.info("Loaded pre-trained model from disk.")
        else:
            self.model = RandomForestClassifier(
            n_estimators=100,
            random_state=42,
            min_samples_leaf=1,
            max_features="sqrt"
            )
            self.model.fit(np.zeros((1, len(DANGEROUS_PERMISSIONS) + 1)), [0])  # Dummy fit
            logging.warning("No model found. Initialized new RandomForestClassifier.")

    def _extract_features(self, permissions: List[str], metadata: Dict = None) -> np.ndarray:
        vector = [1 if p in permissions else 0 for p in DANGEROUS_PERMISSIONS]
        # Add placeholder for metadata-based features
        vector.append(metadata.get("app_category", 0) if metadata else 0)
        return np.array(vector).reshape(1, -1)

def predict_risk(self, permissions: List[str], metadata: Dict = None) -> Tuple[float, str]:
    features = self._extract_features(permissions, metadata)
    if not self.model:
        raise RuntimeError("Model not loaded.")
    
    probs = self.model.predict_proba(features)[0]
    if len(probs) > 1:
        risk_score = probs[1]  # Intermediate risk class
    else:
        risk_score = 1.0 if self.model.classes_[0] == 1 else 0.0

    risk_class = self.model.predict(features)[0]
    return float(risk_score), RISK_LABELS.get(risk_class, "Unknown")


def train_model(self, csv_path: str = EXAMPLE_DATA_PATH):
        if not os.path.exists(csv_path):
            raise FileNotFoundError("Training CSV not found.")
        df = pd.read_csv(csv_path)
        X = df[DANGEROUS_PERMISSIONS + ["app_category"]]
        y = df["risk"]  # Expect values: 0 (Low), 1 (Intermediate), 2 (High)
        x_train, x_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
        self.model.fit(x_train, y_train)
        joblib.dump(self.model, MODEL_PATH)
        logging.info("Model trained and saved.")

# Example usage for inference
if __name__ == "__main__":
    predictor = PermissionRiskPredictor()
    sample_permissions = ["READ_SMS", "ACCESS_FINE_LOCATION"]
    metadata = {"app_category": 1}  # e.g., social = 1, system = 0, etc.
    score, label = predictor.predict_risk(sample_permissions, metadata)
    print(f"Predicted risk score: {score:.2f}, classification: {label}")
