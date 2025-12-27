# ai_models/dns_model/train_dns_model.py

import pandas as pd
from sklearn.ensemble import RandomForestClassifier
import joblib
import os

# Training data format (must match features used in `extract_features`)
df = pd.read_csv("training_data/dns_labeled_features.csv")

X = df.drop(columns=["label"])  # features
y = df["label"]  # Low, Intermediate, High

model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X, y)

os.makedirs("ai_models/dns_model", exist_ok=True)
joblib.dump(model, "ai_models/dns_model/model.pkl")
print("[+] Model saved to ai_models/dns_model/model.pkl")
