# ai_models/train_bandwidth_model.py

import pandas as pd
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split

# Generate dummy data (replace with real pcap analysis results)
data = {
    "Upload_MB": [0.5, 2.3, 6.7, 1.2, 0.2, 5.5, 0.9, 7.0],
    "Hour": [10, 11, 22, 9, 8, 23, 16, 3],
    "Label": [0, 1, 1, 0, 0, 1, 0, 1]  # 1 = Anomalous, 0 = Normal
}

df = pd.DataFrame(data)
X = df[["Upload_MB", "Hour"]]
y = df["Label"]

model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X, y)
joblib.dump(model, "ai_models/bandwidth_anomaly_model.pkl")
print("✅ Model trained and saved.")
