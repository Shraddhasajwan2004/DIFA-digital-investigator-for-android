# ai_models/hidden_apps_model/train_hidden_model.py
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
import pickle
import os

# Dummy training data
data = [
    {"has_launcher_intent": 0, "num_permissions": 25, "app_size_mb": 15.4, "last_used_days_ago": 180, "label": 1},  # Hidden
    {"has_launcher_intent": 1, "num_permissions": 5, "app_size_mb": 30.1, "last_used_days_ago": 1, "label": 0},    # Normal
    {"has_launcher_intent": 0, "num_permissions": 20, "app_size_mb": 12.3, "last_used_days_ago": 300, "label": 1},  # Hidden
    {"has_launcher_intent": 1, "num_permissions": 8, "app_size_mb": 25.0, "last_used_days_ago": 5, "label": 0},    # Normal
]

df = pd.DataFrame(data)
X = df.drop("label", axis=1)
y = df["label"]

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

model = RandomForestClassifier(
    n_estimators=100,
    max_features='sqrt',
    min_samples_leaf=2,
    random_state=42
)

model.fit(X_train, y_train)

# Save the model
os.makedirs("ai_models/hidden_apps_model", exist_ok=True)
with open("ai_models/hidden_apps_model/model.pkl", "wb") as f:
    pickle.dump(model, f)

print("✅ Model trained and saved to model.pkl")

