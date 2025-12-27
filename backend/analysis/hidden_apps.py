# backend/analysis/hidden_apps.py

import os
import pandas as pd
import zipfile
from datetime import datetime
from backend.utils.file_hash import calculate_sha256
from backend.utils.csv_writer import write_df_to_csv
from ai_models.hidden_apps_model.predictor import load_model, predict_risk

# Suspicious indicators
SUSPICIOUS_KEYWORDS = ["spy", "hide", "vault", "stealth", "incognito", "ghost"]
LAUNCHER_INTENT_KEY = "android.intent.category.LAUNCHER"

def analyze_installed_apps(apps_list):
    entries = []

    # Build feature DataFrame for ML model
    features = []
    for app in apps_list:
        has_launcher = LAUNCHER_INTENT_KEY in app.get("intents", [])
        features.append({
            "has_launcher_intent": has_launcher,
            "num_permissions": len(app.get("permissions", [])),
            "app_size_mb": app.get("apk_size_mb", 0),
            "last_used_days_ago": app.get("last_used_days_ago", 0)
        })

    # Predict ML risk
    df_features = pd.DataFrame(features)
    ml_preds = predict_risk(df_features)

    # Loop through apps and append metadata + risk
    for idx, app in enumerate(apps_list):
        app_name = app.get("app_name", "")
        package = app.get("package_name", "")
        permissions = app.get("permissions", [])
        intents = app.get("intents", [])
        size_mb = app.get("apk_size_mb", 0)
        first_seen = app.get("first_seen", "Unknown")
        last_used = app.get("last_used_days_ago", 0)

        has_launcher = LAUNCHER_INTENT_KEY in intents
        keyword_flag = any(kw in app_name.lower() for kw in SUSPICIOUS_KEYWORDS)

        model_risk = ml_preds[idx]

        if not has_launcher or keyword_flag or model_risk == "High":
            risk = "High"
            reason = "Hidden intent or Suspicious keyword or High ML score"
        elif model_risk == "Intermediate":
            risk = "Intermediate"
            reason = "Intermediate ML score"
        else:
            risk = "Low"
            reason = "Normal behavior"

        entries.append({
            "App Name": app_name,
            "Package Name": package,
            "Has Launcher Intent": has_launcher,
            "Suspicious Keyword in Name": keyword_flag,
            "Permissions Count": len(permissions),
            "App Size (MB)": size_mb,
            "Last Used (days ago)": last_used,
            "First Seen": first_seen,
            "ML Risk Prediction": model_risk,
            "Risk Level": risk,
            "Reason": reason
        })

    return pd.DataFrame(entries)


def save_hidden_apps_report(df: pd.DataFrame):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_dir = "reports/hidden_apps"
    zip_dir = "reports/zipped_reports"
    os.makedirs(report_dir, exist_ok=True)
    os.makedirs(zip_dir, exist_ok=True)

    # CSV path
    csv_path = os.path.join(report_dir, f"hidden_apps_report_{timestamp}.csv")
    write_df_to_csv(df, csv_path)

    # SHA256 hash
    hash_val = calculate_sha256(csv_path)
    hash_path = os.path.join(report_dir, f"hash_{timestamp}.txt")
    with open(hash_path, "w") as f:
        f.write(f"SHA256: {hash_val}\nFile: {csv_path}\n")

    # ZIP everything
    zip_path = os.path.join(zip_dir, f"hidden_apps_{timestamp}.zip")
    with zipfile.ZipFile(zip_path, "w") as zipf:
        zipf.write(csv_path, os.path.basename(csv_path))
        zipf.write(hash_path, os.path.basename(hash_path))

    return csv_path, hash_path, zip_path

# Debug/Test
if __name__ == "__main__":
    dummy_apps = [
        {
            "app_name": "Vault App",
            "package_name": "com.stealth.vault",
            "permissions": ["CAMERA", "READ_SMS", "INTERNET"],
            "intents": [],
            "apk_size_mb": 15.4,
            "last_used_days_ago": 180,
            "first_seen": "2025-07-01"
        },
        {
            "app_name": "WhatsApp",
            "package_name": "com.whatsapp",
            "permissions": ["INTERNET", "ACCESS_NETWORK_STATE"],
            "intents": [LAUNCHER_INTENT_KEY],
            "apk_size_mb": 30.1,
            "last_used_days_ago": 1,
            "first_seen": "2025-06-28"
        }
    ]
    df = analyze_installed_apps(dummy_apps)
    print(df)
    save_hidden_apps_report(df)

