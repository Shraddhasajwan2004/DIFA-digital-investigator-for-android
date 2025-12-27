# backend/analysis/permissions_audit.py

import os
import json
import hashlib
import zipfile
import logging
import datetime
import streamlit as st
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from typing import Dict, List
from ai_models.permission_model.predictor import PermissionRiskPredictor
from backend.zip_exporter import compute_file_hash

logging.basicConfig(level=logging.INFO)

OUTPUT_DIR = "reports/permissions"
os.makedirs(OUTPUT_DIR, exist_ok=True)

HASH_TYPES = ["sha256", "md5"]
RISK_LEVEL = "Risk Level"

DANGEROUS_PERMISSIONS = [
    "READ_SMS", "SEND_SMS", "RECEIVE_SMS", "READ_CONTACTS",
    "WRITE_CONTACTS", "ACCESS_FINE_LOCATION", "RECORD_AUDIO",
    "CAMERA", "READ_PHONE_STATE", "CALL_PHONE"
]

def generate_file_hashes(file_path: str) -> Dict[str, str]:
    hashes = {}
    with open(file_path, "rb") as f:
        data = f.read()
        if "sha256" in HASH_TYPES:
            hashes["sha256"] = hashlib.sha256(data).hexdigest()
        if "md5" in HASH_TYPES:
            hashes["md5"] = hashlib.md5(data).hexdigest()
    return hashes

def load_extracted_json(json_path: str) -> Dict:
    with open(json_path, "r") as f:
        return json.load(f)

def analyze_permissions(json_data: Dict) -> pd.DataFrame:
  if isinstance(json_data, list):
    try:
        json_data = {
            entry.get("package", f"app_{i}"): entry
            for i, entry in enumerate(json_data)
            if isinstance(entry, dict)
        }
    except Exception as e:
        st.error(f"Error processing uploaded file: {e}")
        st.stop()
  elif not isinstance(json_data, dict):
    st.error("Invalid data format: expected a JSON object or list of objects.")
    st.stop()

    if isinstance(json_data, list):
        json_data = {"unknown": {"runtime_permissions": json_data}}
    records = []
    for pkg, data in json_data.items():
        if pkg in ["device_admin_apps", "logcat", "runtime_permissions_xml"]:
            continue

        app_name = pkg.split(".")[-1].capitalize()
        manifest_perms = data.get("manifest_permissions", [])
        runtime_perms = data.get("runtime_permissions", [])
        all_perms = list(set(manifest_perms + runtime_perms))

        flat_perms = [p.split("/")[-1].split(".")[-1] for p in all_perms]

        risk = "Low"
        high_risk_matches = [p for p in flat_perms if p in DANGEROUS_PERMISSIONS]

        if high_risk_matches:
            risk = "High"
        elif len(flat_perms) >= 3:
            risk = "Intermediate"

        records.append({
            "App": app_name,
            "Package": pkg,
            "Permissions": ", ".join(flat_perms),
            RISK_LEVEL: risk,
            "High Risk Matches": ", ".join(high_risk_matches),
            "Dangerous Permission Count": len(high_risk_matches),
        })

    return pd.DataFrame(records)

def generate_report(json_data, predictor: PermissionRiskPredictor) -> str:
    # Handle if json_data is a list of dicts
    if isinstance(json_data, list):
        try:
            json_data = {
                entry.get("package", f"app_{i}"): entry
                for i, entry in enumerate(json_data)
                if isinstance(entry, dict)
            }
        except Exception as e:
            logging.error(f"Error converting list to dict: {e}")
            return ""
    elif not isinstance(json_data, dict):
        logging.error("Invalid input format: json_data must be a dict or list of dicts.")
        return ""

    report_rows = []
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

    for package, details in json_data.items():
        if package in ["logcat", "device_admin_apps", "runtime_permissions_xml"]:
            continue

        manifest_perms = details.get("manifest_permissions", [])
        runtime_perms = details.get("runtime_permissions", [])
        combined = list(set(manifest_perms + runtime_perms))

        clean_perms = [p.split("/")[-1].split(".")[-1]
                       for p in combined
                       if any(dp in p for dp in DANGEROUS_PERMISSIONS)]

        score, label = predictor.predict_risk(clean_perms, metadata={"app_category": 1})

        report_rows.append({
            "App Package": package,
            "Dangerous Permissions": ", ".join(clean_perms),
            "Risk Score": round(score, 2),
            RISK_LEVEL: label,
            "Timestamp": timestamp
        })

    df = pd.DataFrame(report_rows)
    report_csv = os.path.join(OUTPUT_DIR, f"permissions_report_{timestamp}.csv")
    df.to_csv(report_csv, index=False)
    logging.info(f"CSV report saved: {report_csv}")
    return report_csv


def generate_visualizations(csv_path: str):
    df = pd.read_csv(csv_path)
    sns.set(style="whitegrid")
    plt.figure(figsize=(10, 6))
    sns.countplot(data=df, x=RISK_LEVEL, palette="coolwarm")
    plt.title("App Risk Level Distribution")
    plt.savefig(csv_path.replace(".csv", "_risk_distribution.png"))
    plt.clf()
    plt.figure(figsize=(12, 8))
    df['Dangerous Permission Count'] = df['Dangerous Permissions'].apply(lambda x: len(x.split(", ")))
    sns.histplot(data=df, x='Dangerous Permission Count', hue=RISK_LEVEL, multiple="stack")
    plt.title("Dangerous Permission Count by Risk Level")
    plt.savefig(csv_path.replace(".csv", "_permissions_heatmap.png"))
    plt.close()

def zip_report_components(report_csv: str):
    zip_name = report_csv.replace(".csv", ".zip")
    with zipfile.ZipFile(zip_name, "w") as zipf:
        zipf.write(report_csv, os.path.basename(report_csv))
        for ext in ["_risk_distribution.png", "_permissions_heatmap.png"]:
            img_path = report_csv.replace(".csv", ext)
            if os.path.exists(img_path):
                zipf.write(img_path, os.path.basename(img_path))
    logging.info(f"Zipped report: {zip_name}")
    return zip_name

# Entry point for full report generation
if __name__ == "__main__":
    extracted_file = os.path.join("extracted_data", sorted(os.listdir("extracted_data"))[-1])
    data = load_extracted_json(extracted_file)
    predictor = PermissionRiskPredictor()
    report_csv = generate_report(data, predictor)
    generate_visualizations(report_csv)
    zip_report_components(report_csv)
    hashes = generate_file_hashes(report_csv)
    logging.info(f"Report Hashes: {hashes}")