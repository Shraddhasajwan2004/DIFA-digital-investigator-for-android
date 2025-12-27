# backend/bandwidth_analyzer.py

import os
import subprocess
import pandas as pd
import hashlib
from datetime import datetime
from scapy.all import rdpcap, TCP, IP
import joblib
from collections import defaultdict
OUTPUT_DIR = "forensics_output/bandwidth"
MODEL_PATH = "ai_models/bandwidth_anomaly_model.pkl"
os.makedirs(OUTPUT_DIR, exist_ok=True)

def pull_pcap_from_device():
    local_path = os.path.join(OUTPUT_DIR, "traffic.pcap")
    adb_path = "/sdcard/capture.pcap"
    subprocess.run(["adb", "pull", adb_path, local_path], check=True)
    return local_path

def extract_upload_data(pcap_path):
    packets = rdpcap(pcap_path)
    upload_data = defaultdict(int)

    for pkt in packets:
        try:
            if IP in pkt and TCP in pkt:
                if pkt[IP].src.startswith("192.") or pkt[IP].src.startswith("10.") or pkt[IP].src.startswith("172."):
                    timestamp = datetime.fromtimestamp(float(pkt.time)).replace(second=0, microsecond=0)
                    upload_data[timestamp] += int(len(pkt))
        except Exception as e:
            print(f"Error processing packet: {e}")

    df = pd.DataFrame(upload_data.items(), columns=["Timestamp", "Upload_Bytes"])
    df["Upload_MB"] = df["Upload_Bytes"] / (1024 * 1024)
    return df.sort_values("Timestamp")


def detect_after_hours(timestamp):
    return timestamp.hour < 9 or timestamp.hour >= 17

def detect_anomalies(df, threshold_mb=1.0, use_ml=False):
    df["After_Hours"] = df["Timestamp"].apply(detect_after_hours)

    if use_ml and os.path.exists(MODEL_PATH):
        model = joblib.load(MODEL_PATH)
        df["Hour"] = df["Timestamp"].dt.hour
        df["ML_Score"] = model.predict_proba(df[["Upload_MB", "Hour"]])[:, 1]  # Anomaly score
    else:
        df["ML_Score"] = 0.0

    def label(row):
        if row["Upload_MB"] > 5 or row["After_Hours"] or row["ML_Score"] > 0.8:
            return "High"
        elif row["Upload_MB"] > threshold_mb or row["ML_Score"] > 0.4:
            return "Intermediate"
        return "Low"

    df["Risk_Level"] = df.apply(label, axis=1)
    return df.drop(columns=["Hour"], errors="ignore")

def compute_sha256(file_path):
    with open(file_path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()

def export_report(df):
    csv_path = os.path.join(OUTPUT_DIR, "bandwidth_anomalies.csv")
    zip_path = os.path.join(OUTPUT_DIR, "bandwidth_report.zip")

    df.to_csv(csv_path, index=False)

    import zipfile
    with zipfile.ZipFile(zip_path, "w") as zipf:
        zipf.write(csv_path, arcname="bandwidth_anomalies.csv")

    return csv_path, zip_path
