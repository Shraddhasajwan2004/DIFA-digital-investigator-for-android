# backend/analysis/dns_log_analyzer.py

import re
import pandas as pd
from datetime import datetime
import hashlib
import joblib
import os
import zipfile

from backend.utils.threat_intel import is_domain_suspicious
from backend.utils.constants import DNS_MODEL_PATH
from backend.utils.csv_writer import write_df_to_csv
from backend.utils.file_hash import calculate_sha256

# Known suspicious TLDs and patterns
SUSPICIOUS_TLDS = [".xyz", ".tk", ".top", ".gq", ".ml", ".cf", ".onion"]
FREE_DOMAINS = ["duckdns.org", "freedns.afraid.org"]
SUSPICIOUS_KEYWORDS = ["dns-tunnel", "malware", "c2", "leak", "exploit"]

# Time range outside working hours
WORK_HOURS_START = 9
WORK_HOURS_END = 17

# Load ML model for risk scoring
try:
    model = joblib.load(DNS_MODEL_PATH)
except Exception as e:
    model = None
    print(f"[!] Warning: DNS ML model could not be loaded. {e}")

def parse_dns_log_line(line):
    pattern = r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}).*?query\s+(\S+)"
    match = re.search(pattern, line)
    if match:
        timestamp_str = match.group(1)
        domain = match.group(2).rstrip('.')
        try:
            timestamp = datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S")
            return timestamp, domain
        except ValueError:
            return None, None
    return None, None

def classify_risk(domain):
    domain = domain.lower()
    if any(tld in domain for tld in SUSPICIOUS_TLDS):
        return "High", "Suspicious TLD"
    if any(free in domain for free in FREE_DOMAINS):
        return "Intermediate", "Free Domain"
    if any(kw in domain for kw in SUSPICIOUS_KEYWORDS):
        return "Intermediate", "Keyword"
    if is_domain_suspicious(domain):
        return "High", "Threat Intel Match"
    return "Low", "Normal"

def extract_features(domain, timestamp):
    return {
        "domain_length": len(domain),
        "num_dots": domain.count('.'),
        "hour_accessed": timestamp.hour,
        "has_numeric": any(char.isdigit() for char in domain),
        "tld": domain.split('.')[-1],
    }

def predict_model_risk(domain, timestamp):
    if not model:
        return "Unknown"
    features = extract_features(domain, timestamp)
    df_feat = pd.DataFrame([features])
    try:
        pred = model.predict(df_feat)[0]
        return pred  # Low / Intermediate / High
    except Exception as e:
        return "Unknown"

def analyze_dns_logs(file_path):
    parsed_data = []
    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            timestamp, domain = parse_dns_log_line(line)
            if timestamp and domain:
                after_hours = not (WORK_HOURS_START <= timestamp.hour < WORK_HOURS_END)
                heuristic_risk, reason = classify_risk(domain)
                model_risk = predict_model_risk(domain, timestamp)
                parsed_data.append({
                    "Timestamp": timestamp,
                    "Domain": domain,
                    "Accessed After Hours": after_hours,
                    "Heuristic Risk": heuristic_risk,
                    "Reason": reason,
                    "Model Risk": model_risk
                })

    df = pd.DataFrame(parsed_data)

    if df.empty:
        return df, None, None, None

    # Save CSV
    timestamp_str = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_dir = "reports/dns_logs"
    os.makedirs(report_dir, exist_ok=True)
    csv_path = os.path.join(report_dir, f"dns_analysis_{timestamp_str}.csv")
    write_df_to_csv(df, csv_path)

    # Hash file
    hash_path = os.path.join(report_dir, f"hash_{timestamp_str}.txt")
    with open(hash_path, "w") as h:
        h.write(f"SHA256: {calculate_sha256(csv_path)}\nFile: {csv_path}\n")

    # Zip
    zip_path = os.path.join("reports/zipped_reports", f"dns_report_{timestamp_str}.zip")
    os.makedirs(os.path.dirname(zip_path), exist_ok=True)
    with zipfile.ZipFile(zip_path, 'w') as z:
        z.write(csv_path, os.path.basename(csv_path))
        z.write(hash_path, os.path.basename(hash_path))

    return df, csv_path, hash_path, zip_path

if __name__ == "__main__":
    test_file = "sample_dns_log.txt"
    df, csv, hsh, z = analyze_dns_logs(test_file)
    print(df.head())
    print(f"CSV Path: {csv}")
    print(f"Hash Path: {hsh}")
    print(f"ZIP Path: {z}")
