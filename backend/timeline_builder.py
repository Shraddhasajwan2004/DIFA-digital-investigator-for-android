# backend/timeline_builder.py

import pandas as pd
import os

def load_csv_with_source(path, source):
    if not os.path.exists(path):
        return pd.DataFrame()
    df = pd.read_csv(path)
    df["Source"] = source
    return df

def build_timeline():
    dfs = []

    # DNS Logs
    dns = load_csv_with_source("reports/dns_logs/dns_log_summary.csv", "DNS Logs")
    if not dns.empty and "Timestamp" in dns.columns:
        dns.rename(columns={"Domain": "Activity"}, inplace=True)
        dfs.append(dns[["Timestamp", "Activity", "Risk Level", "Source"]])

    # Email Headers
    email = load_csv_with_source("reports/email_headers/email_analysis.csv", "Email")
    if not email.empty and "Timestamp" in email.columns:
        email["Activity"] = "Email from: " + email["From"]
        dfs.append(email[["Timestamp", "Activity", "Risk Level", "Source"]])

    # SSL Certificates
    ssl = load_csv_with_source("reports/ssl_certs/ssl_certificates.csv", "SSL")
    if not ssl.empty and "Timestamp" in ssl.columns:
        ssl["Activity"] = "SSL to: " + ssl["Domain"]
        dfs.append(ssl[["Timestamp", "Activity", "Risk Level", "Source"]])

    # Hidden Apps (last used timestamp)
    hidden = load_csv_with_source("reports/hidden_apps/hidden_apps_report.csv", "Hidden App")
    if not hidden.empty and "First Seen" in hidden.columns:
        hidden.rename(columns={"First Seen": "Timestamp", "App Name": "Activity"}, inplace=True)
        dfs.append(hidden[["Timestamp", "Activity", "Risk Level", "Source"]])

    # Bandwidth
    bw = load_csv_with_source("reports/bandwidth/bandwidth_analysis.csv", "Bandwidth")
    if not bw.empty and "Timestamp" in bw.columns:
        bw["Activity"] = "Upload to: " + bw["Destination"]
        dfs.append(bw[["Timestamp", "Activity", "Risk Level", "Source"]])

    # Combine all
    timeline_df = pd.concat(dfs, ignore_index=True)
    timeline_df["Timestamp"] = pd.to_datetime(timeline_df["Timestamp"], errors="coerce")
    timeline_df.dropna(subset=["Timestamp"], inplace=True)
    timeline_df.sort_values(by="Timestamp", inplace=True)

    return timeline_df
