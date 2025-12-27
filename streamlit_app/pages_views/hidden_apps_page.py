# pages_views/hidden_apps_page.py

import streamlit as st
import pandas as pd
import ast
import json
import os
from backend.analysis.hidden_apps import analyze_installed_apps, save_hidden_apps_report
from backend.extract.log_extractor import extract_hidden_apps_data  # Corrected import

def parse_uploaded_app_file(uploaded_file):
    if uploaded_file.name.endswith(".csv"):
        df = pd.read_csv(uploaded_file)
        apps = []
        for _, row in df.iterrows():
            apps.append({
                "app_name": row.get("app_name", ""),
                "package_name": row.get("package_name", ""),
                "permissions": ast.literal_eval(row.get("permissions", "[]")),
                "intents": ast.literal_eval(row.get("intents", "[]")),
                "apk_size_mb": row.get("apk_size_mb", 0),
                "last_used_days_ago": row.get("last_used_days_ago", 0),
                "first_seen": row.get("first_seen", "Unknown"),
            })
        return apps

    elif uploaded_file.name.endswith(".txt") or uploaded_file.name.endswith(".json"):
        try:
            content = uploaded_file.read().decode("utf-8")
            return json.loads(content)
        except Exception as e:
            st.error(f"Error parsing file: {e}")
            return []
    else:
        st.warning("Unsupported file type. Please upload a CSV or TXT/JSON file.")
        return []

def hidden_apps_ui():
    st.subheader("🕵️ Hidden Apps Scanner")
    st.markdown("This module detects apps that are potentially hidden, suspicious, or rarely used.")

    # Step 1: Upload or extract
    input_method = st.radio("Choose Input Method:", ["📤 Upload App List", "📱 Pull via ADB"])

    app_list = []

    if input_method == "📤 Upload App List":
        uploaded_file = st.file_uploader("Upload APK list (CSV, TXT, or JSON)", type=["csv", "txt", "json"])
        if uploaded_file:
            app_list = parse_uploaded_app_file(uploaded_file)

    elif input_method == "📱 Pull via ADB":
        if st.button("🔍 Extract from Connected Device"):
            with st.spinner("Extracting app list from device..."):
                app_list, _ = extract_hidden_apps_data()
                st.success(f"{len(app_list)} apps extracted from device.")

    # Step 2: Analyze
    if app_list:
        with st.spinner("Analyzing apps..."):
            result_df = analyze_installed_apps(app_list)
            csv_path, hash_path, zip_path = save_hidden_apps_report(result_df)

        st.success(f"Analysis complete. {len(result_df)} apps analyzed.")

        # Step 3: Show results
        st.markdown("### 📋 Hidden App Analysis Results")
        st.dataframe(result_df, use_container_width=True)

        st.markdown("### 📥 Download Reports")
        with open(csv_path, "rb") as f:
            st.download_button("📄 Download CSV", data=f, file_name=os.path.basename(csv_path), mime="text/csv")

        with open(zip_path, "rb") as fz:
            st.download_button("🗜️ Download ZIP", data=fz, file_name=os.path.basename(zip_path), mime="application/zip")
    else:
        st.info("Please upload a valid app list file or extract from ADB to proceed.")



