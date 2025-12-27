# streamlit_app/pages_views/permissions_analysis_page.py

import os
import json
import streamlit as st
from backend.analysis.permissions_audit import analyze_permissions, generate_visualizations, generate_report, zip_report_components
from backend.extract.adb_connector import auto_extract_android_filesystem
from ai_models.permission_model.predictor import PermissionRiskPredictor
import tempfile

def permissions_ui():
    st.title("🔐 Android Dangerous Permissions Auditor")

    st.markdown("Use **ADB auto extraction** or upload a file manually (`.json`, `.xml`, `.txt`, `.zip`, `.pcap`, `.log`).")

    # Input base directory (default: data_dump)
    base_dir = st.text_input("📁 Base Directory for Parsed Dump", value="data_dump")

    col1, col2 = st.columns([1, 2])

    # ADB Auto Extraction trigger
    with col1:
        if st.button("📲 Start ADB Extraction"):
            adb_result = auto_extract_android_filesystem(base_dir=base_dir)
            if adb_result:
                st.success(f"✅ Extraction complete. Saved to: `{adb_result['output_dir']}`")
            else:
                st.error("❌ No ADB device connected or extraction failed.")

    # File uploader (supports multiple types)
    with col2:
        uploaded_file = st.file_uploader("📤 Upload Permissions-related File", type=["json", "xml", "txt", "zip", "pcap", "log"], accept_multiple_files=False)

    # Choose from existing dumps
    existing_dumps = [d for d in os.listdir(base_dir) if os.path.isdir(os.path.join(base_dir, d))]
    selected_case = st.selectbox("📂 Or Select From Existing Parsed Cases", sorted(existing_dumps, reverse=True) if existing_dumps else [])

    # Final action
    if st.button("🚀 Run Permissions Audit"):
        json_data = None

        # Option 1: Uploaded file
        if uploaded_file:
            suffix = uploaded_file.name.split(".")[-1].lower()
            with tempfile.TemporaryDirectory() as tmpdir:
                temp_path = os.path.join(tmpdir, uploaded_file.name)
                with open(temp_path, "wb") as f:
                    f.write(uploaded_file.read())
                if suffix == "json":
                    json_data = json.load(open(temp_path))
                elif suffix in ["zip", "pcap", "log", "txt", "xml"]:
                    st.warning(f"⚠️ File type `{suffix}` is supported for upload, but parsing logic is not yet implemented for it.")
        # Option 2: From parsed dump
        elif selected_case:
            selected_dir = os.path.join(base_dir, selected_case)
            candidates = [f for f in os.listdir(selected_dir) if f.endswith(".json")]
            if candidates:
                latest_file = sorted(candidates)[-1]
                json_path = os.path.join(selected_dir, latest_file)
                with open(json_path, "r") as f:
                    json_data = json.load(f)
            else:
                st.error("❌ No JSON file found in selected dump folder.")

        if json_data:
            predictor = PermissionRiskPredictor()
            df = analyze_permissions(json_data)
            st.success("✅ Permissions successfully analyzed.")
            st.dataframe(df)

            report_csv = generate_report(json_data, predictor)
            generate_visualizations(report_csv)
            zipped_report = zip_report_components(report_csv)
            with open(zipped_report, "rb") as f:
                st.download_button("📥 Download Full Report (ZIP)", f, file_name=os.path.basename(zipped_report))
        else:
            st.error("❌ No valid permission data available. Please upload or extract.")
