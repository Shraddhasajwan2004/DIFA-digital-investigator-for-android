# streamlit_app/pages/5_Bandwidth_Analyzer.py

import streamlit as st
import pandas as pd
import plotly.express as px
from backend.analysis.bandwidth_analyser import (
    pull_pcap_from_device,
    extract_upload_data,
    detect_anomalies,
    export_report,
    compute_sha256
)

def bandwidth_analysis_ui():
    st.set_page_config(page_title="📶 Bandwidth Anomaly Detector", layout="wide")
    st.title("📶 Bandwidth Anomaly Detector")

    st.markdown("""
        Analyze network traffic to detect **unusual upload activity**, **after-hours usage**, and **AI-flagged anomalies**.
    """)
    st.sidebar.header("📂 Data Source")

    use_adb = st.sidebar.radio("Select Input Method", ["ADB Pull", "Manual Upload"])
    use_ml = st.sidebar.checkbox("Use AI Model for Risk Scoring", value=True)

    if use_adb == "ADB Pull":
        if st.sidebar.button("📥 Pull PCAP from Device"):
            try:
                pcap_path = pull_pcap_from_device()
                st.success("✅ PCAP pulled from device.")
            except Exception as e:
                st.error(f"❌ ADB Error: {e}")
                return
        else:
            st.info("⬅️ Click 'Pull PCAP from Device' to begin.")
            return
    else:
        uploaded_file = st.sidebar.file_uploader("Upload PCAP File", type=["pcap"])
        if uploaded_file:
            pcap_path = f"forensics_output/bandwidth/uploaded_{uploaded_file.name}"
            with open(pcap_path, "wb") as f:
                f.write(uploaded_file.read())
            st.success("✅ Uploaded PCAP file.")
        else:
            st.info("⬅️ Upload a `.pcap` file to begin.")
            return

    with st.spinner("⏳ Processing..."):
        df = extract_upload_data(pcap_path)
        if df.empty:
            st.warning("No valid upload traffic found.")
            return
        df = detect_anomalies(df, use_ml=use_ml)

    st.subheader("📈 Upload Bandwidth Over Time")
    fig = px.line(df, x="Timestamp", y="Upload_MB", color="Risk_Level", markers=True)
    st.plotly_chart(fig, use_container_width=True)

    st.subheader("📌 Anomaly Table")
    with st.expander("🔍 View Detailed Anomalies"):
        st.dataframe(df, use_container_width=True)

    st.markdown("### 📁 Export Report")
    csv_path, zip_path = export_report(df)
    sha256 = compute_sha256(csv_path)
    st.success(f"SHA256: `{sha256}`")

    st.download_button("⬇️ Download CSV", open(csv_path, "rb"), file_name="bandwidth_anomalies.csv")
    st.download_button("📦 Download ZIP Report", open(zip_path, "rb"), file_name="bandwidth_report.zip")

if __name__ == "__main__":
    bandwidth_analysis_ui()

