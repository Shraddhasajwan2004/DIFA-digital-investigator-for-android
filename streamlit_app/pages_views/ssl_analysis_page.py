# streamlit_app/pages_views/ssl_analysis_page.py

import streamlit as st
import os
import zipfile
import shutil
import tempfile
import pandas as pd
from backend.analysis.ssl_certificate_inspector import pull_pcap_from_android, parse_ssl_certificates

def ssl_analysis_ui():
    st.title("🔐 SSL Certificate Analysis")

    uploaded_pcap = st.file_uploader("Upload PCAP or ZIP File", type=["pcap", "zip"])
    col1, col2 = st.columns(2)
    analyze = False

    with col1:
        if st.button("📥 Pull PCAP from Android"):
            if pull_pcap_from_android():
                st.success("✅ Pulled PCAP from device.")
                analyze = True
            else:
                st.error("❌ Pull failed.")

    with col2:
        if st.button("🚀 Analyze SSL Certificates"):
            analyze = True

    if uploaded_pcap:
        os.makedirs("data", exist_ok=True)
        path = os.path.join("data", "traffic.pcap")
        if uploaded_pcap.name.endswith(".zip"):
            with tempfile.TemporaryDirectory() as tmpdir:
                with zipfile.ZipFile(uploaded_pcap, 'r') as zip_ref:
                    zip_ref.extractall(tmpdir)
                for root, _, files in os.walk(tmpdir):
                    for f in files:
                        if f.endswith(".pcap"):
                            shutil.copy(os.path.join(root, f), path)
                            st.success(f"Loaded: {f}")
                            analyze = True
        else:
            with open(path, "wb") as f:
                f.write(uploaded_pcap.read())
            st.success("✅ PCAP uploaded.")

    if analyze and os.path.exists("data/traffic.pcap"):
        with st.spinner("🔎 Parsing SSL certificates..."):
            csv, zipf, certs = parse_ssl_certificates()
            if certs:
                df = pd.DataFrame(certs)
                st.dataframe(df)
                if os.path.exists(csv):
                    st.download_button("⬇ Download CSV", open(csv, "rb"), "ssl_certificates.csv")
                if os.path.exists(zipf):
                    st.download_button("⬇ Download ZIP", open(zipf, "rb"), "ssl_certificates.zip")
            else:
                st.warning("⚠️ No certificates found.")
