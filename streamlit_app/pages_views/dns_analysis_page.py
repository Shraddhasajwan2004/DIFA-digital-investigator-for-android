# streamlit_app/pages_views/dns_analysis_page.py

import streamlit as st
from backend.analysis.dns_log_parser import analyze_dns_logs
from backend.extract.adb_connector import pull_dns_logs_from_device

def dns_analysis_ui():
    st.title("🌐 DNS Logs Analysis")
    st.markdown("Analyze DNS activity for suspicious domains and after-hours access.")

    dns_log_file = None
    use_adb = st.toggle("📱 Pull from ADB-connected device", value=True)

    if use_adb:
        if st.button("🔄 Pull DNS Logs via ADB"):
            dns_log_file = pull_dns_logs_from_device()
            if dns_log_file:
                st.success(f"Pulled DNS logs to: `{dns_log_file}`")
            else:
                st.error("No device detected or failed to pull logs.")
    else:
        uploaded = st.file_uploader("📤 Upload DNS log file", type=["txt", "log"])
        if uploaded:
            temp_path = f"temp_uploads/{uploaded.name}"
            with open(temp_path, "wb") as f:
                f.write(uploaded.read())
            dns_log_file = temp_path

    if dns_log_file and st.button("🚀 Analyze DNS Logs"):
        df, csv_path, hash_path, zip_path = analyze_dns_logs(dns_log_file)

        if not df.empty:
            st.success("✅ DNS analysis complete.")
            st.dataframe(df)

            st.download_button("📥 Download CSV Report", data=open(csv_path, "rb"), file_name="dns_analysis.csv")
            st.download_button("🔐 Download Hash", data=open(hash_path, "rb"), file_name="dns_hash.txt")
            st.download_button("🗜️ Download ZIP Report", data=open(zip_path, "rb"), file_name="dns_report.zip")

            st.markdown("### 📊 Risk Distribution")
            st.bar_chart(df["Model Risk"].value_counts())

            st.markdown("### ⏱️ After-Hours Access")
            after_hours_count = df["Accessed After Hours"].value_counts()
            st.bar_chart(after_hours_count)
        else:
            st.warning("No valid DNS entries found.")
