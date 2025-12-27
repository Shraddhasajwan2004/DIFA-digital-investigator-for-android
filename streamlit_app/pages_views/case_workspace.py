# pages/case_workspace.py

import streamlit as st
from backend.extract.adb_connector import auto_extract_android_filesystem

def show_case_workspace():
    st.title("🧪 Case Workspace")
    st.info("You can start forensic analysis and reporting here.")

    st.markdown("### 📂 Android Device Extraction")
    if st.button("📥 Extract Device File System"):
        result = auto_extract_android_filesystem()
        if result:
            st.success(f"✅ Data pulled from device `{result['device_id']}`")
            st.write("📁 Saved at:", result['output_dir'])
        else:
            st.error("❌ No device found or extraction failed.")

    st.markdown("---")
    if st.button("⬅️ Back to Home"):
        st.session_state.page = "Home"
    if st.button("🔄 Refresh"):
        st.experimental_rerun()