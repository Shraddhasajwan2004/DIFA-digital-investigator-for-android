# streamlit_app/sidebar.py

import streamlit as st

def show_sidebar():
    with st.sidebar:
        st.title("🧭 Navigation")

        # Show only after login
        if st.session_state.get("authenticated", False):
            st.markdown("## 🧑‍💼 Investigator Info")
            st.write("👤 ID:", st.session_state.get("investigator_id", ""))
            st.write("📁 Case:", st.session_state.get("case_name", "Not started"))

            st.markdown("---")
            # Primary navigation
            page = st.radio("Go to", ["Home", "CaseWorkspace"], key="main_navigation")
            st.session_state.page = page

            # Show extra options only if case has started
            if "case_number" in st.session_state:
                st.markdown("## 🧪 Case Analysis")
                analysis_choice = st.radio(
                        "Choose Module", [
            "Email Analysis", "SSL Certificate Analysis", 
            "Bandwidth Analyzer", "DNS Logs Analysis", 
            "Hidden Apps", "Permissions Audit","Timeline Analysis",
                 ],
                key="analysis_module_radio"
                )
                st.session_state.analysis_module = analysis_choice

            if st.button("🚀 Go to Case Workspace"):
                st.session_state.page = "CaseWorkspace"

            if st.button("🔓 Logout"):
                st.session_state.authenticated = False
                st.session_state.case_started = False
                st.session_state.page = "Home"
                st.success("You’ve been logged out.")


