# streamlit_app/main.py

import streamlit as st
import os, sys


# Add project root to sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

# Initialize DB
from database.init_db import init_db
init_db()

# App components
from pages_views import home, case_workspace
from pages_views.email_analysis_page import email_analysis_ui
from pages_views.ssl_analysis_page import ssl_analysis_ui
from streamlit_app.pages_views.bandwidth_analysis_page import bandwidth_analysis_ui
from streamlit_app.pages_views.dns_analysis_page import dns_analysis_ui
from streamlit_app.pages_views.hidden_apps_page import hidden_apps_ui
from streamlit_app.pages_views.permissions_analysis_page import permissions_ui
from streamlit_app.sidebar import show_sidebar
from streamlit_app.routing import route_app

# Analysis module labels
EMAIL_MODULE = "Email Analysis"
SSL_MODULE = "SSL Certificate Analysis"
BANDWIDTH_MODULE = "Bandwidth Analyzer"
DNS_MODULE = "DNS Logs Analysis"
HIDDEN_APPS_MODULE = "Hidden Apps"
PERMISSIONS_MODULE = "Permissions Audit"
TIMELINE_MODULE = "Forensic Timeline"


def main():
    st.set_page_config("Android Forensics Dashboard", layout="wide")

    # ✅ Initialize session state
    st.session_state.setdefault("authenticated", False)
    st.session_state.setdefault("case_started", False)
    st.session_state.setdefault("page", "Home")
    st.session_state.setdefault("analysis_module", "")

    # 🚀 Top Bar – Profile + Logout
    if st.session_state.get("authenticated"):
        col1, _, col3 = st.columns([4, 2, 1])
        with col1:
            st.markdown(f"👤 **{st.session_state.get('investigator_id')}** | 🗂️ Case: `{st.session_state.get('case_number', 'None')}`")
        with col3:
            if st.button("🔓 Logout"):
                for key in ["authenticated", "case_started", "page", "analysis_module", "case_number", "investigator_id"]:
                    st.session_state.pop(key, None)
                st.rerun()

    # 🔐 Login/register first
    if not st.session_state.authenticated:
        home.show_home()
        st.session_state.page = "Home"
        return

    # 🧭 Sidebar and routing
    show_sidebar()
    route_app()

    # 🚀 Page Router
    if st.session_state.page == "CaseWorkspace":
        module = st.session_state.get("analysis_module", "")
        case_id = st.session_state.get("case_number", "No Case")
        inv_id = st.session_state.get("investigator_id", "Unknown")

        if not module:
            st.markdown(f"# 🧪 Case Workspace — `{case_id}`")
            st.markdown(f"👤 Investigator: **{inv_id}**")
            case_workspace.show_case_workspace()

        elif module == EMAIL_MODULE:
            st.markdown("## 📧 Email Header Analysis")
            email_analysis_ui()

        elif module == SSL_MODULE:
            st.markdown("## 🔐 SSL Certificate Analysis")
            ssl_analysis_ui()

        elif module == BANDWIDTH_MODULE:
            st.markdown("## 📊 Bandwidth Analyzer")
            bandwidth_analysis_ui()

        elif module == DNS_MODULE:
            st.markdown("## 🌐 DNS Logs Analysis")
            dns_analysis_ui()

        elif module == HIDDEN_APPS_MODULE:
            st.markdown("## 🕵️ Hidden Apps Scanner")
            hidden_apps_ui()

        elif module == PERMISSIONS_MODULE:
            st.markdown("## 🔒 Permissions Audit")
            permissions_ui()
        elif module == TIMELINE_MODULE:
            st.markdown("## 📆 Forensic Activity Timeline")
            from streamlit_app.timeline_page import timeline_ui
            timeline_ui()
    else:
        home.render()


if __name__ == "__main__":
    main()
