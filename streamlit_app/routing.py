# streamlit_app/routing.py

from altair import selection
from numpy import select
import streamlit as st
from streamlit_app.pages_views.case_workspace import show_case_workspace
from streamlit_app.pages_views.home import show_home
from pages_views.dns_analysis_page import dns_analysis_ui
from streamlit_app.timeline_page import timeline_ui

def route_app():
    page = st.session_state.get("page", "Home")
    if not st.session_state.get("authenticated", False):
        show_home()
    elif select == "Bandwidth Analyzer":
            st.session_state.page = "BandwidthAnalyzer"
            st.session_state.analysis_module = "Bandwidth Analyzer"
    elif selection == "Forensic Timeline":
        timeline_ui()
        return

    if page == "Case Workspace":
        show_case_workspace()
    else:
        show_home()
