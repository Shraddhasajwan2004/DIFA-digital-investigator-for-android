# streamlit_app/pages_views/home.py

import streamlit as st
import sqlite3
from datetime import datetime
from backend.extract.adb_connector import is_adb_device_connected

DB_PATH = "database/forensics.db"

def authenticate_user(investigator_id, password):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("SELECT * FROM investigators WHERE investigator_id = ? AND password = ?", (investigator_id, password))
    user = cur.fetchone()
    conn.close()
    return user

def register_user(name, org, inv_id, password):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    try:
        cur.execute(
            "INSERT INTO investigators (investigator_name, organization, investigator_id, password) VALUES (?, ?, ?, ?)",
            (name, org, inv_id, password)
        )
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False

def insert_case(case_number, investigator_id):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("INSERT INTO cases (case_number, investigator_id, created_at) VALUES (?, ?, ?)",
                (case_number, investigator_id, datetime.now().isoformat()))
    conn.commit()
    conn.close()

def get_previous_cases(investigator_id):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("SELECT case_number, created_at FROM cases WHERE investigator_id = ?", (investigator_id,))
    rows = cur.fetchall()
    conn.close()
    return rows

def show_home():
    st.title("🔐 Investigator Login & Case Launcher")

    if "authenticated" not in st.session_state:
        st.session_state.authenticated = False

    if not st.session_state.authenticated:
        tab1, tab2 = st.tabs(["Login", "Register"])
        with tab1:
            investigator_id = st.text_input("Investigator ID")
            password = st.text_input("Password", type="password")
            if st.button("Login"):
                if authenticate_user(investigator_id, password):
                    st.success("✅ Login successful.")
                    st.session_state.authenticated = True
                    st.session_state.investigator_id = investigator_id
                    st.session_state.page = "CaseWorkspace"
                    st.rerun()
                else:
                    st.error("❌ Invalid credentials.")
        with tab2:
            name = st.text_input("Investigator Name")
            org = st.text_input("Organization")
            new_id = st.text_input("Create Investigator ID")
            new_pass = st.text_input("Create Password", type="password")
            if st.button("Register"):
                if register_user(name, org, new_id, new_pass):
                    st.success("🎉 Registration successful.")
                else:
                    st.error("🚫 Investigator ID already exists.")
        return

    st.subheader("📁 Start New Case")
    case_number = st.text_input("Enter Case Number")
    if st.button("Register Case"):
        insert_case(case_number, st.session_state.investigator_id)
        st.session_state.case_number = case_number
        st.success(f"🗂️ Case `{case_number}` created.")

    st.subheader("📂 Previous Cases")
    prev = get_previous_cases(st.session_state.investigator_id)
    if prev:
        options = [f"{c} (created at {t})" for c, t in prev]
        selected = st.selectbox("Select a previous case to resume:", options)

        if selected:
            selected_case_number = selected.split(" (", 1)[0]
            if st.button("🧪 Continue Working on This Case"):
                st.session_state.case_number = selected_case_number
                st.session_state.page = "CaseWorkspace"
                st.rerun()
    else:
        st.info("No previous cases found.")

    st.subheader("📱 Device Detection")
    if st.button("Check ADB Connection"):
        connected, dev_id = is_adb_device_connected()
        if connected:
            st.success(f"✅ Device connected: `{dev_id}`")
        else:
            st.error("❌ No device detected.")

    st.markdown("---")
    if st.button("🚀 Start Working on Case"):
        st.session_state.page = "CaseWorkspace"

def render():
    if st.button("📧 Start Email Header Analysis"):
        st.session_state.page = "EmailAnalysis"
        st.rerun()
