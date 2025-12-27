# pages_views/timeline_page.py

import streamlit as st
from backend.timeline_builder import build_timeline
import altair as alt

def timeline_ui():
    st.title("📆 Forensic Activity Timeline")

    timeline_df = build_timeline()
    if timeline_df.empty:
        st.warning("No activity found yet. Run forensic modules first.")
        return

    # Filter
    with st.sidebar:
        risk_filter = st.multiselect("Filter by Risk", ["High", "Intermediate", "Low"], default=["High", "Intermediate", "Low"])
        module_filter = st.multiselect("Filter by Module", sorted(timeline_df["Source"].unique()), default=timeline_df["Source"].unique())

    filtered = timeline_df[
        (timeline_df["Risk Level"].isin(risk_filter)) &
        (timeline_df["Source"].isin(module_filter))
    ]

    st.subheader("📋 Event Timeline Table")
    st.dataframe(filtered, use_container_width=True)

    st.subheader("📊 Timeline Risk Chart")
    chart = alt.Chart(filtered).mark_circle(size=90).encode(
        x='Timestamp:T',
        y=alt.Y('Source:N', title="Module"),
        color=alt.Color('Risk Level:N', scale=alt.Scale(scheme='redyellowgreen')),
        tooltip=["Timestamp", "Activity", "Risk Level", "Source"]
    ).properties(height=400)
    st.altair_chart(chart, use_container_width=True)



