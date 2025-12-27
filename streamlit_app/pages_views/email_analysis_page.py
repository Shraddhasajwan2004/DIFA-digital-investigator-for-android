import streamlit as st
import pandas as pd
from ai_models.email_model.predictor import score_email
from backend.analysis.email_header_analyzer import parse_uploaded_eml  # assumes you extract features here

# Folder where parsed .eml files are stored
EMAIL_FOLDER = "D:/android_image_dump/email_files/"

def email_analysis_ui():
    st.title("📧 Email Header Forensics & Risk Scoring")

    uploaded_file = st.file_uploader("Upload an .eml file", type="eml")
    
    if uploaded_file:
        st.success("Email uploaded and parsing...")

        # Parse header features
        features = parse_uploaded_eml(uploaded_file)  # Should return a dict compatible with predictor

        st.subheader("🧬 Parsed Email Header Features")
        st.json(features)

        # Run scoring
        result = score_email(features)

        st.subheader("🔐 Risk Evaluation")
        col1, col2 = st.columns([1, 3])
        col1.metric("Risk Level", result['risk_level'])
        col1.metric("Score", round(result['score'], 2))
        
        col2.markdown("### ⚠️ Risk Indicators:")
        for reason in result['reasons']:
            col2.markdown(f"- {reason}")

        # Optional download report
        csv_data = pd.DataFrame([{
            **features,
            "score": result["score"],
            "risk_level": result["risk_level"]
        }])
        st.download_button("⬇ Download Report CSV", csv_data.to_csv(index=False), "email_risk_report.csv")

