import pickle
import os
import pandas as pd

MODEL_PATH = "ai_models/hidden_apps_model/model.pkl"

def load_model():
    if not os.path.exists(MODEL_PATH):
        raise FileNotFoundError("Model not found. Train it first.")
    with open(MODEL_PATH, "rb") as f:
        return pickle.load(f)

def predict_risk(df: pd.DataFrame):
    model = load_model()
    preds = model.predict(df)
    return ["High" if p == 1 else "Low" for p in preds]
