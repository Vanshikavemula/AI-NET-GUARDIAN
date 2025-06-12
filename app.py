import streamlit as st
import pandas as pd
import joblib
from utils.feature_extraction import extract_features

st.title("🛡️ SQLi & XSS Attack Detection Dashboard")

model = joblib.load("model/rf_model.pkl")

option = st.radio("Choose Mode:", ("Upload URLs", "Enter Single URL"))

if option == "Upload URLs":
    uploaded_file = st.file_uploader("Upload CSV with column 'url'", type=["csv"])
    if uploaded_file:
        df = pd.read_csv(uploaded_file)
        df["features"] = df["url"].apply(extract_features)
        df["prediction"] = df["features"].apply(lambda x: model.predict([x])[0])
        df["result"] = df["prediction"].map({1: "🔴 Malicious", 0: "🟢 Benign"})
        st.dataframe(df[["url", "result"]])
else:
    url = st.text_input("Enter a URL:")
    if url:
        features = extract_features(url)
        pred = model.predict([features])[0]
        result = "🔴 Malicious (SQLi/XSS)" if pred else "🟢 Benign"
        st.markdown(f"### Prediction: {result}")
