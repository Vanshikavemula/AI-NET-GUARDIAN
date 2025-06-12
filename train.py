# train_rf_model.py
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
import joblib
from utils.feature_extraction import extract_features

df = pd.read_csv("sample_http.csv")
X = [extract_features(url) for url in df["url"]]
y = df["label"].values

X_train, X_test, y_train, y_test = train_test_split(X, y)
model = RandomForestClassifier().fit(X_train, y_train)

joblib.dump(model, "model/rf_model.pkl")
