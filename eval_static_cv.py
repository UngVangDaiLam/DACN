import numpy as np, pandas as pd
from sklearn.model_selection import RepeatedStratifiedKFold
from sklearn.metrics import precision_score, recall_score, f1_score
from xgboost import XGBClassifier
from scanner.static_features import FEATURE_SCHEMA

df = pd.read_csv("dataset/processed/static_features.csv")
y = (df["label"] != "Benign").astype(int).values
print("Benign:", (y == 0).sum(), "| Malware:", (y == 1).sum())

def run(cols, name):
    X = df[cols].fillna(0).astype(float).values
    cv = RepeatedStratifiedKFold(n_splits=5, n_repeats=5, random_state=42)
    P, R, F = [], [], []
    for tr, te in cv.split(X, y):
        spw = (y[tr] == 0).sum() / max((y[tr] == 1).sum(), 1)
        m = XGBClassifier(n_estimators=200, max_depth=4, eval_metric="logloss",
                          scale_pos_weight=spw, random_state=42)
        m.fit(X[tr], y[tr])
        p = m.predict(X[te])
        P.append(precision_score(y[te], p, zero_division=0))
        R.append(recall_score(y[te], p, zero_division=0))
        F.append(f1_score(y[te], p, zero_division=0))
    print(f"{name:32s} precision={np.mean(P):.2f}±{np.std(P):.2f}  "
          f"recall={np.mean(R):.2f}±{np.std(R):.2f}  f1={np.mean(F):.2f}±{np.std(F):.2f}")

run(FEATURE_SCHEMA, "Day du 73 dac trung")
NO_TAMPER = [c for c in FEATURE_SCHEMA if c not in ("manifest_tampered", "zip_tampered")]
run(NO_TAMPER, "Bo 2 co tamper")