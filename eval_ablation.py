import numpy as np, pandas as pd
from sklearn.model_selection import RepeatedStratifiedKFold
from sklearn.metrics import confusion_matrix, f1_score
from sklearn.preprocessing import LabelEncoder
from sklearn.utils.class_weight import compute_sample_weight
from xgboost import XGBClassifier
from scanner.static_features import FEATURE_SCHEMA

CLASSES = ["Benign", "Adware", "Banking", "SMS", "Riskware"]
df = pd.read_csv("dataset/processed/static_features.csv")
df = df[df.label.isin(CLASSES)]
le = LabelEncoder()
y = le.fit_transform(df.label)
K = len(le.classes_)

def make():
    return XGBClassifier(n_estimators=200, max_depth=4, random_state=42, eval_metric="mlogloss")

def run(cols, name):
    X = df[cols].fillna(0).astype(float).values
    cv = RepeatedStratifiedKFold(n_splits=5, n_repeats=3, random_state=42)
    cm = np.zeros((K, K), dtype=int)
    f1s = []
    for tr, te in cv.split(X, y):
        m = make()
        m.fit(X[tr], y[tr], sample_weight=compute_sample_weight("balanced", y[tr]))
        p = m.predict(X[te])
        cm += confusion_matrix(y[te], p, labels=range(K))
        f1s.append(f1_score(y[te], p, average="macro"))
    rec = "  ".join(f"{c}={cm[i, i] / cm[i].sum():.2f}" for i, c in enumerate(le.classes_))
    print(f"{name:34s} F1={np.mean(f1s):.2f}  {rec}")

ERA = ["min_sdk", "target_sdk", "file_size_kb", "dex_entropy",
       "has_native_lib", "is_allow_backup", "is_debuggable"]
run(FEATURE_SCHEMA, "Day du")
run([c for c in FEATURE_SCHEMA if c not in ERA], "Bo dac trung doi may/build")
run([c for c in FEATURE_SCHEMA if not c.startswith("opcode__")], "Bo opcode (quyen + manifest)")
run([c for c in FEATURE_SCHEMA if c.startswith("opcode__")], "Chi opcode")

m = make().fit(df[FEATURE_SCHEMA].fillna(0).astype(float).values, y,
               sample_weight=compute_sample_weight("balanced", y))
top = sorted(zip(FEATURE_SCHEMA, m.feature_importances_), key=lambda t: -t[1])[:10]
print("Top 10 dac trung:", [(n, round(float(v), 3)) for n, v in top])