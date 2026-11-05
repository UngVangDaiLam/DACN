import sys, numpy as np, pandas as pd
from sklearn.model_selection import RepeatedStratifiedKFold
from sklearn.metrics import confusion_matrix, f1_score
from sklearn.preprocessing import LabelEncoder
from sklearn.utils.class_weight import compute_sample_weight
from xgboost import XGBClassifier
from scanner.static_features import FEATURE_SCHEMA

CLASSES = ["Benign", "Adware", "Banking", "SMS", "Riskware"]
df = pd.read_csv("dataset/processed/static_features.csv")
df = df[df[[c for c in FEATURE_SCHEMA if c.startswith("opcode__")]].sum(axis=1) > 0]
df = df[df.label.isin(CLASSES)]
cnt = df.label.value_counts()
print(cnt.to_string())

ok = [c for c in CLASSES if cnt.get(c, 0) >= 5]
miss = [c for c in CLASSES if c not in ok]
if miss:
    print("Thieu mau (<5), bo qua:", miss)
if len(ok) < 3:
    sys.exit("Chua du lop de phan loai nhieu lop.")

df = df[df.label.isin(ok)]
le = LabelEncoder()
y = le.fit_transform(df.label)
X = df[[c for c in FEATURE_SCHEMA if c not in ("min_sdk", "target_sdk")]].fillna(0).astype(float).values
k = int(min(5, df.label.value_counts().min()))
cv = RepeatedStratifiedKFold(n_splits=k, n_repeats=3, random_state=42)

cm = np.zeros((len(ok), len(ok)), dtype=int)
f1s = []
for tr, te in cv.split(X, y):
    w = compute_sample_weight("balanced", y[tr])
    m = XGBClassifier(n_estimators=200, max_depth=4, random_state=42,
                      eval_metric="mlogloss")
    m.fit(X[tr], y[tr], sample_weight=w)
    p = m.predict(X[te])
    cm += confusion_matrix(y[te], p, labels=range(len(ok)))
    f1s.append(f1_score(y[te], p, average="macro"))

print("Cac lop:", list(le.classes_), "| so fold:", k)
print("Ma tran nham lan cong don (hang=that, cot=du doan):")
print(cm)
for i, c in enumerate(le.classes_):
    print(f"  {c:10s} recall = {cm[i, i] / cm[i].sum():.2f}  ({cm[i, i]}/{cm[i].sum()})")
print(f"Macro F1 trung binh = {np.mean(f1s):.2f} Â± {np.std(f1s):.2f}")