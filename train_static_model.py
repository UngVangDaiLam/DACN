r"""
train_static_model.py
Huan luyen lai model Tang 1 (dac trung TINH) tu dataset/processed/static_features.csv
(sinh boi build_static_dataset.py, dung chung extract_features() voi luc app chay that).

Yeu cau: file CSV phai co it nhat 2 nhan khac nhau (vi du Benign + it nhat 1 loai
ma doc) thi moi huan luyen duoc mot classifier co y nghia. Neu chi co 1 nhan,
script se bao loi va dung lai - hay chay download_malwarebazaar.py (hoac tai
thu cong vai mau ma doc vao dataset/raw_apk/malicious/<nhom>/) roi chay lai
build_static_dataset.py truoc khi chay file nay.

CHAY:
  .\venv\Scripts\python.exe train_static_model.py
"""

import os
import sys
import json
import joblib
import numpy as np
import pandas as pd

from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score

try:
    from xgboost import XGBClassifier
    HAS_XGB = True
except Exception:
    HAS_XGB = False

try:
    from imblearn.over_sampling import SMOTE
    HAS_SMOTE = True
except Exception:
    HAS_SMOTE = False

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from scanner.static_features import FEATURE_SCHEMA

CSV_PATH = "dataset/processed/static_features.csv"
MODEL_DIR = "models"
MODEL_PATH = os.path.join(MODEL_DIR, "static_model.pkl")
ENCODER_PATH = os.path.join(MODEL_DIR, "static_label_encoder.pkl")
SCHEMA_PATH = os.path.join(MODEL_DIR, "static_feature_schema.json")


def load_data():
    if not os.path.exists(CSV_PATH):
        print(f"Khong tim thay {CSV_PATH}. Chay build_static_dataset.py truoc.")
        sys.exit(1)

    df = pd.read_csv(CSV_PATH)
    print(f"Doc {len(df)} dong tu {CSV_PATH}")

    missing = [c for c in FEATURE_SCHEMA if c not in df.columns]
    if missing:
        print(f"CSV thieu {len(missing)} cot dac trung (vi du: {missing[:5]}...).")
        print("Co the CSV nay sinh tu phien ban static_features.py cu hon. Chay lai build_static_dataset.py.")
        sys.exit(1)

    counts = df["label"].value_counts()
    print("\nPhan bo nhan trong du lieu:")
    print(counts.to_string())

    if counts.shape[0] < 2:
        print("\nLOI: chi co 1 nhan duy nhat trong du lieu ("
              f"'{counts.index[0]}'). Khong the huan luyen classifier phan loai voi 1 lop.")
        print("Hay them mau o cac lop con lai (vi du chay download_malwarebazaar.py de lay mau ma doc)")
        print("roi chay lai build_static_dataset.py truoc khi chay file nay.")
        sys.exit(1)

    return df


def main():
    df = load_data()

    X = df[FEATURE_SCHEMA].fillna(0).astype(float)
    y_raw = df["label"].astype(str)

    le = LabelEncoder()
    y = le.fit_transform(y_raw)
    print(f"\nCac lop: {list(le.classes_)}")

    # Neu lop nao qua it mau (< 2), train_test_split stratify se loi -> bo stratify.
    min_class_count = pd.Series(y).value_counts().min()
    stratify_arg = y if min_class_count >= 2 else None
    if stratify_arg is None:
        print("Canh bao: co lop chi co 1 mau, bo qua stratify khi chia train/test.")

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=stratify_arg
    )

    # SMOTE chi ap dung duoc neu lop nho nhat trong tap train co >= 2 mau
    # va >= k_neighbors+1 mau (mac dinh k_neighbors=5, ta ha xuong neu can).
    if HAS_SMOTE:
        train_counts = pd.Series(y_train).value_counts()
        min_train_count = train_counts.min()
        if min_train_count >= 2:
            k = max(1, min(5, min_train_count - 1))
            try:
                sm = SMOTE(random_state=42, k_neighbors=k)
                X_train, y_train = sm.fit_resample(X_train, y_train)
                print(f"\nDa ap dung SMOTE (k_neighbors={k}). "
                      f"So mau train sau SMOTE: {len(y_train)}")
            except Exception as e:
                print(f"\nSMOTE loi ({e}), bo qua, dung du lieu goc.")
        else:
            print("\nBo qua SMOTE: co lop trong tap train chi co 1 mau (can >= 2).")
    else:
        print("\nimbalanced-learn chua duoc cai, bo qua SMOTE.")

    if HAS_XGB:
        print("\nHuan luyen XGBoost...")
        clf = XGBClassifier(
            n_estimators=300, max_depth=6, learning_rate=0.1,
            subsample=0.9, colsample_bytree=0.9, random_state=42,
            eval_metric="mlogloss",
        )
    else:
        print("\nxgboost chua duoc cai, dung RandomForest thay the...")
        clf = RandomForestClassifier(
            n_estimators=400, max_depth=None, random_state=42, n_jobs=-1
        )

    clf.fit(X_train, y_train)

    y_pred = clf.predict(X_test)
    acc = accuracy_score(y_test, y_pred)
    print(f"\nDo chinh xac tren tap test: {acc:.4f}")
    print("\nBao cao phan loai:")
    print(classification_report(y_test, y_pred, target_names=le.classes_, zero_division=0))
    print("Ma tran nham lan:")
    print(confusion_matrix(y_test, y_pred))

    os.makedirs(MODEL_DIR, exist_ok=True)
    joblib.dump(clf, MODEL_PATH)
    joblib.dump(le, ENCODER_PATH)
    with open(SCHEMA_PATH, "w", encoding="utf-8") as f:
        json.dump(FEATURE_SCHEMA, f, ensure_ascii=False, indent=2)

    print(f"\nDa luu model: {MODEL_PATH}")
    print(f"Da luu label encoder: {ENCODER_PATH}")
    print(f"Da luu feature schema: {SCHEMA_PATH}")
    print("\nLUU Y: day la model moi (Tang 1 tinh, dung schema 71 dac trung co dinh).")
    print("Model nay KHONG tuong thich voi models/*.pkl cu (dynamic/syscalls) - can sua")
    print("scanner/detect_and_classify.py de dung model + schema moi nay khi suy luan (inference).")


if __name__ == "__main__":
    main()
