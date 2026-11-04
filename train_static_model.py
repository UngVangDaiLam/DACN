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
from sklearn.utils.class_weight import compute_sample_weight

try:
    from xgboost import XGBClassifier
    HAS_XGB = True
except Exception:
    HAS_XGB = False

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from scanner.static_features import FEATURE_SCHEMA

# 5 lop cua bai toan. Nhan khac (vi du "Malware" = dropper chung) bi loai.
CLASSES = ["Benign", "Adware", "Banking", "SMS", "Riskware"]
# Cot van duoc extract_features() trich nhung KHONG dua vao model.
EXCLUDE_FEATURES = ["min_sdk", "target_sdk"]
MODEL_FEATURES = [c for c in FEATURE_SCHEMA if c not in EXCLUDE_FEATURES]

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

    print("\nPhan bo nhan trong CSV:")
    print(df["label"].value_counts().to_string())

    dropped = df[~df["label"].isin(CLASSES)]
    if len(dropped):
        print(f"\nLoai {len(dropped)} mau khong thuoc 5 lop {CLASSES}:")
        print(dropped["label"].value_counts().to_string())
    df = df[df["label"].isin(CLASSES)].reset_index(drop=True)
    print(f"Con lai {len(df)} mau cho bai toan 5 lop.")

    # APK khong dem duoc lenh DEX nao (DEX hong/bi lam meo) -> moi cot opcode__* = 0.
    # Luc suy luan, mau nhu vay bi danh dau analysis_incomplete va KHONG du doan,
    # nen cung loai khoi train/danh gia de model khong hoc tu vector thieu.
    opcode_cols = [c for c in MODEL_FEATURES if c.startswith("opcode__")]
    no_dex = df[opcode_cols].fillna(0).sum(axis=1) == 0
    print(f"\nLoai {int(no_dex.sum())} mau co tong opcode__* = 0 (khong dem duoc lenh DEX):")
    if no_dex.any():
        print(df.loc[no_dex, "label"].value_counts().to_string())
    df = df[~no_dex].reset_index(drop=True)
    print(f"Con lai {len(df)} mau de train/danh gia.")

    counts = df["label"].value_counts()

    if counts.shape[0] < 2:
        print("\nLOI: chi co 1 nhan duy nhat trong du lieu ("
              f"'{counts.index[0]}'). Khong the huan luyen classifier phan loai voi 1 lop.")
        print("Hay them mau o cac lop con lai (vi du chay download_malwarebazaar.py de lay mau ma doc)")
        print("roi chay lai build_static_dataset.py truoc khi chay file nay.")
        sys.exit(1)

    return df


def main():
    df = load_data()

    X = df[MODEL_FEATURES].fillna(0).astype(float)
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

    # Khong dung SMOTE (mau tong hop de lot vao danh gia); can bang bang trong so
    # nhu eval_5class_cv.py, chi tinh tren tap train.
    w_train = compute_sample_weight("balanced", y_train)

    if HAS_XGB:
        import xgboost
        print(f"\nHuan luyen XGBoost (xgboost {xgboost.__version__}, python {sys.version.split()[0]}, "
              f"{sys.executable})...")
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

    clf.fit(X_train, y_train, sample_weight=w_train)

    y_pred = clf.predict(X_test)
    acc = accuracy_score(y_test, y_pred)
    print(f"\nDo chinh xac tren tap test: {acc:.4f}")
    all_labels = list(range(len(le.classes_)))
    missing = [le.classes_[i] for i in all_labels if i not in set(y_test)]
    if missing:
        print("\n" + "!" * 60)
        print(f"CANH BAO QUAN TRONG: tap test KHONG co mau nao cua lop {missing}.")
        print("Accuracy/precision/recall o duoi KHONG CO Y NGHIA - chua duoc dua vao bao cao.")
        print("Can them mau cho cac lop nay roi build + train lai.")
        print("!" * 60)
    print("\nBao cao phan loai:")
    print(classification_report(y_test, y_pred, labels=all_labels,
                                target_names=le.classes_, zero_division=0))

    os.makedirs(MODEL_DIR, exist_ok=True)
    joblib.dump(clf, MODEL_PATH)
    joblib.dump(le, ENCODER_PATH)
    # Luu dung danh sach + thu tu cot model dung, de luc suy luan lay lai y het
    with open(SCHEMA_PATH, "w", encoding="utf-8") as f:
        json.dump(MODEL_FEATURES, f, ensure_ascii=False, indent=2)

    print(f"\nDa luu model: {MODEL_PATH}")
    print(f"Da luu label encoder: {ENCODER_PATH}")
    print(f"Da luu feature schema: {SCHEMA_PATH}")

    print("\n" + "=" * 60)
    print("TOM TAT")
    print("=" * 60)
    print("So mau moi lop (sau khi loai nhan ngoai 5 lop):")
    print(f"{'Lop':10s} {'Tong':>5s} {'Train':>6s} {'Test':>5s}")
    for i, c in enumerate(le.classes_):
        print(f"{c:10s} {int((y == i).sum()):5d} {int((y_train == i).sum()):6d} {int((y_test == i).sum()):5d}")
    print(f"\nCot dau vao model: {len(MODEL_FEATURES)} "
          f"(= {len(FEATURE_SCHEMA)} FEATURE_SCHEMA - {len(EXCLUDE_FEATURES)} loai tru {EXCLUDE_FEATURES})")
    print(", ".join(MODEL_FEATURES))
    print("\nMa tran nham lan tren tap test (hang = that, cot = du doan), thu tu lop:", list(le.classes_))
    print(confusion_matrix(y_test, y_pred, labels=all_labels))
    print(f"\nLUU Y: Tang 1 tinh, {len(MODEL_FEATURES)} dac trung doc tu {SCHEMA_PATH}.")
    print("Model nay KHONG tuong thich voi models/*.pkl cu (dynamic/syscalls) - can sua")
    print("scanner/detect_and_classify.py de dung model + schema moi nay khi suy luan (inference).")


if __name__ == "__main__":
    main()
