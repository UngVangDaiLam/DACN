# scanner/oof_scores.py
"""
Buoc 5.2 - Diem OUT-OF-FOLD (OOF) cua Tang 1, dung de huan luyen meta (Tang 5).

Moi mau chi duoc cham diem boi mo hinh KHONG thay mau do (va khong thay cac mau
cung nhom package_name) luc huan luyen. SMOTE chi chay TRONG tap train cua tung fold.

Chay:  python scanner/oof_scores.py [--folds 5] [--permute]
  --permute : xao tron nhan truoc khi chay. Neu quy trinh khong ro ri thi do chinh xac
              phai tut ve muc ngau nhien (= tong binh phuong ti le cac lop, xem dong
              'Muc ngau nhien' in ra). Neu van cao hon ro ret -> CO RO RI.
"""
import argparse
import json
import os
import sys

import numpy as np
import pandas as pd
from imblearn.over_sampling import SMOTE
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
from sklearn.model_selection import StratifiedGroupKFold
from xgboost import XGBClassifier

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CLASSES = ["Adware", "Banking", "Benign", "Riskware", "SMS"]  # = static_label_encoder.classes_ (abc)


def make_model():
    # Tham so mac dinh; doi cho KHOP train_static_model.py neu khac.
    return XGBClassifier(n_estimators=200, max_depth=4, learning_rate=0.1,
                         subsample=0.8, colsample_bytree=0.8,
                         objective="multi:softprob", eval_metric="mlogloss",
                         tree_method="hist", random_state=42, n_jobs=1)


def fit_predict(Xtr, ytr, Xte, K):
    """SMOTE tren tap train roi huan luyen, tra xac suat cho Xte."""
    minc = int(np.bincount(ytr, minlength=K).min())
    if minc < 2:
        raise RuntimeError("Tap train co lop chi %d mau - khong SMOTE duoc" % minc)
    Xr, yr = SMOTE(k_neighbors=min(5, minc - 1), random_state=42).fit_resample(Xtr, ytr)
    return make_model().fit(Xr, yr).predict_proba(Xte)


def run_oof(X, y, groups, K, n_splits, seed):
    cv = StratifiedGroupKFold(n_splits=n_splits, shuffle=True, random_state=seed)
    oof = np.full((len(y), K), np.nan)
    fold = np.full(len(y), -1)
    for f, (tr, te) in enumerate(cv.split(X, y, groups)):
        if len(np.unique(y[tr])) < K:
            raise RuntimeError("fold %d: tap train thieu lop - giam --folds" % f)
        if set(groups.iloc[tr]) & set(groups.iloc[te]):
            raise RuntimeError("fold %d: nhom bi chia doi giua train/test" % f)
        oof[te] = fit_predict(X.iloc[tr], y[tr], X.iloc[te], K)
        fold[te] = f
    if np.isnan(oof).any() or (fold < 0).any():
        raise RuntimeError("Con mau chua duoc cham OOF")
    return oof, fold


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--csv", default=os.path.join(ROOT, "dataset", "processed", "static_features.csv"))
    ap.add_argument("--schema", default=os.path.join(ROOT, "models", "static_feature_schema.json"))
    ap.add_argument("--out", default=os.path.join(ROOT, "dataset", "processed", "oof_layer1.csv"))
    ap.add_argument("--folds", type=int, default=5)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--permute", action="store_true")
    ap.add_argument("--drop", default="", help="bo cac dac trung nay (cach nhau dau phay)")
    ap.add_argument("--only", default="", help="CHI dung cac dac trung nay (cach nhau dau phay)")
    ap.add_argument("--add", default="", help="THEM cot cua CSV ngoai schema (chi de chan doan)")
    a = ap.parse_args()
    drop = [x.strip() for x in a.drop.split(",") if x.strip()]
    only = [x.strip() for x in a.only.split(",") if x.strip()]
    add = [x.strip() for x in a.add.split(",") if x.strip()]

    df = pd.read_csv(a.csv, low_memory=False)
    with open(a.schema, encoding="utf-8") as f:
        feats = list(json.load(f))
    miss = [c for c in feats + ["label", "sha256", "package_name"] if c not in df.columns]
    if miss:
        sys.exit("CSV thieu cot: %s" % miss[:8])

    # 1) chi giu 5 lop cua mo hinh Tang 1
    keep = df["label"].isin(CLASSES)
    if (~keep).any():
        print("Bo %d mau co nhan ngoai 5 lop: %s" %
              ((~keep).sum(), df.loc[~keep, "label"].value_counts().to_dict()))
    df = df[keep].reset_index(drop=True)
    # 2) giong train_static_model.py: tong opcode__* = 0 -> khong co DEX -> bo
    opc = [c for c in feats if c.startswith("opcode__")]
    nodex = df[opc].sum(axis=1) == 0
    if nodex.any():
        print("Bo %d mau khong co opcode (khong co DEX)" % nodex.sum())
    df = df[~nodex].reset_index(drop=True)

    # 3) tuy chon CHAN DOAN: them / bo / chi giu mot so dac trung (kiem tra tin hieu 'thoi dai').
    #    Cot NGOAI schema cua model (vd min_sdk) chi dung de chan doan, khong anh huong model that.
    extra = [c for c in dict.fromkeys(add + only) if c not in feats]
    nocol = [c for c in extra if c not in df.columns]
    if nocol:
        sys.exit("CSV khong co cot: %s" % nocol)
    pool = feats + extra
    if only:
        pool = [c for c in pool if c in only]
    bad = [c for c in drop if c not in pool]
    if bad:
        sys.exit("Khong bo duoc (khong nam trong tap dac trung dang dung): %s" % bad)
    feats = [c for c in pool if c not in drop]
    if not feats:
        sys.exit("Khong con dac trung nao.")
    if only or drop or add:
        print("THU NGHIEM DAC TRUNG: dung %d dac trung%s" % (len(feats), " " + str(feats) if len(feats) <= 8 else ""))
        if extra:
            print("CANH BAO: dung cot NGOAI schema cua model (chi de chan doan): %s" % extra)

    try:
        X = df[feats].astype(float)
    except (ValueError, TypeError):
        sys.exit("Co cot khong phai so trong: %s" % feats)
    y = df["label"].map({c: i for i, c in enumerate(CLASSES)}).to_numpy()
    K = len(CLASSES)
    pkg = df["package_name"]
    groups = pkg.where(pkg.notna() & (pkg.astype(str).str.strip() != ""), df["sha256"]).astype(str)

    counts = np.bincount(y, minlength=K)
    print("So mau moi lop:", dict(zip(CLASSES, map(int, counts))), "| tong", len(y))
    print("So nhom (package_name): %d / %d mau" % (groups.nunique(), len(y)))
    print("Baseline lop da so (luon doan %s): %.3f" % (CLASSES[int(counts.argmax())], counts.max() / len(y)))
    folds = min(a.folds, int(counts.min()))
    if folds < a.folds:
        print("CANH BAO: lop nho nhat chi %d mau -> dung %d fold" % (counts.min(), folds))
    if folds < 2:
        sys.exit("Qua it mau de chia fold.")

    if a.permute:
        y = np.random.RandomState(a.seed).permutation(y)
        print(">>> CHE DO XAO TRON NHAN: ket qua phai ~ ngau nhien <<<")
        print("Muc ngau nhien ky vong (tong p_i^2): %.3f" % float(((counts / len(y)) ** 2).sum()))

    oof, fold = run_oof(X, y, groups, K, folds, a.seed)
    pred = oof.argmax(axis=1)
    acc = accuracy_score(y, pred)
    print("\nOOF accuracy (%d fold): %.3f" % (folds, acc))
    print(classification_report(y, pred, labels=list(range(K)), target_names=CLASSES, zero_division=0))
    print("Confusion matrix (hang=that, cot=doan; thu tu:", CLASSES, ")")
    print(confusion_matrix(y, pred, labels=list(range(K))))

    if not a.permute:
        # che do thu nghiem dac trung KHONG ghi file (khong de len diem OOF dung cho meta)
        write_out = not (drop or only or add)
        ins = fit_predict(X, y, X, K).argmax(axis=1)
        acc_in = accuracy_score(y, ins)
        print("\nIn-sample accuracy (mo hinh da THAY nhan): %.3f" % acc_in)
        print("Khoang cach in-sample - OOF = %.3f  <- day la muc 'ao tuong' neu dung diem in-sample" % (acc_in - acc))
        if not write_out:
            print("(Thu nghiem dac trung: khong ghi file OOF)")
            return
        os.makedirs(os.path.dirname(a.out), exist_ok=True)
        out = pd.DataFrame({"sha256": df["sha256"], "package_name": df["package_name"],
                            "label": df["label"], "fold": fold})
        for i, c in enumerate(CLASSES):
            out["p_" + c] = oof[:, i]
        out.to_csv(a.out, index=False)
        print("Da ghi:", a.out)


if __name__ == "__main__":
    main()
