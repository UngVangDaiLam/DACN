# scanner/stacking.py
"""
Buoc 5.3b - Stacking bang Logistic Regression tren diem OUT-OF-FOLD (Tang 5).

Dau vao: dataset/processed/oof_layer1.csv (tao boi oof_scores.py). Hien chi co Tang 1,
nen day la HIEU CHINH lai xac suat L1, CHUA phai stacking nhieu tang. Khi co OOF cua
L4 (cot l4_p_<lop>) thi them --layers L1,L4.

Quy tac chong ro ri:
  * dac trung meta CHI la xac suat cac tang (cot p_* / l4_p_*); khong dung metadata,
    min_sdk, ten goi... -> meta khong hoc duoc tin hieu 'nguon du lieu / thoi dai'.
  * danh gia meta bang CV co nhom (StratifiedGroupKFold, seed khac voi luc tao OOF).
  * --permute : xao tron nhan cua meta; ket qua phai ve muc ngau nhien.
Tang vang mat KHONG duoc dien 0: moi to hop tang co mat -> mot mo hinh meta rieng.

Chay:  python scanner/stacking.py [--layers L1] [--folds 5] [--permute]
"""
import argparse
import os
import sys

import numpy as np
import pandas as pd
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (accuracy_score, classification_report, confusion_matrix,
                             f1_score, log_loss)
from sklearn.model_selection import StratifiedGroupKFold
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import FunctionTransformer, StandardScaler

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CLASSES = ["Adware", "Banking", "Benign", "Riskware", "SMS"]
PREFIX = {"L1": "p_", "L4": "l4_p_"}
EPS = 1e-4


def meta_columns(df, layers):
    cols = []
    for L in layers:
        if L not in PREFIX:
            sys.exit("Tang khong ho tro: %s (chi %s)" % (L, sorted(PREFIX)))
        c = [PREFIX[L] + k for k in CLASSES]
        miss = [x for x in c if x not in df.columns]
        if miss:
            sys.exit("OOF thieu cot cua %s: %s" % (L, miss))
        cols += c
    # chong dac trung la metadata lot vao
    assert all(c.startswith(tuple(PREFIX.values())) for c in cols)
    return cols


def logit_feats(P):
    P = np.clip(np.asarray(P, dtype=float), EPS, 1 - EPS)
    return np.log(P / (1 - P))


def make_meta():
    return make_pipeline(FunctionTransformer(logit_feats), StandardScaler(),
                         LogisticRegression(C=1.0, class_weight="balanced", max_iter=5000))


def cv_meta(X, y, groups, n_splits, seed):
    K = len(CLASSES)
    cv = StratifiedGroupKFold(n_splits=n_splits, shuffle=True, random_state=seed)
    out = np.full((len(y), K), np.nan)
    for f, (tr, te) in enumerate(cv.split(X, y, groups)):
        if len(np.unique(y[tr])) < K:
            sys.exit("fold %d: tap train thieu lop - giam --folds" % f)
        if set(groups.iloc[tr]) & set(groups.iloc[te]):
            sys.exit("fold %d: nhom bi chia doi" % f)
        out[te] = make_meta().fit(X[tr], y[tr]).predict_proba(X[te])
    if np.isnan(out).any():
        sys.exit("Con mau chua duoc cham")
    return out


def binary_report(name, true_lab, p_mal):
    mal = true_lab != "Benign"
    pred = p_mal >= 0.5
    tp, fn = int((mal & pred).sum()), int((mal & ~pred).sum())
    fp, tn = int((~mal & pred).sum()), int((~mal & ~pred).sum())
    print("  %-10s doc bat duoc %d/%d | sach bi bao nham %d/%d" % (name, tp, tp + fn, fp, fp + tn))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--oof", default=os.path.join(ROOT, "dataset", "processed", "oof_layer1.csv"))
    ap.add_argument("--layers", default="L1")
    ap.add_argument("--folds", type=int, default=5)
    ap.add_argument("--seed", type=int, default=7)   # KHAC seed tao OOF (42)
    ap.add_argument("--permute", action="store_true")
    a = ap.parse_args()
    layers = [x.strip() for x in a.layers.split(",") if x.strip()]

    df = pd.read_csv(a.oof)
    for c in ("sha256", "package_name", "label"):
        if c not in df.columns:
            sys.exit("OOF thieu cot %s" % c)
    cols = meta_columns(df, layers)
    if df[cols].isna().any().any():
        sys.exit("Co o NaN trong diem tang - tang vang mat phai tach to hop rieng, khong dien 0")
    df = df[df["label"].isin(CLASSES)].reset_index(drop=True)
    X = df[cols].to_numpy(dtype=float)
    if layers == ["L1"] and abs(X.sum(axis=1) - 1).max() > 1e-3:
        sys.exit("Xac suat L1 khong cong lai = 1")
    y = df["label"].map({c: i for i, c in enumerate(CLASSES)}).to_numpy()
    K = len(CLASSES)
    pkg = df["package_name"]
    groups = pkg.where(pkg.notna() & (pkg.astype(str).str.strip() != ""), df["sha256"]).astype(str)
    counts = np.bincount(y, minlength=K)
    print("Tang dung:", layers, "| dac trung meta:", len(cols))
    print("So mau moi lop:", dict(zip(CLASSES, map(int, counts))), "| tong", len(y))
    print("So nhom: %d / %d mau" % (groups.nunique(), len(y)))
    folds = min(a.folds, int(counts.min()))
    if folds < 2:
        sys.exit("Qua it mau")

    if a.permute:
        yp = np.random.RandomState(a.seed).permutation(y)
        P = cv_meta(X, yp, groups, folds, a.seed)
        print(">>> XAO TRON NHAN: meta phai ~ ngau nhien <<<")
        print("Muc ngau nhien ky vong (tong p_i^2): %.3f" % float(((counts / len(y)) ** 2).sum()))
        print("Meta CV accuracy sau xao tron: %.3f" % accuracy_score(yp, P.argmax(1)))
        return

    P = cv_meta(X, y, groups, folds, a.seed)
    pm = P.argmax(1)
    raw = df[["p_" + c for c in CLASSES]].to_numpy()   # L1 tho (chi de so sanh)
    pr = raw.argmax(1)
    print("\n%-22s %8s %9s %9s" % ("", "accuracy", "macro-F1", "log-loss"))
    print("%-22s %8.3f %9.3f %9.3f" % ("L1 tho (OOF)", accuracy_score(y, pr),
          f1_score(y, pr, average="macro"), log_loss(y, np.clip(raw, 1e-6, 1) / np.clip(raw, 1e-6, 1).sum(1, keepdims=True), labels=range(K))))
    print("%-22s %8.3f %9.3f %9.3f" % ("Meta LR (CV long)", accuracy_score(y, pm),
          f1_score(y, pm, average="macro"), log_loss(y, P, labels=range(K))))
    print("So mau hai cach khac nhan:", int((pr != pm).sum()), "/", len(y))
    print("\nMeta LR - bao cao tung lop:")
    print(classification_report(y, pm, labels=list(range(K)), target_names=CLASSES, zero_division=0))
    print("Confusion matrix meta (hang=that, cot=doan; thu tu:", CLASSES, ")")
    print(confusion_matrix(y, pm, labels=list(range(K))))

    lab = df["label"].to_numpy()
    print("\nQUYET DINH NHI PHAN doc/sach (nguong 0.5), dem mau that:")
    binary_report("L1 tho", lab, 1 - raw[:, 2])
    binary_report("Meta LR", lab, 1 - P[:, 2])
    print("  Ty le bat duoc theo ho (meta):",
          {c: "%d/%d" % (int((P[y == i, 2] < 0.5).sum()), int(counts[i]))
           for i, c in enumerate(CLASSES) if c != "Benign"})

    ins = make_meta().fit(X, y).predict_proba(X).argmax(1)
    print("\nMeta in-sample accuracy: %.3f | CV: %.3f | khoang cach %.3f" %
          (accuracy_score(y, ins), accuracy_score(y, pm), accuracy_score(y, ins) - accuracy_score(y, pm)))
    print("LUU Y: voi vai chuc mau/lop, chenh lech vai mau KHONG co y nghia thong ke;"
          " day la minh hoa phuong phap.")


if __name__ == "__main__":
    main()
