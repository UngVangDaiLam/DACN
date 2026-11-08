# scanner/oof_scores.py
"""
Buoc 5.2 - Diem OUT-OF-FOLD (OOF) cua Tang 1, dung de huan luyen meta (Tang 5).

Moi mau chi duoc cham diem boi mo hinh KHONG thay mau do (va khong thay cac mau
cung nhom package_name) luc huan luyen. Cau hinh mo hinh + can bang lop GIONG
train_static_model.py (mo hinh dang trien khai models/static_model.pkl): cung tham so
XGBoost, sample_weight 'balanced' tinh tren tap train cua tung fold, KHONG SMOTE.
tests/test_oof_config.py kiem tra tu dong de hai file khong bi lech lai.

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
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
from sklearn.model_selection import StratifiedGroupKFold
from sklearn.utils.class_weight import compute_sample_weight
from xgboost import XGBClassifier

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CLASSES = ["Adware", "Banking", "Benign", "Riskware", "SMS"]  # = static_label_encoder.classes_ (abc)

# PHAI KHOP doi so XGBClassifier(...) trong train_static_model.py (= static_model.pkl.get_params()).
# Khong dat objective/tree_method: de mac dinh y nhu ban trien khai (multi:softprob tu suy ra;
# tree_method mac dinh cua xgboost dang cai).
XGB_PARAMS = dict(n_estimators=300, max_depth=6, learning_rate=0.1,
                  subsample=0.9, colsample_bytree=0.9, random_state=42,
                  eval_metric="mlogloss")


def make_model():
    # n_jobs=1 chi de OOF tai lap duoc tung bit; khong doi dinh nghia mo hinh.
    return XGBClassifier(**XGB_PARAMS, n_jobs=1)


def fit_predict(Xtr, ytr, Xte, K):
    """Giong train_static_model.py: KHONG SMOTE; can bang lop bang sample_weight 'balanced'
    tinh CHI tren tap train cua fold. Tra xac suat cho Xte (cot theo thu tu 0..K-1)."""
    if len(np.unique(ytr)) < K:
        raise RuntimeError("Tap train thieu lop - giam --folds")
    w = compute_sample_weight("balanced", ytr)
    return make_model().fit(Xtr, ytr, sample_weight=w).predict_proba(Xte)


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
        X = df[feats].fillna(0).astype(float)  # giong train_static_model.py (hien du lieu khong co NaN)
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
