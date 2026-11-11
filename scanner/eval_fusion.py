r"""Tang 5 - SO SANH CAC CACH KET HOP + ablation + tuong quan loi + doi chieu mo hinh hoc.

So sanh (theo de cuong): HOAC / VA / cong diem co gioi han theo ho / bo phieu da so /
bo phieu co trong so (baseline meta_arbiter) / XAC NHAN CHEO THEO HO, canh cac tang don le
va hai mo hinh hoc (Logistic Regression, LightGBM) tren diem cac ho.

Chong ao tuong:
  * Nguong va mo hinh hoc chi duoc chon/huan luyen tren FOLD TRAIN, do tren FOLD TEST.
  * Chia fold theo NHOM package (StratifiedGroupKFold): cung package khong nam o ca hai phia.
  * Diem ho A la diem out-of-fold cua Tang 1 (oof_layer1.csv).
  * --permute: xao tron nhan -> mo hinh hoc phai ve muc ngau nhien (AUC ~ 0.5).
  * Luon in so mau that tung lop canh moi con so.

Che do chia:
  --split cv      (mac dinh) CV nhom lap lai --repeats lan
  --split family  giu rieng tung LOP ma doc: mo hinh hoc khong duoc thay lop do khi huan luyen
  --split time    mau doc chia theo ngay (cot ngay cua --dates); can dien ngay truoc

Chay:  .\venv\Scripts\python.exe scanner\eval_fusion.py
       .\venv\Scripts\python.exe scanner\eval_fusion.py --split family
Ket qua: reports\layer5\ (fusion_metrics_<split>.csv, fusion_report_<split>.md)
"""
import argparse
import json
import os
import sys
import warnings

import numpy as np
import pandas as pd
from sklearn.impute import SimpleImputer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import roc_auc_score
from sklearn.model_selection import GroupShuffleSplit, StratifiedGroupKFold
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from scanner.fusion_common import (BENIGN, FAMS, LEVEL_RANK, PROCESSED, calibrate,  # noqa: E402
                                   capped_sum_score, describe, levels, load_table, over_matrix,
                                   threshold_at_fpr, weighted_vote_score)

M_A, M_B, M_C = "Tầng 1 đơn lẻ (họ A)", "Tầng 2+3 đơn lẻ (họ B)", "Tầng 4 đơn lẻ (họ C)"
M_OR, M_AND, M_MAJ = "HOẶC", "VÀ", "Bỏ phiếu đa số"
M_SUM, M_VOTE = "Cộng điểm có giới hạn theo họ", "Bỏ phiếu có trọng số (baseline)"
M_X_D, M_X_W, M_X_C = ("Xác nhận chéo: Nguy hiểm", "Xác nhận chéo: từ Đáng ngờ",
                       "Xác nhận chéo: từ Cần lưu ý")
M_LR, M_GBM = "Logistic Regression (học)", "LightGBM (học)"


def make_gbm():
    try:
        from lightgbm import LGBMClassifier
        return LGBMClassifier(n_estimators=100, num_leaves=7, min_child_samples=5,
                              learning_rate=0.1, random_state=42, n_jobs=1, verbose=-1), "LightGBM"
    except ImportError:
        from sklearn.ensemble import HistGradientBoostingClassifier
        return HistGradientBoostingClassifier(max_iter=100, max_leaf_nodes=7, min_samples_leaf=5,
                                              random_state=42), "HistGradientBoosting (chua cai lightgbm)"


def learned_scores(train, test):
    """Tra ve {ten: xac suat doc tren test}. Chi dung cot diem cac ho (khong metadata)."""
    cols = [k for k in FAMS if train[k].notna().any()]
    out = {}
    if train["y"].nunique() < 2 or not cols:
        return {M_LR: np.full(len(test), np.nan), M_GBM: np.full(len(test), np.nan)}
    Xtr, Xte, ytr = train[cols].to_numpy(float), test[cols].to_numpy(float), train["y"].to_numpy()
    lr = make_pipeline(SimpleImputer(strategy="median", add_indicator=True), StandardScaler(),
                       LogisticRegression(class_weight="balanced", max_iter=2000))
    out[M_LR] = lr.fit(Xtr, ytr).predict_proba(Xte)[:, 1]
    gbm, _ = make_gbm()
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        out[M_GBM] = gbm.fit(Xtr, ytr).predict_proba(Xte)[:, 1]
    return out


def predict_all(train, test, a):
    """Tra ve (decisions {ten: bool[]}, scores {ten: float[]}, levels[], thresholds)."""
    th, _ = calibrate(train, a.fpr_weak, a.fpr_strong, a.min_benign)
    weak, _, avail = over_matrix(test, th)
    dec, sc = {}, {}
    dec[M_A], sc[M_A] = weak[:, 0], test["a"].to_numpy(float)
    dec[M_B], sc[M_B] = weak[:, 1], test["b"].to_numpy(float)
    if test["c"].notna().any():
        dec[M_C], sc[M_C] = weak[:, 2], test["c"].to_numpy(float)
    dec[M_OR] = weak.any(axis=1)
    dec[M_AND] = (weak | ~avail).all(axis=1) & avail.any(axis=1)
    dec[M_MAJ] = weak.sum(axis=1) > avail.sum(axis=1) / 2.0
    s_tr, s_te = capped_sum_score(train), capped_sum_score(test)
    t_sum = threshold_at_fpr(s_tr[train["y"].to_numpy() == 0], a.fpr_weak)
    dec[M_SUM] = np.nan_to_num(s_te, nan=-1.0) >= (t_sum if t_sum is not None else 2.0)
    sc[M_SUM] = s_te
    sc[M_VOTE] = weighted_vote_score(test)
    dec[M_VOTE] = np.nan_to_num(sc[M_VOTE], nan=-1.0) >= 0.5
    lv = levels(test, th)
    rank = np.array([LEVEL_RANK[x] for x in lv])
    dec[M_X_D], dec[M_X_W], dec[M_X_C] = rank >= 3, rank >= 2, rank >= 1
    sc[M_X_W] = rank.astype(float)
    present = [k for k in FAMS if test[k].notna().any()]
    if len(present) >= 2:                      # ablation: bo tung ho khoi trong tai
        for drop in present:
            use = tuple(k for k in present if k != drop)
            r = np.array([LEVEL_RANK[x] for x in levels(test, th, use)])
            dec["Xác nhận chéo từ Đáng ngờ, BỎ họ %s" % drop.upper()] = r >= 2
    for name, p in learned_scores(train, test).items():
        sc[name] = p
        dec[name] = np.nan_to_num(p, nan=0.0) >= 0.5
    return dec, sc, lv, th


def metrics(y, d, s=None):
    y, d = np.asarray(y).astype(int), np.asarray(d).astype(bool)
    tp, fp = int((d & (y == 1)).sum()), int((d & (y == 0)).sum())
    fn, tn = int((~d & (y == 1)).sum()), int((~d & (y == 0)).sum())
    div = lambda n, m: n / m if m else float("nan")  # noqa: E731
    prec, rec = div(tp, tp + fp), div(tp, tp + fn)
    f1 = div(2 * prec * rec, prec + rec) if prec == prec and rec == rec else float("nan")
    auc = float("nan")
    if s is not None:
        ok = ~np.isnan(np.asarray(s, float))
        if ok.sum() and len(np.unique(y[ok])) == 2:
            auc = float(roc_auc_score(y[ok], np.asarray(s, float)[ok]))
    return {"accuracy": div(tp + tn, len(y)), "precision": prec, "recall": rec, "f1": f1,
            "fpr": div(fp, fp + tn), "auc": auc, "tp": tp, "fp": fp, "fn": fn, "tn": tn}


def splits_cv(t, a, seed):
    y_strat = t["label"].to_numpy()
    n = min(a.folds, int(t["label"].value_counts().min()))
    if n < 2:
        sys.exit("Lop nho nhat chi co %d mau - khong chia fold duoc" % t["label"].value_counts().min())
    cv = StratifiedGroupKFold(n_splits=n, shuffle=True, random_state=seed)
    for tr, te in cv.split(t, y_strat, t["group"]):
        if set(t["group"].iloc[tr]) & set(t["group"].iloc[te]):
            raise RuntimeError("nhom bi chia doi giua train/test")
        yield tr, te


def run_pooled(t, a, seed, split_fn):
    """Gop du doan tren cac fold test cua MOT lan lap."""
    n = len(t)
    dec, sc, lv = {}, {}, np.array([""] * n, dtype=object)
    seen = np.zeros(n, bool)
    for tr, te in split_fn(t, a, seed):
        d, s, l, _ = predict_all(t.iloc[tr], t.iloc[te], a)
        for k, v in d.items():
            dec.setdefault(k, np.zeros(n, bool))[te] = v
        for k, v in s.items():
            sc.setdefault(k, np.full(n, np.nan))[te] = v
        lv[te] = l
        seen[te] = True
    return dec, sc, lv, seen


def summarize(rows):
    df = pd.DataFrame(rows)
    keys = ["accuracy", "precision", "recall", "f1", "fpr", "auc"]
    g = df.groupby("method", sort=False)
    out = g[keys].mean().round(4)
    std = g[keys].std(ddof=0).round(4)
    for k in keys:
        out[k + "_std"] = std[k]
    for k in ("tp", "fp", "fn", "tn"):
        out[k] = g[k].mean().round(1)
    return out.reset_index()


def error_correlation(t, dec, seen):
    """Hai ho A va B co sai CUNG mau khong? (co so cua xac nhan cheo)."""
    both = seen & t["a"].notna().to_numpy() & t["b"].notna().to_numpy()
    y = t["y"].to_numpy()
    da, db = dec[M_A], dec[M_B]
    out = {"n_co_ca_hai_ho": int(both.sum())}
    for name, cls in (("doc", 1), ("sach", 0)):
        m = both & (y == cls)
        out[name] = {"n": int(m.sum()), "ca_hai_bao": int((da & db & m).sum()),
                     "chi_A_bao": int((da & ~db & m).sum()), "chi_B_bao": int((~da & db & m).sum()),
                     "khong_ho_nao_bao": int((~da & ~db & m).sum())}
    ea, eb = (da != (y == 1))[both], (db != (y == 1))[both]
    n11, n00 = int((ea & eb).sum()), int((~ea & ~eb).sum())
    n10, n01 = int((ea & ~eb).sum()), int((~ea & eb).sum())
    den = (n11 + n10) * (n01 + n00) * (n11 + n01) * (n10 + n00)
    out["loi"] = {"ca_hai_sai": n11, "chi_A_sai": n10, "chi_B_sai": n01, "ca_hai_dung": n00,
                  "phi": round((n11 * n00 - n10 * n01) / den ** 0.5, 4) if den else None,
                  "yule_q": round((n11 * n00 - n10 * n01) / (n11 * n00 + n10 * n01), 4)
                  if (n11 * n00 + n10 * n01) else None,
                  "ti_le_ca_hai_sai": round(n11 / max(1, int(both.sum())), 4)}
    return out


def fmt_table(df, cols):
    head = "| " + " | ".join(cols) + " |\n|" + "|".join(["---"] * len(cols)) + "|\n"
    body = ""
    for _, r in df.iterrows():
        body += "| " + " | ".join(("—" if isinstance(r[c], float) and r[c] != r[c] else
                                   "%.3f" % r[c] if isinstance(r[c], float) else str(r[c]))
                                  for c in cols) + " |\n"
    return head + body


def run(a):
    t = load_table(a.oof, a.family_b, a.family_c, a.dates)
    info = describe(t)
    print("\n".join(info))
    if (t.y == 0).sum() < a.min_benign or (t.y == 1).sum() < 2:
        sys.exit("Qua it mau de danh gia.")
    if a.permute:
        rng = np.random.RandomState(a.seed)
        perm = rng.permutation(len(t))
        t["y"], t["label"] = t["y"].to_numpy()[perm], t["label"].to_numpy()[perm]
        print(">>> CHE DO XAO TRON NHAN: mo hinh hoc phai ve AUC ~ 0.5 <<<")
    notes, extra = [], {}
    rows = []

    if a.split == "cv":
        first = None
        for r in range(a.repeats):
            dec, sc, lv, seen = run_pooled(t, a, a.seed + r, splits_cv)
            if first is None:
                first = (dec, sc, lv, seen)
            for m in dec:
                rows.append(dict(method=m, repeat=r, **metrics(t["y"][seen], dec[m][seen],
                                                               sc[m][seen] if m in sc else None)))
        dec, sc, lv, seen = first
        extra["error_correlation"] = error_correlation(t, dec, seen)
        lvl = pd.crosstab(t["label"][seen], pd.Categorical(
            lv[seen], ["safe", "caution", "warning", "danger", "unknown"]), dropna=False)
        extra["levels_by_label"] = lvl
        notes.append("CV nhom %d fold x %d lan lap; so lieu la trung binh (± do lech chuan) qua cac lan lap."
                     % (a.folds, a.repeats))

    elif a.split == "family":
        per = []
        for cls in sorted(c for c in t["label"].unique() if c != BENIGN):
            def split_fn(tt, aa, seed, cls=cls):
                for tr, te in splits_cv(tt, aa, seed):
                    lab = tt["label"].to_numpy()
                    yield tr[lab[tr] != cls], te[(lab[te] == cls) | (lab[te] == BENIGN)]
            dec, sc, lv, seen = run_pooled(t, a, a.seed, split_fn)
            for m in dec:
                r = metrics(t["y"][seen], dec[m][seen], sc[m][seen] if m in sc else None)
                rows.append(dict(method=m, repeat=cls, **r))
                per.append({"lop_giu_rieng": cls, "n_mau_lop": int((t["label"][seen] == cls).sum()),
                            "method": m, "recall": r["recall"], "fpr": r["fpr"]})
        extra["per_class"] = pd.DataFrame(per)
        notes.append("Giu rieng tung lop ma doc: mo hinh hoc KHONG thay lop do luc huan luyen. "
                     "Bang tong hop la trung binh qua cac lop giu rieng; xem recall tung lop ben duoi.")

    else:  # time
        mal = t[(t.y == 1) & t["date"].notna()]
        if len(mal) < 10:
            sys.exit("Chi %d mau doc co ngay. Dien cot ngay (first_seen) vao malware_manifest.csv "
                     "roi chay lai voi --dates malware_manifest.csv" % len(mal))
        cutoff = pd.Timestamp(a.cutoff) if a.cutoff else mal["date"].sort_values().iloc[len(mal) // 2]
        ben = t[t.y == 0]
        gss = GroupShuffleSplit(n_splits=1, test_size=0.5, random_state=a.seed)
        btr, bte = next(gss.split(ben, groups=ben["group"]))
        tr = np.concatenate([ben.index[btr], mal.index[mal["date"] < cutoff]])
        te = np.concatenate([ben.index[bte], mal.index[mal["date"] >= cutoff]])
        dec, sc, lv, _ = predict_all(t.loc[tr], t.loc[te], a)
        yte = t["y"].loc[te]
        for m in dec:
            rows.append(dict(method=m, repeat=0, **metrics(yte, dec[m], sc.get(m))))
        notes.append("Chia theo thoi gian: mau doc truoc %s de huan luyen (%d), tu ngay do tro di de "
                     "kiem tra (%d). Mau sach khong co ngay nen chia doi ngau nhien theo package "
                     "(train %d / test %d). Bo %d mau doc khong co ngay."
                     % (cutoff.date(), int((mal["date"] < cutoff).sum()),
                        int((mal["date"] >= cutoff).sum()), len(btr), len(bte),
                        int(((t.y == 1) & t["date"].isna()).sum())))

    summary = summarize(rows)
    cols = ["method", "accuracy", "precision", "recall", "f1", "fpr", "auc"]
    print("\n" + summary[cols + ["tp", "fp", "fn", "tn"]].to_string(index=False))
    for n in notes:
        print("GHI CHU:", n)

    os.makedirs(a.out_dir, exist_ok=True)
    tag = a.split + ("_permute" if a.permute else "")
    summary.to_csv(os.path.join(a.out_dir, "fusion_metrics_%s.csv" % tag), index=False)
    _, gbm_name = make_gbm()
    md = ["# Tầng 5 — So sánh các cách kết hợp (%s)%s\n" % (a.split, " — XÁO TRỘN NHÃN" if a.permute else ""),
          "\n".join("- " + x for x in info), "",
          "- Mục tiêu báo động giả khi chọn ngưỡng: yếu %.1f%%, mạnh %.1f%% (chọn trên fold train)."
          % (100 * a.fpr_weak, 100 * a.fpr_strong),
          "- Mô hình học tăng cường: %s." % gbm_name] + ["- " + n for n in notes] + [
          "", "## Chỉ số (fpr = tỉ lệ báo động giả trên mẫu sạch; auc trống = cách đó không có điểm liên tục)", "",
          fmt_table(summary, cols + ["tp", "fp", "fn", "tn"])]
    if "levels_by_label" in extra:
        lvl = extra["levels_by_label"]
        lvl.to_csv(os.path.join(a.out_dir, "levels_by_label.csv"))
        md += ["## Phân bố 4 mức theo lớp (lần lặp đầu, trên fold test)", "",
               fmt_table(lvl.reset_index().rename(columns={"label": "lớp"}),
                         ["lớp", "safe", "caution", "warning", "danger", "unknown"])]
        print("\nPHAN BO MUC THEO LOP:\n" + lvl.to_string())
    if "error_correlation" in extra:
        ec = extra["error_correlation"]
        with open(os.path.join(a.out_dir, "error_correlation.json"), "w", encoding="utf-8") as f:
            json.dump(ec, f, ensure_ascii=False, indent=2)
        md += ["## Tương quan lỗi giữa họ A và họ B", "", "```json",
               json.dumps(ec, ensure_ascii=False, indent=2), "```",
               "phi/yule_q gần 0 = hai họ sai độc lập (xác nhận chéo có lợi); gần 1 = hay sai cùng mẫu."]
        print("\nTUONG QUAN LOI A-B:", json.dumps(ec, ensure_ascii=False))
    if "per_class" in extra:
        pc = extra["per_class"]
        pc.to_csv(os.path.join(a.out_dir, "fusion_per_heldout_class.csv"), index=False)
        piv = pc.pivot(index="method", columns="lop_giu_rieng", values="recall").round(3)
        nrow = pc.drop_duplicates("lop_giu_rieng").set_index("lop_giu_rieng")["n_mau_lop"]
        piv.columns = ["%s (n=%d)" % (c, nrow[c]) for c in piv.columns]
        md += ["## Recall trên từng lớp bị giữ riêng", "",
               fmt_table(piv.reset_index(), ["method"] + list(piv.columns))]
        print("\nRECALL TREN LOP GIU RIENG:\n" + piv.to_string())
    sec = t["seconds_b"].dropna()
    if len(sec):
        md += ["", "Thời gian phân tích Tầng 2+3 mỗi APK (không tính mẫu lấy từ cache): trung vị %.1f giây, "
               "p90 %.1f giây (n=%d)." % (sec.median(), sec.quantile(0.9), len(sec))]
    path = os.path.join(a.out_dir, "fusion_report_%s.md" % tag)
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(md) + "\n")
    print("\nDa ghi:", path)
    return summary, extra


def main():
    try:  # console Windows (cp1252) khong in duoc tieng Viet co dau
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):
        pass
    ap = argparse.ArgumentParser()
    ap.add_argument("--oof", default=os.path.join(PROCESSED, "oof_layer1.csv"))
    ap.add_argument("--family-b", default=os.path.join(PROCESSED, "family_b_scores.csv"))
    ap.add_argument("--family-c", default=os.path.join(PROCESSED, "family_c_scores.csv"))
    ap.add_argument("--dates", default=os.path.join(ROOT, "malware_manifest.csv"))
    ap.add_argument("--out-dir", default=os.path.join(ROOT, "reports", "layer5"))
    ap.add_argument("--split", choices=["cv", "family", "time"], default="cv")
    ap.add_argument("--cutoff", default="", help="--split time: ngay cat (YYYY-MM-DD); mac dinh = trung vi")
    ap.add_argument("--folds", type=int, default=5)
    ap.add_argument("--repeats", type=int, default=5)
    ap.add_argument("--fpr-weak", type=float, default=0.05)
    ap.add_argument("--fpr-strong", type=float, default=0.01)
    ap.add_argument("--min-benign", type=int, default=20)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--permute", action="store_true")
    run(ap.parse_args())


if __name__ == "__main__":
    main()
