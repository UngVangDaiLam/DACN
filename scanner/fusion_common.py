r"""Tang 5 - Phan dung chung cho hieu chinh nguong va danh gia cach ket hop.

Bang diem moi mau (mot dong / mau):
  sha256, group, label, y (1 = doc), a, b, c (NaN = ho vang mat), b_partial, date (tuy chon)

Nguon:
  * a = 1 - p_Benign tu dataset/processed/oof_layer1.csv (diem OUT-OF-FOLD cua Tang 1:
    mo hinh cham diem KHONG thay mau do luc huan luyen).
  * b = score_b tu dataset/processed/family_b_scores.csv; neu bi cat/khuyet thi dung
    observed_score_b lam can duoi (b_partial = True).
  * c = cot score_c cua file --family-c (khi Tang 4 co diem).
Khong dien 0 cho ho vang mat.
"""
import os

import numpy as np
import pandas as pd

from scanner.family_arbiter import DEFAULT_THRESHOLDS, LEVELS, decide_level

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PROCESSED = os.path.join(ROOT, "dataset", "processed")
BENIGN = "Benign"
FAMS = ("a", "b", "c")
MIN_THRESHOLD = 0.02     # diem 0 khong bao gio duoc tinh la "vuot nguong"
VOTE_WEIGHTS = {"a": 0.45, "c": 0.45, "b": 0.10}   # = meta_arbiter.WEIGHTS (L2 + L3 = 0.10)
SUM_CAP = 0.5            # tran diem moi ho trong cach "cong diem co gioi han"


# ---------------------------------------------------------------- bang diem
def load_table(oof_path, b_path, c_path=None, dates_path=None):
    oof = pd.read_csv(oof_path)
    if "p_" + BENIGN not in oof.columns:
        raise SystemExit("%s thieu cot p_%s" % (oof_path, BENIGN))
    oof = oof.drop_duplicates("sha256")
    pkg = oof["package_name"]
    group = pkg.where(pkg.notna() & (pkg.astype(str).str.strip() != ""), oof["sha256"]).astype(str)
    t = pd.DataFrame({"sha256": oof["sha256"].astype(str), "group": group.values,
                      "label": oof["label"].astype(str),
                      "a": 1.0 - oof["p_" + BENIGN].astype(float)})
    t["y"] = (t["label"] != BENIGN).astype(int)

    t["b"], t["b_partial"], t["seconds_b"] = np.nan, False, np.nan
    if b_path and os.path.exists(b_path):
        fb = pd.read_csv(b_path).drop_duplicates("sha256")
        fb["sha256"] = fb["sha256"].astype(str)
        ok = (fb["error"].isna() | (fb["error"].astype(str).str.strip() == "")) \
            & (fb["available"].astype(str) == "True")
        fb = fb[ok].set_index("sha256")
        full = pd.to_numeric(fb["score_b"], errors="coerce")
        obs = pd.to_numeric(fb["observed_score_b"], errors="coerce") \
            if "observed_score_b" in fb.columns else pd.Series(np.nan, index=fb.index)
        score = full.where(full.notna(), obs)
        t["b"] = t["sha256"].map(score)
        t["b_partial"] = t["sha256"].map(full.isna() & obs.notna()).fillna(False).astype(bool)
        if "seconds" in fb.columns:
            t["seconds_b"] = t["sha256"].map(pd.to_numeric(fb["seconds"], errors="coerce"))
    t["c"] = np.nan
    if c_path and os.path.exists(c_path):
        fc = pd.read_csv(c_path).drop_duplicates("sha256")
        t["c"] = t["sha256"].map(pd.to_numeric(fc.set_index(fc["sha256"].astype(str))["score_c"],
                                               errors="coerce"))
    t["date"] = pd.NaT
    if dates_path and os.path.exists(dates_path):
        d = pd.read_csv(dates_path, encoding="utf-8-sig")
        col = next((c for c in ("ngay", "date", "first_seen") if c in d.columns), None)
        if col:
            d = d.drop_duplicates("sha256")
            t["date"] = t["sha256"].map(pd.to_datetime(
                d.set_index(d["sha256"].astype(str))[col], errors="coerce"))
    for k in FAMS:
        bad = t[k].notna() & ~t[k].between(0.0, 1.0)
        if bad.any():
            raise SystemExit("Diem ho %s ngoai [0,1] o %d mau" % (k.upper(), int(bad.sum())))
    return t.reset_index(drop=True)


def describe(t):
    lines = ["So mau: %d (sach %d, doc %d) | so nhom (package): %d"
             % (len(t), int((t.y == 0).sum()), int((t.y == 1).sum()), t["group"].nunique()),
             "Theo lop: %s" % t["label"].value_counts().to_dict()]
    for k in FAMS:
        n = int(t[k].notna().sum())
        extra = " (trong do %d mau la can duoi vi bi cat)" % int(t.b_partial.sum()) if k == "b" else ""
        lines.append("Ho %s co diem: %d/%d mau%s" % (k.upper(), n, len(t), extra))
    return lines


# ---------------------------------------------------------------- hieu chinh nguong
def threshold_at_fpr(benign_scores, alpha):
    """Nguong t NHO NHAT sao cho ti le mau sach co diem >= t khong vuot alpha."""
    s = np.sort(np.asarray(benign_scores, dtype=float))
    s = s[~np.isnan(s)]
    if len(s) == 0:
        return None
    cands = np.unique(np.concatenate([s, [np.nextafter(s[-1], 2.0)]]))
    for t in cands:
        if np.mean(s >= t) <= alpha:
            return float(min(1.0, max(MIN_THRESHOLD, t)))
    return 1.0


def calibrate(t, fpr_weak, fpr_strong, min_benign=20):
    """Tra ve (thresholds {'A': (yeu, manh)...}, info). Ho khong du mau sach -> dung mac dinh."""
    th, info = dict(DEFAULT_THRESHOLDS), {}
    ben = t[t.y == 0]
    for k in FAMS:
        s = ben[k].dropna().to_numpy()
        K = k.upper()
        if len(s) < min_benign:
            info[K] = {"calibrated": False, "n_benign": int(len(s)),
                       "note": "khong du mau sach co diem (can >= %d) - dung nguong mac dinh" % min_benign}
            continue
        weak = threshold_at_fpr(s, fpr_weak)
        strong = max(weak, threshold_at_fpr(s, fpr_strong))
        th[K] = (round(weak, 4), round(strong, 4))
        notes = []
        if len(s) * fpr_strong < 1:
            notes.append("so mau sach (%d) qua it cho muc %.1f%%: nguong manh = ngay tren diem sach "
                         "cao nhat" % (len(s), 100 * fpr_strong))
        if len(s) * fpr_weak < 1:
            notes.append("so mau sach qua it cho muc %.1f%%" % (100 * fpr_weak))
        info[K] = {"calibrated": True, "n_benign": int(len(s)),
                   "fpr_weak_actual": float(np.mean(s >= weak)),
                   "fpr_strong_actual": float(np.mean(s >= strong)), "notes": notes}
    return th, info


# ---------------------------------------------------------------- cac cach ket hop
def over_matrix(t, th):
    """Tra ve (weak, strong, avail): 3 mang bool kich thuoc (n, 3) theo thu tu A, B, C."""
    S = t[list(FAMS)].to_numpy(dtype=float)
    avail = ~np.isnan(S)
    weak_t = np.array([th[k.upper()][0] for k in FAMS])
    strong_t = np.array([th[k.upper()][1] for k in FAMS])
    with np.errstate(invalid="ignore"):
        weak = avail & (S >= weak_t)
        strong = avail & (S >= strong_t)
    return weak, strong, avail


def levels(t, th, use=FAMS):
    """Muc 4 cap (+ unknown) cua trong tai theo ho, chi dung cac ho trong `use` (ablation)."""
    weak, strong, avail = over_matrix(t, th)
    idx = [FAMS.index(k) for k in use]
    partial = t["b_partial"].to_numpy() if "b" in use else np.zeros(len(t), bool)
    out = []
    for i in range(len(t)):
        strengths = ["strong" if strong[i, j] else "weak" for j in idx if weak[i, j]]
        core = [j for j in idx if FAMS[j] in ("a", "b")]
        core_complete = all(avail[i, j] for j in core) and not partial[i]
        out.append(decide_level(strengths, core_complete))
    return np.array(out)


def capped_sum_score(t):
    S = t[list(FAMS)].to_numpy(dtype=float)
    avail = ~np.isnan(S)
    num = np.where(avail, np.minimum(S, SUM_CAP), 0.0).sum(axis=1)
    den = avail.sum(axis=1) * SUM_CAP
    return np.where(den > 0, num / np.where(den > 0, den, 1), np.nan)


def weighted_vote_score(t):
    S = t[list(FAMS)].to_numpy(dtype=float)
    avail = ~np.isnan(S)
    w = np.array([VOTE_WEIGHTS[k] for k in FAMS])
    num = np.where(avail, S * w, 0.0).sum(axis=1)
    den = (avail * w).sum(axis=1)
    return np.where(den > 0, num / np.where(den > 0, den, 1), np.nan)


LEVEL_RANK = {"unknown": 0, **{name: i for i, name in enumerate(LEVELS)}}
