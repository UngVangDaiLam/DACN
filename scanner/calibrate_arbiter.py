r"""Tang 5 - HIEU CHINH NGUONG tung ho bang chung tren TAP SACH.

Theo de cuong: chon nguong sao cho ti le bao dong gia tren tap sach o muc chap nhan duoc,
SAU DO moi do kha nang phat hien. Nguong chi phu thuoc diem cua mau SACH (khong dung mau doc
de chon nguong).

  nguong yeu  = nguong nho nhat de <= --fpr-weak   mau sach vuot (mac dinh 5%)
  nguong manh = nguong nho nhat de <= --fpr-strong mau sach vuot (mac dinh 1%)

Ghi models/arbiter_thresholds.json -> scanner/family_arbiter.py tu dong dung.
Ho khong du mau sach co diem (vd ho C khi Tang 4 chua co) -> KHONG ghi, van dung nguong de xuat.

Chay:  .\venv\Scripts\python.exe scanner\calibrate_arbiter.py              (xem, khong ghi)
       .\venv\Scripts\python.exe scanner\calibrate_arbiter.py --write      (ghi file nguong)
"""
import argparse
import datetime
import json
import os
import sys

import numpy as np

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from scanner.family_arbiter import THRESHOLDS_PATH  # noqa: E402
from scanner.fusion_common import (FAMS, PROCESSED, calibrate, describe, load_table,  # noqa: E402
                                   threshold_at_fpr)


def bootstrap_ci(scores, alpha, n_boot, seed):
    """Khoang 95% cua nguong khi lay mau lai tap sach (do on dinh cua nguong)."""
    rng = np.random.RandomState(seed)
    scores = np.asarray(scores, dtype=float)
    vals = [threshold_at_fpr(rng.choice(scores, len(scores), replace=True), alpha)
            for _ in range(n_boot)]
    return float(np.percentile(vals, 2.5)), float(np.percentile(vals, 97.5))


def run(a):
    t = load_table(a.oof, a.family_b, a.family_c)
    print("\n".join(describe(t)))
    th, info = calibrate(t, a.fpr_weak, a.fpr_strong, a.min_benign)
    ben, mal = t[t.y == 0], t[t.y == 1]
    out = {}
    print("\nNGUONG (muc tieu bao dong gia: yeu %.1f%%, manh %.1f%%)" % (100 * a.fpr_weak, 100 * a.fpr_strong))
    for k in FAMS:
        K, i = k.upper(), info[k.upper()]
        if not i["calibrated"]:
            print("  Ho %s: KHONG hieu chinh - %s (n sach = %d)" % (K, i["note"], i["n_benign"]))
            continue
        sb, sm = ben[k].dropna().to_numpy(), mal[k].dropna().to_numpy()
        weak, strong = th[K]
        ci_w = bootstrap_ci(sb, a.fpr_weak, a.boot, a.seed)
        ci_s = bootstrap_ci(sb, a.fpr_strong, a.boot, a.seed + 1)
        det_w = float(np.mean(sm >= weak)) if len(sm) else float("nan")
        det_s = float(np.mean(sm >= strong)) if len(sm) else float("nan")
        print("  Ho %s (sach n=%d, doc n=%d):" % (K, len(sb), len(sm)))
        print("     yeu  = %.4f  [95%%: %.3f - %.3f] | bao dong gia %.3f | phat hien %.3f"
              % (weak, ci_w[0], ci_w[1], i["fpr_weak_actual"], det_w))
        print("     manh = %.4f  [95%%: %.3f - %.3f] | bao dong gia %.3f | phat hien %.3f"
              % (strong, ci_s[0], ci_s[1], i["fpr_strong_actual"], det_s))
        for note in i["notes"]:
            print("     CANH BAO: " + note)
        out[K] = {"weak": weak, "strong": strong, "n_benign": len(sb), "n_malicious": len(sm),
                  "ci95_weak": ci_w, "ci95_strong": ci_s,
                  "fpr_weak": i["fpr_weak_actual"], "fpr_strong": i["fpr_strong_actual"],
                  "detect_weak_in_sample": det_w, "detect_strong_in_sample": det_s,
                  "notes": i["notes"]}
    print("\nLUU Y: ti le 'phat hien' o tren la tren chinh tap nay (chi de tham khao). So lieu bao cao "
          "phai lay tu scanner\\eval_fusion.py (nguong chon tren fold train, do tren fold test).")
    if not out:
        print("Khong ho nao hieu chinh duoc -> khong ghi file.")
        return None
    data = {"calibrated": True,
            "thresholds": {K: [v["weak"], v["strong"]] for K, v in out.items()},
            "meta": {"created": datetime.datetime.now().isoformat(timespec="seconds"),
                     "target_fpr_weak": a.fpr_weak, "target_fpr_strong": a.fpr_strong,
                     "n_samples": int(len(t)), "n_benign": int(len(ben)), "n_malicious": int(len(mal)),
                     "benign_source": a.benign_source, "families": out,
                     "score_a": "1 - p_Benign, diem out-of-fold cua Tang 1"}}
    if a.write:
        os.makedirs(os.path.dirname(a.out), exist_ok=True)
        tmp = a.out + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        os.replace(tmp, a.out)
        print("Da ghi:", a.out)
    else:
        print("(Chua ghi file. Them --write de ghi %s)" % a.out)
    return data


def main():
    try:  # console Windows (cp1252) khong in duoc tieng Viet co dau
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):
        pass
    ap = argparse.ArgumentParser()
    ap.add_argument("--oof", default=os.path.join(PROCESSED, "oof_layer1.csv"))
    ap.add_argument("--family-b", default=os.path.join(PROCESSED, "family_b_scores.csv"))
    ap.add_argument("--family-c", default=os.path.join(PROCESSED, "family_c_scores.csv"))
    ap.add_argument("--out", default=THRESHOLDS_PATH)
    ap.add_argument("--fpr-weak", type=float, default=0.05)
    ap.add_argument("--fpr-strong", type=float, default=0.01)
    ap.add_argument("--min-benign", type=int, default=20)
    ap.add_argument("--boot", type=int, default=500)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--benign-source", default="F-Droid (chua co Google Play/AndroZoo)",
                    help="ghi vao file de biet nguong hieu chinh tren nguon sach nao")
    ap.add_argument("--write", action="store_true")
    a = ap.parse_args()
    if not 0 < a.fpr_strong <= a.fpr_weak < 1:
        sys.exit("Can 0 < --fpr-strong <= --fpr-weak < 1")
    run(a)


if __name__ == "__main__":
    main()
