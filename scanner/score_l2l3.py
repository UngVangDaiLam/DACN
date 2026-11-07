# scanner/score_l2l3.py
"""
Buoc 5.4a - Cham diem L2 (lam roi) va L3 (rule_score) cho TUNG MAU bang
scanner/deep_analysis.analyze_deep. Danh sach mau lay tu oof_layer1.csv (139 mau, cung
tap voi diem L1), APK tim trong dataset/raw_apk theo SHA256.

  * Chi DOC apk; khong dung nhan de cham diem.
  * Ghi tung dong ngay (dataset/processed/l2l3_scores.csv); chay lai se bo qua mau da xong
    (mau loi duoc thu lai). Ctrl+C an toan.
  * rule_score thang 0-100. obfuscated_class_ratio thang 0-1 (de lam diem L2 tam).
Chay:  python scanner/score_l2l3.py --limit 3      (thu 3 mau)
       python scanner/score_l2l3.py                (toan bo)
"""
import argparse
import csv
import hashlib
import json
import os
import sys
import time
import traceback

import pandas as pd

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FIELDS = ["sha256", "package_name", "label", "min_sdk", "target_sdk", "rule_score",
          "dex_entropy", "obfuscated_class_ratio", "class_count", "n_embedded_payloads",
          "n_native_libs", "categories_capped_json", "error", "seconds"]


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def load_analyze_deep():
    try:
        from loguru import logger
        logger.disable("androguard")
    except Exception:
        pass
    sys.path.insert(0, ROOT)
    try:
        from scanner.deep_analysis import analyze_deep
        return analyze_deep
    except ImportError:
        sys.path.insert(0, os.path.join(ROOT, "scanner"))
        from deep_analysis import analyze_deep
        return analyze_deep


def num(x, default=None):
    try:
        return float(x)
    except (TypeError, ValueError):
        return default


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--apk-dir", default=os.path.join(ROOT, "dataset", "raw_apk"))
    ap.add_argument("--oof", default=os.path.join(ROOT, "dataset", "processed", "oof_layer1.csv"))
    ap.add_argument("--features", default=os.path.join(ROOT, "dataset", "processed", "static_features.csv"))
    ap.add_argument("--out", default=os.path.join(ROOT, "dataset", "processed", "l2l3_scores.csv"))
    ap.add_argument("--limit", type=int, default=0, help="chi cham N mau dau chua xong (0 = het)")
    a = ap.parse_args()

    oof = pd.read_csv(a.oof, usecols=["sha256", "package_name", "label"])
    feat = pd.read_csv(a.features, low_memory=False, usecols=["sha256", "min_sdk", "target_sdk"])
    feat = feat.drop_duplicates("sha256").set_index("sha256")
    want = oof.drop_duplicates("sha256").set_index("sha256")

    # 1) tim file APK theo sha256
    found = {}
    for dp, _, fns in os.walk(a.apk_dir):
        for fn in fns:
            if fn.lower().endswith(".apk"):
                p = os.path.join(dp, fn)
                s = sha256_file(p)
                if s in want.index and s not in found:
                    found[s] = p
    miss = [s for s in want.index if s not in found]
    print("Mau can cham: %d | tim thay APK: %d | KHONG thay APK: %d" % (len(want), len(found), len(miss)))
    if miss:
        print("  (vi du sha256 thieu APK: %s)" % miss[:3])

    # 2) mau da xong
    done = set()
    if os.path.exists(a.out) and os.path.getsize(a.out) > 0:
        old = pd.read_csv(a.out, dtype=str, keep_default_na=False)
        done = set(old.loc[old["error"] == "", "sha256"])
    todo = [s for s in found if s not in done]
    if a.limit:
        todo = todo[:a.limit]
    print("Da xong truoc do: %d | se cham: %d" % (len(done), len(todo)))

    if todo:
        analyze_deep = load_analyze_deep()
        new_file = not os.path.exists(a.out) or os.path.getsize(a.out) == 0
        os.makedirs(os.path.dirname(a.out), exist_ok=True)
        with open(a.out, "a", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=FIELDS)
            if new_file:
                w.writeheader()
            for i, s in enumerate(todo, 1):
                row = {k: "" for k in FIELDS}
                row.update(sha256=s, package_name=want.loc[s, "package_name"], label=want.loc[s, "label"],
                           min_sdk=feat.loc[s, "min_sdk"] if s in feat.index else "",
                           target_sdk=feat.loc[s, "target_sdk"] if s in feat.index else "")
                t0 = time.time()
                try:
                    r = analyze_deep(found[s])
                    obf = r.get("obfuscation") or {}
                    row.update(rule_score=num(r.get("rule_score")),
                               dex_entropy=num(obf.get("dex_entropy")),
                               obfuscated_class_ratio=num(obf.get("obfuscated_class_ratio")),
                               class_count=num(obf.get("class_count")),
                               n_embedded_payloads=len(obf.get("embedded_payloads") or []),
                               n_native_libs=len(obf.get("native_libs") or []),
                               categories_capped_json=json.dumps(r.get("category_scores_capped") or {}))
                    if row["rule_score"] is None:
                        row["error"] = "khong co rule_score trong ket qua"
                except KeyboardInterrupt:
                    print("\nDung theo yeu cau (Ctrl+C). Chay lai de tiep tuc.")
                    break
                except Exception as e:
                    row["error"] = ("%s: %s" % (type(e).__name__, e))[:200].replace("\n", " ")
                    if i <= 2:
                        traceback.print_exc()
                row["seconds"] = round(time.time() - t0, 1)
                w.writerow(row)
                f.flush()
                if i % 10 == 0 or i == len(todo) or row["error"]:
                    print("  [%d/%d] %s %s%s" % (i, len(todo), s[:10], row["label"],
                                                 "  LOI: " + row["error"] if row["error"] else ""))

    # 3) gop dong trung (giu dong cuoi) va tom tat
    if not (os.path.exists(a.out) and os.path.getsize(a.out) > 0):
        return
    df = pd.read_csv(a.out, keep_default_na=False)
    df = df.drop_duplicates("sha256", keep="last")
    df.to_csv(a.out, index=False)
    ok = df[df["error"].astype(str) == ""].copy()
    print("\nTONG KET: %d dong | thanh cong %d | loi %d" % (len(df), len(ok), len(df) - len(ok)))
    if len(df) - len(ok):
        print(df.loc[df["error"].astype(str) != "", "error"].value_counts().head(5).to_string())
    if ok.empty:
        return
    for c in ("rule_score", "obfuscated_class_ratio", "min_sdk"):
        ok[c] = pd.to_numeric(ok[c], errors="coerce")
    print("\nrule_score theo lop (so mau, trung binh, trung vi, min, max):")
    print(ok.groupby("label")["rule_score"].agg(["count", "mean", "median", "min", "max"]).round(1).to_string())
    print("\nobfuscated_class_ratio theo lop:")
    print(ok.groupby("label")["obfuscated_class_ratio"].agg(["count", "mean", "median"]).round(3).to_string())
    sub = ok.dropna(subset=["rule_score", "min_sdk"])
    if len(sub) > 5:
        print("\nKIEM TRA THOI DAI cua L3: Spearman(rule_score, min_sdk)")
        print("  toan bo (n=%d): %.2f" % (len(sub), sub["rule_score"].corr(sub["min_sdk"], method="spearman")))
        for lab, g in sub.groupby("label"):
            if len(g) >= 8:
                print("  chi lop %-9s (n=%d): %.2f" % (lab, len(g), g["rule_score"].corr(g["min_sdk"], method="spearman")))
    print("Da ghi:", a.out)


if __name__ == "__main__":
    main()
