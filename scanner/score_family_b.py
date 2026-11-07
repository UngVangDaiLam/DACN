# scanner/score_family_b.py
r"""
Buoc 5.4b - Cham diem HO B (Tang 2 + 3) cho tung mau va THONG KE de chon nguong.

  * Danh sach mau lay tu oof_layer1.csv; APK tim trong dataset/raw_apk theo SHA256.
  * layer2/layer3 tho (output cua An) duoc CACHE tung mau trong dataset/processed/layers_cache/
    -> chay lai / doi he so trong scanner/capabilities.py chi mat vai giay, khong phan tich lai APK.
  * Diem ho B tinh bang scanner/family_scores.score_family_b (khong dung nhan de cham diem).
  * Chi DOC apk. Ctrl+C an toan (cache da luu tung mau).

Chay:  .\venv\Scripts\python.exe scanner\score_family_b.py --limit 3     (thu 3 mau)
       .\venv\Scripts\python.exe scanner\score_family_b.py               (toan bo)
"""
import argparse
import hashlib
import json
import os
import sys
import time
import traceback
from collections import Counter

import pandas as pd

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from scanner.family_scores import score_family_b  # noqa: E402

FIELDS = ["sha256", "package_name", "label", "available", "score_b", "n_capabilities",
          "capabilities", "notes", "error", "seconds"]
THRESHOLDS = (0.1, 0.2, 0.3, 0.4, 0.5)
BENIGN = "Benign"


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def find_apks(apk_dir, wanted):
    found = {}
    for dp, _, fns in os.walk(apk_dir):
        for fn in fns:
            if fn.lower().endswith(".apk"):
                p = os.path.join(dp, fn)
                s = sha256_file(p)
                if s in wanted and s not in found:
                    found[s] = p
    return found


def load_analyze_deep():
    try:
        from loguru import logger
        logger.disable("androguard")
    except Exception:
        pass
    from scanner.deep_analysis import analyze_deep
    return analyze_deep


def get_layers(sha, apk_path, cache_dir, analyze):
    """Tra ve (layer2, layer3, tu_cache). Gan truong 'layer' neu tang chua co."""
    path = os.path.join(cache_dir, sha + ".json")
    if os.path.exists(path):
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        return data.get("layer2"), data.get("layer3"), True
    r = analyze(apk_path)
    l2, l3 = r.get("layer2"), r.get("layer3")
    if l2 is None and l3 is None:
        raise RuntimeError("deep_analysis khong tra ve layer2/layer3")
    l2 = dict(l2, layer=2) if l2 is not None else None
    l3 = dict(l3, layer=3) if l3 is not None else None
    os.makedirs(cache_dir, exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump({"layer2": l2, "layer3": l3}, f, ensure_ascii=False)
    os.replace(tmp, path)
    return l2, l3, False


def summarize(df):
    ok = df[(df["error"].astype(str) == "") & (df["available"].astype(str) == "True")].copy()
    ok["score_b"] = pd.to_numeric(ok["score_b"], errors="coerce")
    ok = ok.dropna(subset=["score_b"])
    if ok.empty:
        print("Khong co mau nao co diem ho B.")
        return
    print("\nDIEM HO B theo lop (so mau, trung binh, trung vi, p90, max):")
    g = ok.groupby("label")["score_b"]
    print(pd.DataFrame({"n": g.count(), "mean": g.mean(), "median": g.median(),
                        "p90": g.quantile(0.9), "max": g.max()}).round(3).to_string())
    ben, mal = ok[ok["label"] == BENIGN], ok[ok["label"] != BENIGN]
    print("\nTI LE MAU CO DIEM >= NGUONG  (Benign = bao dong gia; con lai = phat hien)")
    print("  nguong | Benign (n=%d) | Doc gop (n=%d) | theo lop" % (len(ben), len(mal)))
    for t in THRESHOLDS:
        fp = (ben["score_b"] >= t).mean() if len(ben) else float("nan")
        tp = (mal["score_b"] >= t).mean() if len(mal) else float("nan")
        per = ", ".join("%s %.2f" % (lab, (gg["score_b"] >= t).mean())
                        for lab, gg in mal.groupby("label"))
        print("  %5.2f  |    %5.2f     |     %5.2f      | %s" % (t, fp, tp, per))

    def cap_share(sub):
        c = Counter()
        for js in sub["capabilities"]:
            for cap in json.loads(js) if isinstance(js, str) and js else []:
                c[cap] += 1
        return {k: v / max(1, len(sub)) for k, v in c.items()}
    sb, sm = cap_share(ben), cap_share(mal)
    print("\nCAPABILITY: ti le mau CO capability (Benign vs Doc gop)")
    for cap in sorted(set(sb) | set(sm), key=lambda k: -sb.get(k, 0)):
        print("  %-32s Benign %.2f | Doc %.2f" % (cap, sb.get(cap, 0), sm.get(cap, 0)))


def run(a, analyze=None):
    oof = pd.read_csv(a.oof, usecols=["sha256", "package_name", "label"])
    want = oof.drop_duplicates("sha256").set_index("sha256")
    found = find_apks(a.apk_dir, set(want.index))
    miss = [s for s in want.index if s not in found]
    print("Mau can cham: %d | tim thay APK: %d | KHONG thay APK: %d" % (len(want), len(found), len(miss)))
    rows, new = [], 0
    for i, s in enumerate(found, 1):
        cached = os.path.exists(os.path.join(a.cache, s + ".json"))
        if not cached and a.limit and new >= a.limit:
            continue
        row = {k: "" for k in FIELDS}
        row.update(sha256=s, package_name=want.loc[s, "package_name"], label=want.loc[s, "label"])
        t0 = time.time()
        try:
            if analyze is None and not cached:
                analyze = load_analyze_deep()
            l2, l3, from_cache = get_layers(s, found[s], a.cache, analyze)
            new += 0 if from_cache else 1
            r = score_family_b(l2, l3)
            row.update(available=r["available"], score_b=r["score"],
                       n_capabilities=len(r["evidence"]),
                       capabilities=json.dumps([e["capability"] for e in r["evidence"]]),
                       notes=" | ".join(r["notes"]))
        except KeyboardInterrupt:
            print("\nDung theo yeu cau (Ctrl+C). Cache da luu; chay lai de tiep tuc.")
            break
        except Exception as e:
            row["error"] = ("%s: %s" % (type(e).__name__, e))[:200].replace("\n", " ")
            if new <= 2:
                traceback.print_exc()
        row["seconds"] = round(time.time() - t0, 1)
        rows.append(row)
        if len(rows) % 10 == 0 or row["error"]:
            print("  [%d] %s %s%s" % (len(rows), s[:10], row["label"],
                                      "  LOI: " + row["error"] if row["error"] else ""))
    df = pd.DataFrame(rows, columns=FIELDS)
    os.makedirs(os.path.dirname(a.out), exist_ok=True)
    df.to_csv(a.out, index=False)
    nerr = int((df["error"].astype(str) != "").sum())
    print("\nTONG KET: %d mau | loi %d | phan tich moi %d | da ghi %s" % (len(df), nerr, new, a.out))
    if nerr:
        print(df.loc[df["error"].astype(str) != "", "error"].value_counts().head(5).to_string())
    summarize(df)
    return df


def main():
    p = os.path.join(ROOT, "dataset", "processed")
    ap = argparse.ArgumentParser()
    ap.add_argument("--apk-dir", default=os.path.join(ROOT, "dataset", "raw_apk"))
    ap.add_argument("--oof", default=os.path.join(p, "oof_layer1.csv"))
    ap.add_argument("--cache", default=os.path.join(p, "layers_cache"))
    ap.add_argument("--out", default=os.path.join(p, "family_b_scores.csv"))
    ap.add_argument("--limit", type=int, default=0, help="chi phan tich moi N mau chua co cache (0 = het)")
    run(ap.parse_args())


if __name__ == "__main__":
    main()
