# scanner/evaluate_ablation.py
r"""
Pha C - Ablation THEO TANG cho Tang 5 (meta_arbiter.weighted_vote).

  * Khac voi eval_ablation.py co san: file do chi bo/them NHOM DAC TRUNG ben trong L1.
    File nay bo/them CA TANG (L1, L2, L3, L4) o dau vao cua bo tong hop.
  * Du lieu: oof_layer1.csv (diem L1 out-of-fold) + l2l3_scores.csv (L2, L3), noi theo sha256.
    NaN -> None (tang vang mat, KHONG dien 0). L4 vang (n=0).
  * Quyet dinh NHI PHAN: P(doc) = 1 - P(Benign), nguong = meta_arbiter.T_MAL. Nhan ho chi tham khao.
  * Trong so co dinh = meta_arbiter.WEIGHTS (khong tinh chinh tren nhan dang danh gia).
  * Meta chi dung DIEM CAC TANG; min_sdk/target_sdk CHI xuat hien o hang chan doan thoi dai.
  * Khong doc/ghi models/.

Chay:  .\venv\Scripts\python.exe -B scanner\evaluate_ablation.py
Ra:    reports/ablation.csv  +  reports/ablation_notes.txt
"""
import argparse
import csv
import os
import sys

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import roc_auc_score

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from scanner import meta_arbiter as m  # noqa: E402

COLS = ["hang", "nhom", "tang", "cach_tinh", "trong_so", "n", "n_doc", "n_sach",
        "n_khong_xac_dinh", "n_quyet_dinh", "accuracy", "acc_ci_lo", "acc_ci_hi",
        "recall_doc", "recall_sach", "auc", "auc_ci_lo", "auc_ci_hi", "acc_ho_tham_khao",
        "n_theo_lop", "dung_theo_lop", "kxd_theo_lop", "boot_seed", "boot_n", "ghi_chu"]
MAL, BEN, UNK = 1, 0, None


def nn(x):
    """NaN/rong -> None; con lai giu nguyen (so numpy van la so)."""
    return None if x is None or (isinstance(x, float) and np.isnan(x)) or pd.isna(x) else x


def load(oof_path, l2l3_path):
    o = pd.read_csv(oof_path)
    s = pd.read_csv(l2l3_path, keep_default_na=True)
    if "error" in s:
        bad = s["error"].notna() & (s["error"].astype(str).str.strip() != "")
        if bad.any():
            print("  Canh bao: %d dong l2l3 co loi -> L2/L3 vang mat o cac mau do" % bad.sum())
            s.loc[bad, ["rule_score", "obfuscated_class_ratio"]] = np.nan
    df = o.merge(s[["sha256", "label", "rule_score", "obfuscated_class_ratio",
                    "min_sdk", "target_sdk"]], on="sha256", how="left", suffixes=("", "_l23"))
    lech = df["label_l23"].notna() & (df["label"] != df["label_l23"])
    if lech.any():
        raise SystemExit("DUNG: %d mau co nhan khac nhau giua 2 file" % lech.sum())
    unknown_lab = set(df["label"]) - set(m.CLASSES)
    if unknown_lab:
        raise SystemExit("DUNG: nhan ngoai CLASSES: %s" % sorted(unknown_lab))
    df["y"] = (df["label"] != m.BENIGN).astype(int)
    return df


def layer_inputs(row):
    """Tra dict cac tang dang du lieu cua meta_arbiter (None = vang)."""
    l1 = {"analysis_incomplete": False, "manifest_tampered": 0, "zip_tampered": 0,
          "probabilities": {c: 100.0 * float(row["p_" + c]) for c in m.CLASSES}}
    obf = nn(row["obfuscated_class_ratio"])
    l2 = None if obf is None else {"available": True, "obfuscation_score": obf, "evidence": []}
    return {"L1": l1, "L2": l2, "L3": nn(row["rule_score"]), "L4": None}


def build_layers(inp, use):
    return [m.from_layer1(inp["L1"]) if "L1" in use else m.from_layer1(None),
            m.from_layer4(inp["L4"]) if "L4" in use else m.from_layer4(None),
            m.from_layer2(inp["L2"]) if "L2" in use else m.from_layer2(None),
            m.from_layer3(inp["L3"]) if "L3" in use else m.from_layer3(None)]


def run_vote(df, use, weights):
    """Tra (quyet_dinh 1/0/None, diem p_mal, nhan_ho) cho tung mau."""
    dec, score, fam = [], [], []
    for _, row in df.iterrows():
        r = m.weighted_vote(build_layers(layer_inputs(row), use), weights=weights)
        if r["label"] == m.UNKNOWN or r["p_malicious"] is None:
            dec.append(UNK), score.append(None), fam.append(None)
        else:
            dec.append(MAL if r["label"] != m.BENIGN else BEN)
            score.append(r["p_malicious"])
            fam.append(r["label"] if r["label"] != m.BENIGN else None)
    return dec, score, fam


def run_raw(df, layer):
    """L2 hoac L3 MOT MINH: weighted_vote se tra 100% 'Khong xac dinh' (MIN_VOTERS),
    nen dung diem rui ro tho cua chinh tang do voi CUNG nguong T_MAL."""
    dec, score = [], []
    for _, row in df.iterrows():
        inp = layer_inputs(row)
        r = m.from_layer2(inp["L2"]) if layer == "L2" else m.from_layer3(inp["L3"])
        if not r["available"]:
            dec.append(UNK), score.append(None)
        else:
            dec.append(MAL if r["risk"] >= m.T_MAL else BEN), score.append(r["risk"])
    return dec, score, [None] * len(dec)


def run_era(df, seed):
    """Chan doan: mo hinh CHI dung min_sdk + target_sdk, dung lai cot fold cua oof_layer1
    (StratifiedGroupKFold theo package_name). Tham so co dinh, khong tinh chinh."""
    X = df[["min_sdk", "target_sdk"]].astype(float).values
    yc = df["label"].values
    p_ben = np.full(len(df), np.nan)
    fam = np.array([None] * len(df), dtype=object)
    for f in sorted(df["fold"].unique()):
        te = (df["fold"] == f).values
        clf = RandomForestClassifier(n_estimators=300, min_samples_leaf=2,
                                     random_state=seed, n_jobs=1)
        clf.fit(X[~te], yc[~te])
        pr = clf.predict_proba(X[te])
        cls = list(clf.classes_)
        p_ben[te] = pr[:, cls.index(m.BENIGN)] if m.BENIGN in cls else 0.0
        mal_idx = [i for i, c in enumerate(cls) if c != m.BENIGN]
        fam[te] = [cls[mal_idx[int(np.argmax(p[mal_idx]))]] for p in pr]
    p_mal = 1.0 - p_ben
    dec = [MAL if p >= m.T_MAL else BEN for p in p_mal]
    fam = [fam[i] if dec[i] == MAL else None for i in range(len(dec))]
    return dec, [round(float(p), 4) for p in p_mal], fam


def bootstrap(y, d, s, seed, B):
    """CI 95% percentile cho accuracy (tren mau da quyet dinh) va AUC (tren diem)."""
    rng = np.random.default_rng(seed)
    n = len(y)
    accs, aucs, skip = [], [], 0
    for _ in range(B):
        i = rng.integers(0, n, n)
        accs.append(float(np.mean(y[i] == d[i])))
        if s is not None:
            if len(np.unique(y[i])) < 2:
                skip += 1
                continue
            aucs.append(roc_auc_score(y[i], s[i]))
    ci = lambda a: (round(float(np.percentile(a, 2.5)), 3), round(float(np.percentile(a, 97.5)), 3)) if a else ("", "")
    return ci(accs), ci(aucs), skip


def per_class(df, dec):
    n_c, ok_c, unk_c = [], [], []
    for c in m.CLASSES:
        idx = np.where(df["label"].values == c)[0]
        decided = [i for i in idx if dec[i] is not None]
        truth = BEN if c == m.BENIGN else MAL
        n_c.append("%s=%d" % (c, len(idx)))
        ok_c.append("%s=%d/%d" % (c, sum(dec[i] == truth for i in decided), len(decided)))
        unk_c.append("%s=%d" % (c, len(idx) - len(decided)))
    return "; ".join(n_c), "; ".join(ok_c), "; ".join(unk_c)


def summarize(name, nhom, tang, cach, w, df, dec, score, fam, seed, B, note):
    y_all = df["y"].values
    keep = np.array([d is not None for d in dec])
    y, d = y_all[keep], np.array([x for x in dec if x is not None])
    s = np.array([x for x, k in zip(score, keep) if k], dtype=float) if keep.any() else None
    row = dict.fromkeys(COLS, "")
    row.update(hang=name, nhom=nhom, tang=tang, cach_tinh=cach, trong_so=w,
               n=len(df), n_doc=int(y_all.sum()), n_sach=int((y_all == 0).sum()),
               n_khong_xac_dinh=int((~keep).sum()), n_quyet_dinh=int(keep.sum()),
               boot_seed=seed, boot_n=B, ghi_chu=note)
    if keep.any():
        row["accuracy"] = round(float(np.mean(y == d)), 3)
        row["recall_doc"] = round(float(np.mean(d[y == 1] == 1)), 3) if (y == 1).any() else ""
        row["recall_sach"] = round(float(np.mean(d[y == 0] == 0)), 3) if (y == 0).any() else ""
        if len(np.unique(y)) == 2:
            row["auc"] = round(float(roc_auc_score(y, s)), 3)
        (row["acc_ci_lo"], row["acc_ci_hi"]), (row["auc_ci_lo"], row["auc_ci_hi"]), skip = \
            bootstrap(y, d, s, seed, B)
        if skip:
            row["ghi_chu"] = (note + " | " if note else "") + "AUC: bo %d/%d lan boot thieu 1 lop" % (skip, B)
        # nhan ho: chi tren mau doc that SU da bi bat la doc (tham khao)
        lab = df["label"].values
        hit = [i for i in range(len(dec)) if dec[i] == MAL and y_all[i] == 1 and fam[i] is not None]
        if hit:
            row["acc_ho_tham_khao"] = "%d/%d" % (sum(fam[i] == lab[i] for i in hit), len(hit))
    row["n_theo_lop"], row["dung_theo_lop"], row["kxd_theo_lop"] = per_class(df, dec)
    # tu kiem
    assert row["n"] == len(df) == row["n_doc"] + row["n_sach"]
    assert row["n_quyet_dinh"] + row["n_khong_xac_dinh"] == row["n"]
    assert sum(int(t.split("=")[1]) for t in row["n_theo_lop"].split("; ")) == row["n"]
    ok_sum = sum(int(t.split("=")[1].split("/")[0]) for t in row["dung_theo_lop"].split("; "))
    dec_sum = sum(int(t.split("/")[1]) for t in row["dung_theo_lop"].split("; "))
    assert dec_sum == row["n_quyet_dinh"]
    if keep.any():
        assert abs(ok_sum / dec_sum - row["accuracy"]) < 1e-3
    return row


def wstr(w, use):
    return " ".join("%s=%.2f" % (k, w[k]) for k in ("L1", "L2", "L3", "L4") if k in use)


def _shown_name(path):
    """Ten file hien thi: duong dan tuong doi trong du an (dau /); ngoai du an -> chi ten file."""
    try:
        rel = os.path.relpath(os.path.abspath(path), ROOT)
    except ValueError:  # khac o dia (Windows)
        return os.path.basename(path)
    return os.path.basename(path) if rel.startswith("..") else rel.replace(os.sep, "/")


def era_method(oof_path):
    """Cach tinh hang chan doan thoi dai, ghi TEN FILE OOF THUC TE (--oof), khong viet cung."""
    stem = os.path.splitext(os.path.basename(oof_path))[0]
    return "RandomForest(300 cây, min_samples_leaf=2) 5 lớp, fold của %s (nhóm package_name)" % stem


def build_notes(df, oof_path, l2l3_path, out_path, seed, boot, sens):
    """Noi dung ablation_notes: ten file nguon/dich lay tu tham so thuc te (--oof, --l2l3, --out)."""
    vc = df["label"].value_counts()
    cls_n = ", ".join("%s=%d" % (c, vc.get(c, 0)) for c in m.CLASSES)
    oof_name = os.path.basename(oof_path)
    oof_stem = os.path.splitext(oof_name)[0]
    l23_name = os.path.basename(l2l3_path)
    return f"""Ghi chú cho {_shown_name(out_path)} (sinh bởi scanner/evaluate_ablation.py)

1. ĐÂY LÀ MINH HỌA PHƯƠNG PHÁP, KHÔNG CÓ Ý NGHĨA THỐNG KÊ.
   n={len(df)} ({cls_n}). Điểm L1 là out-of-fold nhưng vẫn chịu nhiễu nguồn/thời đại:
   nhãn lớp trùng với nguồn tải (Adware = tar.gz cũ, Banking/Riskware/SMS = MalwareBazaar mới,
   Benign = F-Droid), nên con số cao có thể phản ánh "nhận ra nguồn" chứ không phải hành vi.
2. Dữ liệu: {oof_name} + {l23_name}, nối theo sha256. NaN -> None = tầng vắng mặt
   (không điền 0). L2 = obfuscated_class_ratio (0-1), L3 = rule_score (0-100, chia 100 trong
   meta_arbiter.from_layer3). L4 vắng (n=0).
3. Quyết định nhị phân: P(độc) = 1 - P(Benign), ngưỡng T_MAL = {m.T_MAL} (cố định, không tinh chỉnh).
   Trọng số = meta_arbiter.WEIGHTS = {m.WEIGHTS} (cố định). Nhãn họ (acc_ho_tham_khao) chỉ tham khảo,
   tính trên mẫu độc thật đã bị bắt là độc.
4. "Không xác định" tính riêng (n_khong_xac_dinh), không gộp vào đúng/sai; accuracy/recall/AUC
   chỉ tính trên n_quyet_dinh.
5. Hàng L2, L3 một mình: weighted_vote cần ít nhất 1 tầng bỏ phiếu (L1/L4, MIN_VOTERS={m.MIN_VOTERS})
   nên sẽ trả 100% "Không xác định"; vì vậy dùng điểm rủi ro thô của chính tầng đó với cùng ngưỡng.
6. L3 đã gồm hạng mục làm rối (obfuscation) nên không độc lập với L2.
7. Bootstrap: seed={seed}, {boot} lần, lấy lại có hoàn lại trên các mẫu đã quyết định,
   khoảng phân vị 2.5-97.5%. Mọi hàng dùng cùng seed.
8. Hàng chẩn đoán thời đại: mô hình CHỈ dùng min_sdk + target_sdk (RandomForest tham số cố định),
   dùng lại cột fold của {oof_stem} (StratifiedGroupKFold theo package_name, seed 42).
   {df['package_name'].nunique(dropna=False)} nhóm / {len(df)} mẫu nên gần như không khác chia ngẫu nhiên
   ({int(df['package_name'].isna().sum())} mẫu thiếu package_name); không có cột họ/chiến dịch.
   Hàng này KHÔNG phải một tầng của meta: đặc trưng của Tầng 5 chỉ là điểm các tầng.
9. Bảng nhạy trọng số (nhom = nhay_trong_so, w_L2=w_L3 = {sens}): CHỈ để xem độ nhạy,
   KHÔNG dùng để chọn trọng số.
10. Khác với eval_ablation.py có sẵn: file đó chỉ ablation NHÓM ĐẶC TRƯNG bên trong L1;
   file này ablation THEO TẦNG ở đầu vào bộ tổng hợp (Tầng 5).
"""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--oof", default=os.path.join(ROOT, "dataset", "processed", "oof_layer1.csv"))
    ap.add_argument("--l2l3", default=os.path.join(ROOT, "dataset", "processed", "l2l3_scores.csv"))
    ap.add_argument("--out", default=os.path.join(ROOT, "reports", "ablation.csv"))
    ap.add_argument("--notes", default=os.path.join(ROOT, "reports", "ablation_notes.txt"))
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--boot", type=int, default=1000)
    ap.add_argument("--sens", default="0.05,0.15,0.30",
                    help="trong so L2/L3 cho bang do nhay (CHI de xem, khong de chon)")
    a = ap.parse_args()
    try:  # console Windows (cp1252) khong in duoc tieng Viet co dau
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

    df = load(a.oof, a.l2l3)
    W = dict(m.WEIGHTS)
    rows = []
    note_l3 = "L3 đã gồm làm rối, không độc lập với L2"
    raw = "điểm thô của tầng >= T_MAL (weighted_vote cần L1/L4 bỏ phiếu)"
    for name, use in [("L1", {"L1"}), ("L2", {"L2"}), ("L3", {"L3"}),
                      ("L1+L2", {"L1", "L2"}), ("L1+L3", {"L1", "L3"}),
                      ("L1+L2+L3", {"L1", "L2", "L3"}),
                      ("Đầy đủ L1+L2+L3+L4", {"L1", "L2", "L3", "L4"})]:
        if use in ({"L2"}, {"L3"}):
            dec, sc, fam = run_raw(df, next(iter(use)))
            cach = raw
        else:
            dec, sc, fam = run_vote(df, use, W)
            cach = "weighted_vote"
        note = note_l3 if "L3" in use else ""
        if "L4" in use:
            note = (note + " | " if note else "") + "L4 vắng (n=0), không điền 0 -> trùng L1+L2+L3"
        rows.append(summarize(name, "ablation_tang", name, cach, wstr(W, use), df, dec, sc, fam,
                              a.seed, a.boot, note))

    dec, sc, fam = run_era(df, a.seed)
    rows.append(summarize(
        "Chẩn đoán thời đại: chỉ min_sdk+target_sdk", "chan_doan", "-",
        era_method(a.oof),
        "-", df, dec, sc, fam, a.seed, a.boot,
        "%d nhóm / %d mẫu nên gần như không khác chia ngẫu nhiên; không có cột họ/chiến dịch; "
        "nhãn lớp trùng nguồn tải (Adware = tar.gz cũ, Banking/Riskware/SMS = MalwareBazaar mới, "
        "Benign = F-Droid)" % (df["package_name"].nunique(dropna=False), len(df))))

    for x in [float(v) for v in a.sens.split(",") if v.strip()]:
        w = dict(W, L2=x, L3=x)
        for name, use in [("L1+L3", {"L1", "L3"}), ("L1+L2+L3", {"L1", "L2", "L3"})]:
            dec, sc, fam = run_vote(df, use, w)
            rows.append(summarize("%s (w_L2=w_L3=%.2f)" % (name, x), "nhay_trong_so", name,
                                  "weighted_vote", wstr(w, use), df, dec, sc, fam, a.seed, a.boot,
                                  "CHỈ để xem độ nhạy, KHÔNG dùng để chọn trọng số"))

    os.makedirs(os.path.dirname(a.out), exist_ok=True)
    with open(a.out, "w", newline="", encoding="utf-8-sig") as f:
        w = csv.DictWriter(f, fieldnames=COLS)
        w.writeheader()
        w.writerows(rows)

    vc = df["label"].value_counts()
    cls_n = ", ".join("%s=%d" % (c, vc.get(c, 0)) for c in m.CLASSES)
    notes = build_notes(df, a.oof, a.l2l3, a.out, a.seed, a.boot, a.sens)
    with open(a.notes, "w", encoding="utf-8") as f:
        f.write(notes)

    show = ["hang", "n", "n_khong_xac_dinh", "accuracy", "acc_ci_lo", "acc_ci_hi", "recall_doc",
            "recall_sach", "auc", "auc_ci_lo", "auc_ci_hi", "acc_ho_tham_khao"]
    pd.set_option("display.width", 250)
    print(pd.DataFrame(rows)[show].to_string(index=False))
    print("\nTong mau: %d (%s) | %d hang | tu kiem n/lop/quyet dinh: OK" % (len(df), cls_n, len(rows)))
    print("Da ghi:", a.out, "|", a.notes)


if __name__ == "__main__":
    main()
