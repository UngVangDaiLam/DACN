r"""Kiem tra hieu chinh nguong va so sanh cach ket hop (fusion_common, calibrate_arbiter, eval_fusion)
bang bang diem GIA LAP nho. Khong can APK, khong can du lieu that.

Chay:  .\venv\Scripts\python.exe -B tests\test_fusion.py -v
"""
import argparse
import contextlib
import hashlib
import io
import json
import os
import sys
import tempfile
import unittest

import numpy as np
import pandas as pd

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from scanner import calibrate_arbiter, eval_fusion  # noqa: E402
from scanner import fusion_common as fc  # noqa: E402


def make_data(d, n_benign=80, n_mal=12, seed=0):
    rng = np.random.RandomState(seed)
    oof, fb, dates = [], [], []
    spec = [("Benign", n_benign, (2, 7), (1.5, 7))] + [
        (c, n_mal, (7, 2), (5, 3)) for c in ("Banking", "SMS", "Adware")]
    for label, n, pa, pb in spec:
        for i in range(n):
            sha = hashlib.sha256(("%s%d" % (label, i)).encode()).hexdigest()
            a, b = float(rng.beta(*pa)), round(float(min(0.95, rng.beta(*pb))), 4)
            row = {"sha256": sha, "package_name": "pkg.%s.%d" % (label, i // 2), "label": label,
                   "fold": 0, "p_Benign": 1 - a}
            row.update({"p_" + c: a / 4 for c in ("Adware", "Banking", "Riskware", "SMS")})
            oof.append(row)
            partial = i % 7 == 0
            fb.append({"sha256": sha, "label": label, "available": True,
                       "score_b": None if partial else b, "observed_score_b": b,
                       "error": "ValueError: hong" if i % 29 == 5 else "", "seconds": 3.0})
            if label != "Benign":
                dates.append({"sha256": sha, "ngay": "2024-%02d-01" % (1 + i % 12)})
    paths = {k: os.path.join(d, k + ".csv") for k in ("oof", "fb", "dates")}
    pd.DataFrame(oof).to_csv(paths["oof"], index=False)
    pd.DataFrame(fb).to_csv(paths["fb"], index=False)
    pd.DataFrame(dates).to_csv(paths["dates"], index=False)
    return paths


def quiet(fn, *args):
    with contextlib.redirect_stdout(io.StringIO()):
        return fn(*args)


class ThresholdTests(unittest.TestCase):
    def test_nguong_giu_bao_dong_gia_duoi_muc_tieu(self):
        s = np.linspace(0.0, 0.99, 100)
        for alpha in (0.10, 0.05, 0.01):
            t = fc.threshold_at_fpr(s, alpha)
            self.assertLessEqual(np.mean(s >= t), alpha)
            self.assertGreater(np.mean(s >= t - 0.011), alpha)   # nho hon mot nac la vuot muc tieu

    def test_it_mau_thi_nguong_nam_tren_diem_sach_cao_nhat(self):
        t = fc.threshold_at_fpr([0.1, 0.2, 0.3], 0.01)
        self.assertGreater(t, 0.3)
        self.assertEqual(np.mean(np.array([0.1, 0.2, 0.3]) >= t), 0.0)

    def test_diem_0_khong_bao_gio_vuot_nguong(self):
        self.assertEqual(fc.threshold_at_fpr([0.0] * 50, 0.05), fc.MIN_THRESHOLD)
        self.assertIsNone(fc.threshold_at_fpr([], 0.05))


class TableTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.p = make_data(self.tmp.name)
        self.t = fc.load_table(self.p["oof"], self.p["fb"], None, self.p["dates"])

    def tearDown(self):
        self.tmp.cleanup()

    def test_bang_diem_khong_dien_0_cho_ho_vang_mat(self):
        t = self.t
        self.assertEqual(len(t), 80 + 36)
        self.assertTrue(t["c"].isna().all())
        self.assertTrue(t["b"].isna().any())               # mau loi -> vang mat, khong phai 0
        self.assertTrue(t["b_partial"].any())
        self.assertTrue(t.loc[t.b_partial, "b"].notna().all())  # bi cat -> dung can duoi
        self.assertEqual(int(t["y"].sum()), 36)
        self.assertTrue(t.loc[t.y == 1, "date"].notna().all())

    def test_muc_theo_luat_xac_nhan_cheo(self):
        t = pd.DataFrame({"a": [0.9, 0.9, 0.65, 0.1, 0.1, 0.1, np.nan],
                          "b": [0.8, 0.1, 0.1, 0.1, np.nan, 0.1, 0.9],
                          "c": [np.nan] * 7,
                          "b_partial": [False, False, False, False, False, True, False]})
        th = {"A": (0.6, 0.85), "B": (0.5, 0.75), "C": (0.5, 0.75)}
        self.assertEqual(list(fc.levels(t, th)),
                         ["danger", "warning", "caution", "safe", "unknown", "unknown", "warning"])
        # ablation: bo ho B -> khong the dat Nguy hiem
        self.assertEqual(fc.levels(t, th, ("a",))[0], "warning")

    def test_diem_cong_va_bo_phieu_bo_qua_ho_vang_mat(self):
        t = pd.DataFrame({"a": [0.8, 0.8], "b": [0.2, np.nan], "c": [np.nan, np.nan]})
        v = fc.weighted_vote_score(t)
        self.assertAlmostEqual(v[0], (0.45 * 0.8 + 0.10 * 0.2) / 0.55)
        self.assertAlmostEqual(v[1], 0.8)
        s = fc.capped_sum_score(t)
        self.assertAlmostEqual(s[0], (0.5 + 0.2) / 1.0)
        self.assertAlmostEqual(s[1], 1.0)

    def test_hieu_chinh_ghi_file_va_trong_tai_doc_duoc(self):
        out = os.path.join(self.tmp.name, "th.json")
        a = argparse.Namespace(oof=self.p["oof"], family_b=self.p["fb"], family_c=None, out=out,
                               fpr_weak=0.05, fpr_strong=0.01, min_benign=20, boot=30, seed=1,
                               benign_source="gia lap", write=True)
        data = quiet(calibrate_arbiter.run, a)
        self.assertEqual(sorted(data["thresholds"]), ["A", "B"])     # ho C khong co diem -> khong ghi
        from scanner import family_arbiter as fa
        th, calibrated, meta = fa.load_thresholds(out)
        self.assertTrue(calibrated)
        self.assertEqual(th["C"], fa.DEFAULT_THRESHOLDS["C"])
        ben = self.t[self.t.y == 0]
        for k in ("a", "b"):
            weak, strong = th[k.upper()]
            self.assertLessEqual(weak, strong)
            self.assertLessEqual((ben[k].dropna() >= weak).mean(), 0.05)
        with open(out, encoding="utf-8") as f:
            self.assertEqual(json.load(f)["meta"]["benign_source"], "gia lap")


class EvalTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.p = make_data(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def args(self, **kw):
        base = dict(oof=self.p["oof"], family_b=self.p["fb"], family_c=None, dates=self.p["dates"],
                    out_dir=os.path.join(self.tmp.name, "rep"), split="cv", cutoff="", folds=4,
                    repeats=2, fpr_weak=0.05, fpr_strong=0.01, min_benign=20, seed=3, permute=False)
        base.update(kw)
        return argparse.Namespace(**base)

    def test_cv_co_du_cac_cach_ket_hop_va_quan_he_logic(self):
        summary, extra = quiet(eval_fusion.run, self.args())
        m = summary.set_index("method")
        for name in (eval_fusion.M_A, eval_fusion.M_B, eval_fusion.M_OR, eval_fusion.M_AND,
                     eval_fusion.M_MAJ, eval_fusion.M_SUM, eval_fusion.M_VOTE, eval_fusion.M_X_D,
                     eval_fusion.M_X_W, eval_fusion.M_X_C, eval_fusion.M_LR, eval_fusion.M_GBM):
            self.assertIn(name, m.index)
        # HOAC bat it nhat bang tung ho; Nguy hiem (>= 2 ho) khong bao nhieu hon HOAC
        self.assertGreaterEqual(m.loc[eval_fusion.M_OR, "recall"], m.loc[eval_fusion.M_A, "recall"])
        self.assertLessEqual(m.loc[eval_fusion.M_X_D, "fpr"], m.loc[eval_fusion.M_OR, "fpr"])
        self.assertLessEqual(m.loc[eval_fusion.M_X_D, "fpr"], m.loc[eval_fusion.M_X_W, "fpr"])
        self.assertGreater(m.loc[eval_fusion.M_A, "auc"], 0.8)        # du lieu gia lap tach duoc
        ec = extra["error_correlation"]
        self.assertEqual(sum(ec["doc"][k] for k in ("ca_hai_bao", "chi_A_bao", "chi_B_bao",
                                                    "khong_ho_nao_bao")), ec["doc"]["n"])
        self.assertEqual(int(extra["levels_by_label"].to_numpy().sum()), 116)
        for f in ("fusion_metrics_cv.csv", "fusion_report_cv.md", "error_correlation.json"):
            self.assertTrue(os.path.exists(os.path.join(self.tmp.name, "rep", f)))

    def test_xao_tron_nhan_thi_mo_hinh_hoc_ve_ngau_nhien(self):
        summary, _ = quiet(eval_fusion.run, self.args(permute=True, repeats=3))
        m = summary.set_index("method")
        self.assertLess(abs(m.loc[eval_fusion.M_LR, "auc"] - 0.5), 0.15)

    def test_giu_rieng_lop_va_chia_theo_thoi_gian(self):
        summary, extra = quiet(eval_fusion.run, self.args(split="family"))
        self.assertEqual(sorted(extra["per_class"]["lop_giu_rieng"].unique()),
                         ["Adware", "Banking", "SMS"])
        summary, _ = quiet(eval_fusion.run, self.args(split="time"))
        self.assertIn(eval_fusion.M_X_W, set(summary["method"]))

    def test_thieu_ngay_thi_dung_lai_co_huong_dan(self):
        with self.assertRaises(SystemExit) as cm:
            quiet(eval_fusion.run, self.args(split="time", dates=os.path.join(self.tmp.name, "khong.csv")))
        self.assertIn("ngay", str(cm.exception))


if __name__ == "__main__":
    unittest.main()
