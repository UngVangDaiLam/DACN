r"""evaluate_ablation.py phai ghi TEN FILE THUC TE (--oof, --l2l3, --out) trong ghi chu va
hang chan doan thoi dai, khong viet cung "oof_layer1.csv". Khong doc du lieu that.

Chay:  .\venv\Scripts\python.exe -B tests\test_evaluate_ablation.py -v
"""
import os
import sys
import tempfile
import unittest

import pandas as pd

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from scanner import evaluate_ablation as ea  # noqa: E402

DF = pd.DataFrame({"label": ["Benign", "Adware", "SMS"], "package_name": ["a.b", None, "c.d"]})
TMP = tempfile.gettempdir()  # ngoai thu muc du an


class TestTenFileThucTe(unittest.TestCase):
    def test_ghi_chu_in_ten_file_thuc_te(self):
        n = ea.build_notes(DF, os.path.join(TMP, "oof_thu.csv"), os.path.join(TMP, "l23_thu.csv"),
                           os.path.join(TMP, "kq_thu.csv"), 42, 1000, "0.05")
        self.assertTrue(n.startswith("Ghi chú cho kq_thu.csv (sinh bởi"))
        self.assertIn("2. Dữ liệu: oof_thu.csv + l23_thu.csv, nối theo sha256.", n)
        self.assertIn("dùng lại cột fold của oof_thu (", n)
        for cu in ("oof_layer1", "l2l3_scores", "reports/ablation.csv"):
            self.assertNotIn(cu, n)

    def test_hang_chan_doan_in_ten_file_oof(self):
        s = ea.era_method(os.path.join(TMP, "oof_thu.csv"))
        self.assertIn("fold của oof_thu (nhóm package_name)", s)
        self.assertNotIn("oof_layer1", s)

    def test_duong_dan_mac_dinh_giu_nguyen_chu_cu(self):
        p = lambda *a: os.path.join(ROOT, *a)
        n = ea.build_notes(DF, p("dataset", "processed", "oof_layer1.csv"), p("dataset", "processed", "l2l3_scores.csv"),
                           p("reports", "ablation.csv"), 42, 1000, "0.05,0.15,0.30")
        self.assertTrue(n.startswith("Ghi chú cho reports/ablation.csv (sinh bởi scanner/evaluate_ablation.py)"))
        self.assertIn("2. Dữ liệu: oof_layer1.csv + l2l3_scores.csv, nối theo sha256.", n)
        self.assertIn("dùng lại cột fold của oof_layer1 (StratifiedGroupKFold theo package_name, seed 42).", n)
        self.assertEqual(ea.era_method(p("dataset", "processed", "oof_layer1.csv")),
                         "RandomForest(300 cây, min_samples_leaf=2) 5 lớp, fold của oof_layer1 (nhóm package_name)")


if __name__ == "__main__":
    unittest.main()
