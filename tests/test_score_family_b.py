r"""Kiem tra scanner/score_family_b.py bang APK gia + analyze_deep gia (khong can androguard).

Chay:  .\venv\Scripts\python.exe -B tests\test_score_family_b.py -v
"""
import argparse
import hashlib
import json
import os
import sys
import tempfile
import unittest

import pandas as pd

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from scanner import score_family_b as m


def f(rule_id, severity, origin="application", **kw):
    return dict({"rule_id": rule_id, "severity": severity, "origin": origin}, **kw)


FAKE = {  # noi dung file -> output kieu An
    b"sach": {"layer2": {"status": "completed", "findings": [f("crypto", "info")]},
              "layer3": {"status": "completed", "findings": []}},
    b"doc": {"layer2": {"status": "completed", "findings": [f("dynamic_dex", "medium")]},
             "layer3": {"status": "completed", "findings": [
                 f("sensitive_network_same_method", "medium", data_types=["SMS"])]}},
    b"hong": None,
}


class Env:
    def __init__(self):
        self.tmp = tempfile.TemporaryDirectory()
        d = self.tmp.name
        os.makedirs(os.path.join(d, "apk"))
        rows = []
        for name, label in ((b"sach", "Benign"), (b"doc", "Banking"), (b"hong", "SMS")):
            with open(os.path.join(d, "apk", name.decode() + ".apk"), "wb") as fh:
                fh.write(name)
            rows.append({"sha256": hashlib.sha256(name).hexdigest(),
                         "package_name": "pkg." + name.decode(), "label": label})
        pd.DataFrame(rows).to_csv(os.path.join(d, "oof.csv"), index=False)
        self.calls = []

    def args(self, limit=0):
        d = self.tmp.name
        return argparse.Namespace(apk_dir=os.path.join(d, "apk"), oof=os.path.join(d, "oof.csv"),
                                  cache=os.path.join(d, "cache"), out=os.path.join(d, "out", "s.csv"),
                                  limit=limit)

    def analyze(self, path):
        self.calls.append(path)
        with open(path, "rb") as fh:
            key = fh.read()
        if FAKE[key] is None:
            raise ValueError("APK hong")
        return FAKE[key]


class TestScoreFamilyB(unittest.TestCase):
    def setUp(self):
        self.env = Env()
        self._stdout = sys.stdout
        sys.stdout = open(os.devnull, "w")

    def tearDown(self):
        sys.stdout.close()
        sys.stdout = self._stdout
        self.env.tmp.cleanup()

    def test_diem_dung_va_loi_duoc_ghi_lai(self):
        df = m.run(self.env.args(), analyze=self.env.analyze).set_index("label")
        self.assertAlmostEqual(float(df.loc["Benign", "score_b"]), 0.05)
        self.assertAlmostEqual(float(df.loc["Banking", "score_b"]), round(1 - 0.65 * 0.65, 4))
        self.assertIn("APK hong", df.loc["SMS", "error"])
        self.assertEqual(json.loads(df.loc["Benign", "capabilities"]), ["crypto_use"])

    def test_chay_lai_dung_cache_khong_phan_tich_lai(self):
        m.run(self.env.args(), analyze=self.env.analyze)
        n = len(self.env.calls)
        m.run(self.env.args(), analyze=self.env.analyze)
        self.assertEqual(len(self.env.calls), n + 1)  # chi mau loi duoc thu lai

    def test_cache_gan_truong_layer(self):
        m.run(self.env.args(), analyze=self.env.analyze)
        sha = hashlib.sha256(b"doc").hexdigest()
        with open(os.path.join(self.env.tmp.name, "cache", sha + ".json"), encoding="utf-8") as fh:
            data = json.load(fh)
        self.assertEqual((data["layer2"]["layer"], data["layer3"]["layer"]), (2, 3))

    def test_limit_chi_gioi_han_mau_moi(self):
        df = m.run(self.env.args(limit=1), analyze=self.env.analyze)
        self.assertEqual(len(df), 1)

    def test_thieu_apk_khong_lam_hong_chay(self):
        os.remove(os.path.join(self.env.tmp.name, "apk", "doc.apk"))
        df = m.run(self.env.args(), analyze=self.env.analyze)
        self.assertEqual(len(df), 2)


if __name__ == "__main__":
    unittest.main()
