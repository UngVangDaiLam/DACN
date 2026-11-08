r"""Kiem tra thang do cua Tang 5 (meta_arbiter).

Chay:  .\venv\Scripts\python.exe -B tests\test_meta_arbiter.py -v
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from scanner import meta_arbiter as m

# Tang 1 noi 92% la sach (dung dinh dang MalwareDetector: don vi %, khoa theo ten lop)
L1_SACH = {"analysis_incomplete": False, "manifest_tampered": 0, "zip_tampered": 0,
           "probabilities": {"Adware": 2.0, "Banking": 2.0, "Benign": 92.0,
                             "Riskware": 2.0, "SMS": 2.0}}


def vote(rule_score):
    return m.weighted_vote([m.from_layer1(L1_SACH), m.from_layer4(None),
                            m.from_layer2(None), m.from_layer3(rule_score)])


class TestThangDo(unittest.TestCase):
    def test_p_mal_luon_trong_khoang_0_1(self):
        for rs in (0, 20, 45, 100):
            p = vote(rs)["p_malicious"]
            self.assertTrue(0.0 <= p <= 1.0, "rule_score=%s -> p_mal=%s" % (rs, p))

    def test_rule_score_trung_binh_khong_lat_ket_luan_cua_L1(self):
        # L2/L3 chi 'nhich nhe' p_mal (trong so 0.05), khong duoc tu quyet dinh nhan
        self.assertEqual(vote(45)["label"], m.BENIGN)

    def test_rule_score_ngoai_thang_bi_tu_choi(self):
        with self.assertRaises(ValueError):
            m.from_layer3(150)

    def test_diem_L2_ngoai_thang_bi_tu_choi(self):
        with self.assertRaises(ValueError):
            m.from_layer2({"available": True, "obfuscation_score": 1.5, "evidence": []})


def l2(score):
    return m.from_layer2({"available": True, "obfuscation_score": score, "evidence": []})


class TestPhaB(unittest.TestCase):
    def test_L3_36_thanh_0_36(self):
        self.assertAlmostEqual(m.from_layer3(36)["risk"], 0.36)

    def test_L3_0_36_giu_nguyen_thang_0_100(self):
        # Co y: khong doan thang. 0.36 duoc hieu la 0.36/100.
        self.assertAlmostEqual(m.from_layer3(0.36)["risk"], 0.0036)

    def test_L3_bien_0_va_100_hop_le(self):
        self.assertEqual(m.from_layer3(0)["risk"], 0.0)
        self.assertEqual(m.from_layer3(100)["risk"], 1.0)

    def test_L3_ngoai_0_100_bi_tu_choi(self):
        for v in (120, 100.01, -1):
            with self.assertRaises(ValueError, msg=repr(v)):
                m.from_layer3(v)

    def test_L3_khong_phai_so_bi_tu_choi(self):
        for v in ("36", "abc", True, float("nan"), [36]):
            with self.assertRaises(ValueError, msg=repr(v)):
                m.from_layer3(v)

    def test_L2_ngoai_0_1_hoac_khong_phai_so_bi_tu_choi(self):
        for v in (-0.01, 1.01, "0.5", True, float("nan")):
            with self.assertRaises(ValueError, msg=repr(v)):
                l2(v)
        self.assertEqual(l2(0)["risk"], 0.0)
        self.assertEqual(l2(1)["risk"], 1.0)

    def test_None_la_lop_vang_mat_khong_dien_0(self):
        for r in (m.from_layer3(None), m.from_layer2(None),
                  m.from_layer2({"available": True, "obfuscation_score": None})):
            self.assertFalse(r["available"])
            self.assertIsNone(r["risk"])
        vang = vote(None)
        self.assertNotIn("L3", vang["layers_present"])
        # Vang mat => p_mal chi tu L1 (0.08); neu dien 0 thi se thanh 0.95*0.08 = 0.076
        self.assertAlmostEqual(vang["p_malicious"], 0.08)
        self.assertNotAlmostEqual(vang["p_malicious"], vote(0)["p_malicious"])

    def test_smoke_cu_van_in_Banking_0_9(self):
        import subprocess
        out = subprocess.run([sys.executable, "-B", m.__file__], capture_output=True,
                             text=True, check=True).stdout.strip()
        self.assertEqual(out, "Banking 0.9")


if __name__ == "__main__":
    unittest.main()
