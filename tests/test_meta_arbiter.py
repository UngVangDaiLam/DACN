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


if __name__ == "__main__":
    unittest.main()
