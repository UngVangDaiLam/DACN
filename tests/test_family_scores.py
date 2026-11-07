r"""Kiem tra scanner/family_scores.py (ho B).

Chay:  .\venv\Scripts\python.exe -B tests\test_family_scores.py -v
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from scanner import family_scores as fs


def f(rule_id, severity, origin="application", **kw):
    return dict({"rule_id": rule_id, "severity": severity, "origin": origin}, **kw)


def layer(n, *findings, **kw):
    return dict({"layer": n, "findings": list(findings)}, **kw)


class TestNoisyOr(unittest.TestCase):
    def test_gia_tri_co_ban(self):
        self.assertAlmostEqual(fs.noisy_or([]), 0.0)
        self.assertAlmostEqual(fs.noisy_or([0.35, 0.35]), 1 - 0.65 * 0.65)

    def test_tran_va_trong_so_sai(self):
        self.assertAlmostEqual(fs.noisy_or([0.9, 0.9, 0.9], cap=0.5), 0.5)
        with self.assertRaises(ValueError):
            fs.noisy_or([1.2])


class TestHoB(unittest.TestCase):
    def test_hai_tang_vang_mat_khong_phai_sach(self):
        r = fs.score_family_b(None, None)
        self.assertFalse(r["available"])
        self.assertIsNone(r["score"])

    def test_tang_co_mat_nhung_khong_finding_la_diem_0(self):
        r = fs.score_family_b(layer(2), layer(3))
        self.assertTrue(r["available"])
        self.assertEqual(r["score"], 0.0)

    def test_chi_mot_tang_co_mat_van_tinh_diem(self):
        r = fs.score_family_b(layer(2, f("dynamic_dex", "medium")), None)
        self.assertTrue(r["available"])
        self.assertAlmostEqual(r["score"], 0.35)

    def test_hai_capability_khac_nhau_cong_theo_noisy_or(self):
        l2 = layer(2, f("dynamic_dex", "medium"))
        l3 = layer(3, f("sensitive_network_same_method", "medium", data_types=["SMS"]))
        self.assertAlmostEqual(fs.score_family_b(l2, l3)["score"], round(1 - 0.65 * 0.65, 4))

    def test_cung_capability_hai_tang_khong_dem_hai_lan(self):
        l2 = layer(2, f("dynamic_dex", "medium"))
        l3 = layer(3, f("dynamic_dex", "medium", capability="dynamic_code_loading"))
        self.assertAlmostEqual(fs.score_family_b(l2, l3)["score"], 0.35)

    def test_chi_tin_hieu_yeu_third_party_diem_rat_thap(self):
        l3 = layer(3, f("sensitive_network_same_method", "low", "third_party", data_types=["SMS"]))
        self.assertLess(fs.score_family_b(None, l3)["score"], 0.05)

    def test_diem_khong_vuot_tran(self):
        caps = [f("sensitive_network_same_method", "medium", data_types=[
            "SMS", "Vị trí", "Camera", "Clipboard", "Số điện thoại", "Định danh thiết bị"]),
            f("dynamic_dex", "medium")]
        r = fs.score_family_b(layer(2, *caps), None, cap=0.6)
        self.assertLessEqual(r["score"], 0.6)

    def test_ghi_chu_khi_partial_hoac_truncated(self):
        r = fs.score_family_b(layer(2, status="partial", truncated=True), None)
        self.assertEqual(len(r["notes"]), 2)

    def test_bang_chung_sap_xep_theo_trong_so_giam_dan(self):
        l2 = layer(2, f("crypto", "info"), f("dynamic_dex", "medium"), f("reflection", "low"))
        ev = fs.score_family_b(l2, None)["evidence"]
        self.assertEqual([e["capability"] for e in ev],
                         ["dynamic_code_loading", "reflection_use", "crypto_use"])


if __name__ == "__main__":
    unittest.main()
