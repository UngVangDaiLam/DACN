r"""Kiem tra scanner/capabilities.py.

Chay:  .\venv\Scripts\python.exe -B tests\test_capabilities.py -v
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from scanner import capabilities as c


def f(rule_id, severity, origin="application", **kw):
    return dict({"rule_id": rule_id, "severity": severity, "origin": origin}, **kw)


class TestAnhXa(unittest.TestCase):
    def test_moi_rule_hien_co_deu_co_capability_hop_le(self):
        for rid, cap in c.RULE_TO_CAPABILITY.items():
            self.assertIn(cap, c.CAPABILITIES, rid)
        for dt, cap in c.DATA_TYPE_TO_CAPABILITY.items():
            self.assertIn(cap, c.CAPABILITIES, dt)

    def test_tang3_nhieu_data_type_tach_thanh_nhieu_capability(self):
        caps = c.capabilities_of(f("sensitive_network_same_method", "medium",
                                   data_types=["SMS", "Vị trí"]))
        self.assertEqual(caps, ["sms_exfiltration_risk", "location_exfiltration_risk"])

    def test_dinh_danh_thiet_bi_va_thue_bao_gop_mot_capability(self):
        caps = c.capabilities_of(f("sensitive_network_same_method", "medium",
                                   data_types=["Định danh thiết bị", "Định danh thuê bao"]))
        self.assertEqual(caps, ["device_id_exfiltration_risk"])

    def test_truong_capability_san_co_duoc_uu_tien(self):
        self.assertEqual(c.capabilities_of(f("dynamic_dex", "medium", capability="reflection_use")),
                         ["reflection_use"])

    def test_rule_la_hoac_capability_la_bi_tu_choi(self):
        with self.assertRaises(ValueError):
            c.capabilities_of(f("rule_moi", "low"))
        with self.assertRaises(ValueError):
            c.capabilities_of(f("dynamic_dex", "low", capability="khong_co"))
        with self.assertRaises(ValueError):
            c.capabilities_of(f("sensitive_network_same_method", "medium", data_types=["NFC"]))


class TestGop(unittest.TestCase):
    def test_cung_capability_o_hai_tang_chi_tinh_mot_lan(self):
        l2 = {"layer": 2, "findings": [f("dynamic_dex", "medium")]}
        l3 = {"layer": 3, "findings": [f("dynamic_dex", "medium", capability="dynamic_code_loading")]}
        m = c.merge_family_b(l2, l3)
        self.assertEqual(list(m), ["dynamic_code_loading"])
        self.assertAlmostEqual(m["dynamic_code_loading"]["weight"], 0.35)  # max, khong cong don
        self.assertEqual(m["dynamic_code_loading"]["count"], 2)
        self.assertEqual(m["dynamic_code_loading"]["layers"], {2, 3})

    def test_nhieu_finding_cung_rule_khong_lam_tang_diem(self):
        l2 = {"findings": [f("reflection", "low") for _ in range(50)]}
        self.assertAlmostEqual(c.merge_family_b(l2)["reflection_use"]["weight"], 0.15)

    def test_third_party_bi_giam_manh_va_application_thang(self):
        l3 = {"findings": [f("sensitive_network_same_method", "low", "third_party", data_types=["SMS"]),
                           f("sensitive_network_same_method", "medium", "application", data_types=["SMS"])]}
        m = c.merge_family_b(None, l3)["sms_exfiltration_risk"]
        self.assertAlmostEqual(m["weight"], 0.35)
        self.assertEqual(m["origin"], "application")
        only_tp = c.merge_family_b({"findings": [l3["findings"][0]]})["sms_exfiltration_risk"]
        self.assertAlmostEqual(only_tp["weight"], 0.15 * 0.15)

    def test_tang_vang_mat_hoac_khong_co_finding(self):
        self.assertEqual(c.merge_family_b(None, None), {})
        self.assertEqual(c.merge_family_b({"findings": []}, {}), {})

    def test_severity_hoac_origin_la_bi_tu_choi(self):
        with self.assertRaises(ValueError):
            c.merge_family_b({"findings": [f("crypto", "high")]})
        with self.assertRaises(ValueError):
            c.merge_family_b({"findings": [f("crypto", "info", "ben_thu_ba")]})

    def test_capability_ho_c_khong_duoc_vao_ho_b(self):
        with self.assertRaises(ValueError):
            c.merge_family_b({"findings": [f("dynamic_dex", "low", capability="overlay")]})


if __name__ == "__main__":
    unittest.main()
