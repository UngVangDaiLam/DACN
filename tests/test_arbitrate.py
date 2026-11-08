r"""Kiem tra meta_arbiter.arbitrate (Pha E) bang mock, KHONG can APK that / model.

Chay:  .\venv\Scripts\python.exe -B tests\test_arbitrate.py -v
"""
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from scanner import meta_arbiter as m

try:  # console Windows (cp1252) khong in duoc tieng Viet co dau
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass


def l1_res(benign_pct, top="Banking"):
    rest = (100.0 - benign_pct) / 4
    p = {c: rest for c in m.CLASSES if c != m.BENIGN}
    p[m.BENIGN] = benign_pct
    return {"success": True, "analysis_incomplete": False, "manifest_tampered": 0,
            "zip_tampered": 0, "probabilities": p, "sha256": "ab" * 32, "package_name": "x.y"}


class FakeDetector:
    def __init__(self, res=None, exc=None):
        self.res, self.exc = res, exc

    def analyze_apk(self, path, name):
        if self.exc:
            raise self.exc
        return self.res


def fake_deep(rule_score=None, ratio=None, exc=None):
    def fn(path):
        if exc:
            raise exc
        d = {"rule_score": rule_score}
        if ratio is not None:
            d["obfuscation"] = {"obfuscated_class_ratio": ratio}
        return d
    return fn


class TestArbitrate(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fd, cls.apk = tempfile.mkstemp(suffix=".apk")  # file gia, mock khong doc noi dung
        os.close(fd)

    @classmethod
    def tearDownClass(cls):
        os.remove(cls.apk)

    def run_(self, res1, deep, **kw):
        return m.arbitrate(self.apk, detector=FakeDetector(res1), deep_fn=deep, **kw)

    def test_chi_L2_doi_trong_so(self):
        self.assertEqual(m.ARBITRATE_WEIGHTS["L2"], 0.0)
        for k in ("L1", "L3", "L4"):
            self.assertEqual(m.ARBITRATE_WEIGHTS[k], m.WEIGHTS[k])

    def test_xung_dot_L1_sach_manh_L3_rat_cao(self):
        """E2: luat mau thuan MOT CHIEU -> 'Khong xac dinh' (truoc E2 la Benign, p_mal 0.069)."""
        r = self.run_(l1_res(98.0), fake_deep(rule_score=100, ratio=0.9))
        print("\n  [xung dot] label=%s risk=%s p_mal=%s conf=%s reason=%r layers=%s"
              % (r["label"], r["risk_level"], r["p_malicious"], r["confidence"],
                 r["reason"], r["layers_present"]))
        self.assertAlmostEqual(r["p_malicious"], 0.069, places=4)  # p_mal khong doi
        self.assertIsNone(r["confidence"])  # buoc 1 sau E2: Khong xac dinh -> confidence None
        self.assertEqual(r["label"], m.UNKNOWN)
        self.assertEqual(r["risk_level"], m.UNKNOWN)
        self.assertIn("L1 sạch nhưng L3 rất cao", r["reason"])
        self.assertIn("Tang 3: rule_score=100/100", r["evidence"])

    def test_E2_bien_dung_T_HIGH(self):
        # dung nguong co san T_HIGH (0.8 -> rule_score 80), khong nguong moi
        at = self.run_(l1_res(98.0), fake_deep(rule_score=m.T_HIGH * 100))
        below = self.run_(l1_res(98.0), fake_deep(rule_score=m.T_HIGH * 100 - 1))
        self.assertEqual(at["label"], m.UNKNOWN)
        self.assertEqual(below["label"], m.BENIGN)

    def test_E2_khong_lam_chieu_nguoc_L1_doc_L3_thap(self):
        r = self.run_(l1_res(5.0), fake_deep(rule_score=2, ratio=0.1))
        self.assertNotEqual(r["label"], m.UNKNOWN)
        self.assertNotEqual(r["label"], m.BENIGN)
        self.assertEqual(r["reason"], "")

    def test_E2_L3_vang_khong_anh_huong(self):
        r = self.run_(l1_res(98.0), fake_deep(rule_score=None, ratio=0.9))
        self.assertEqual(r["label"], m.BENIGN)
        self.assertEqual(r["reason"], "")

    def test_khong_xac_dinh_luon_confidence_None_giu_p_mal(self):
        # (a) ca lam meo manifest + du doan sach
        t = dict(l1_res(98.0), manifest_tampered=1)
        r = m.weighted_vote([m.from_layer1(t), m.from_layer4(None),
                             m.from_layer2(None), m.from_layer3(None)])
        self.assertEqual(r["label"], m.UNKNOWN)
        self.assertIsNone(r["confidence"])
        self.assertAlmostEqual(r["p_malicious"], 0.02)
        # (b) mau thuan L1-L4: tra som, p_malicious chua tinh (None) nhu truoc
        l4_doc = {"Benign": 0.02, "Adware": 0.02, "Banking": 0.9, "SMS": 0.03, "Riskware": 0.03}
        r = m.weighted_vote([m.from_layer1(l1_res(98.0)), m.from_layer4(l4_doc),
                             m.from_layer2(None), m.from_layer3(None)])
        self.assertEqual(r["label"], m.UNKNOWN)
        self.assertIn("mau thuan", r["reason"])
        self.assertIsNone(r["confidence"])
        self.assertIsNone(r["p_malicious"])
        # (c) thieu tang bo phieu
        r = m.weighted_vote([m.from_layer1(None), m.from_layer4(None),
                             m.from_layer2(None), m.from_layer3(50)])
        self.assertIsNone(r["confidence"])
        # (d) ket luan co dinh van co confidence
        r = self.run_(l1_res(98.0), fake_deep(rule_score=10))
        self.assertEqual(r["label"], m.BENIGN)
        self.assertIsNotNone(r["confidence"])

    def test_E2_chi_ap_dung_khi_co_L1(self):
        # chi L4 bo phieu (L1 vang) + L3 cao -> luat khong kich hoat
        l4 = {"Benign": 0.98, "Adware": 0.005, "Banking": 0.005, "SMS": 0.005, "Riskware": 0.005}
        r = m.weighted_vote([m.from_layer1(None), m.from_layer4(l4),
                             m.from_layer2(None), m.from_layer3(100)])
        self.assertEqual(r["label"], m.BENIGN)

    def test_L2_trong_so_0_khong_doi_p_mal_nhung_co_trong_evidence(self):
        a = self.run_(l1_res(40.0), fake_deep(rule_score=30, ratio=0.0))
        b = self.run_(l1_res(40.0), fake_deep(rule_score=30, ratio=1.0))
        self.assertEqual(a["p_malicious"], b["p_malicious"])
        self.assertIn("L2", b["layers_present"])
        self.assertTrue(any("gan dung" in e for e in b["evidence_by_layer"]["L2"]))

    def test_L3_vang_L2_trong_so_0_khong_chia_cho_0(self):
        r = self.run_(l1_res(40.0), fake_deep(rule_score=None, ratio=0.7))
        self.assertAlmostEqual(r["p_malicious"], 0.6)  # chi L1
        self.assertNotIn("L3", r["layers_present"])
        self.assertIn("L2", r["layers_present"])

    def test_analyze_deep_loi_thi_L2_L3_vang_khong_dien_0(self):
        r = self.run_(l1_res(40.0), fake_deep(exc=RuntimeError("hong zip")))
        self.assertAlmostEqual(r["p_malicious"], 0.6)
        self.assertEqual(r["layers_present"], ["L1"])
        self.assertTrue(any("analyze_deep" in e for e in r["layer_errors"]))

    def test_L1_khong_day_du_thi_khong_xac_dinh_du_L3_cao(self):
        res = {"success": True, "analysis_incomplete": True, "probabilities": {},
               "incomplete_reasons": ["tong opcode = 0"]}
        r = self.run_(res, fake_deep(rule_score=95, ratio=0.5))
        self.assertEqual(r["label"], m.UNKNOWN)
        self.assertIsNone(r["p_malicious"])
        self.assertIn("L3", r["layers_present"])

    def test_L1_that_bai_hoac_ngoai_le(self):
        r = self.run_({"success": False, "error": "Loi phan tich"}, fake_deep(rule_score=10))
        self.assertEqual(r["label"], m.UNKNOWN)
        self.assertTrue(any(e.startswith("L1:") for e in r["layer_errors"]))
        r = m.arbitrate(self.apk, detector=FakeDetector(exc=OSError("x")), deep_fn=fake_deep(10))
        self.assertEqual(r["label"], m.UNKNOWN)

    def test_diem_ngoai_thang_ghi_loi_va_vang(self):
        r = self.run_(l1_res(40.0), fake_deep(rule_score=150, ratio=1.5))
        self.assertNotIn("L3", r["layers_present"])
        self.assertNotIn("L2", r["layers_present"])
        self.assertEqual(len(r["layer_errors"]), 2)

    def test_dau_ra_du_truong(self):
        r = self.run_(l1_res(10.0), fake_deep(rule_score=60, ratio=0.2))
        for k in ("label", "risk_level", "confidence", "p_malicious", "evidence",
                  "evidence_by_layer", "layers_present", "layer_errors", "weights_used",
                  "era_biased", "sha256", "package_name"):
            self.assertIn(k, r)
        self.assertEqual(set(r["evidence_by_layer"]), {"L1", "L2", "L3", "L4"})
        self.assertNotIn("L4", r["layers_present"])

    def test_from_results_trung_arbitrate(self):
        # Pha G: web dung arbitrate_from_results voi ket qua da co -> phai giong arbitrate()
        cases = [(l1_res(98.0), dict(rule_score=100, ratio=0.9)), (l1_res(5.0), dict(rule_score=2)),
                 (l1_res(40.0), dict(rule_score=150, ratio=1.5)), (l1_res(60.0), dict()),
                 ({"success": False, "error": "x"}, dict(rule_score=10))]
        for res1, kw in cases:
            a = self.run_(res1, fake_deep(**kw))
            b = m.arbitrate_from_results(res1, fake_deep(**kw)(self.apk))
            self.assertEqual(a, b, msg=repr((res1, kw)))
        e = RuntimeError("hong zip")
        a = self.run_(l1_res(40.0), fake_deep(exc=e))
        b = m.arbitrate_from_results(l1_res(40.0), None,
                                     deep_errors=["L2/L3 (analyze_deep): RuntimeError: hong zip"])
        self.assertEqual(a, b)

    def test_from_results_bo_qua_verdict_cua_web(self):
        # key 'verdict' (combine_verdict) / 'deep' do web gan them KHONG duoc anh huong Tang 5
        res1 = dict(l1_res(98.0), verdict={"final_score": 99, "level": "danger"}, deep={"x": 1})
        a = m.arbitrate_from_results(res1, {"rule_score": 10})
        b = m.arbitrate_from_results(l1_res(98.0), {"rule_score": 10})
        self.assertEqual(a, b)

    def test_file_khong_ton_tai(self):
        with self.assertRaises(FileNotFoundError):
            m.arbitrate(self.apk + ".khong_co", detector=FakeDetector(l1_res(50)),
                        deep_fn=fake_deep(10))

    def test_mac_dinh_weighted_vote_cu_khong_doi(self):
        # WEIGHTS mac dinh (L2=0.05) van dung nhu truoc cho evaluate_ablation / smoke
        self.assertEqual(m.WEIGHTS["L2"], 0.05)


if __name__ == "__main__":
    unittest.main()
