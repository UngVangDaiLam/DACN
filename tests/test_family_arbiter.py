r"""Kiem tra bo trong tai theo ho bang chung (scanner/family_arbiter.py).

Chay:  .\venv\Scripts\python.exe -B tests\test_family_arbiter.py -v
"""
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from scanner import family_arbiter as fa  # noqa: E402


def l1(p_benign, **kw):
    rest = round((100 - p_benign) / 4, 2)
    return {"success": True, "probabilities": {"Benign": p_benign, "Adware": rest, "Banking": rest,
                                               "Riskware": rest, "SMS": rest}, **kw}


def fb(score, observed=None, **kw):
    return {"family": "code_behavior", "available": True,
            "status": "completed" if score is not None else "partial",
            "score": score, "observed_score": score if observed is None else observed,
            "evidence": [{"capability": "dynamic_code_loading", "weight": 0.35}], "notes": [], **kw}


_arbitrate = fa.arbitrate


def arbitrate(*args, **kw):
    """Test luon dung nguong de xuat, khong phu thuoc models/arbiter_thresholds.json tren may."""
    kw.setdefault("thresholds", fa.DEFAULT_THRESHOLDS)
    return _arbitrate(*args, **kw)


class FamilyArbiterTests(unittest.TestCase):
    def test_hai_ho_vuot_nguong_la_nguy_hiem(self):
        r = arbitrate(l1(10), fb(0.64))
        self.assertEqual(r["level"], "danger")
        self.assertEqual(r["families_over"], ["A", "B"])
        self.assertEqual(r["capabilities"], ["dynamic_code_loading"])

    def test_mot_ho_manh_la_dang_ngo_mot_ho_yeu_la_can_luu_y(self):
        self.assertEqual(arbitrate(l1(5), fb(0.1))["level"], "warning")
        self.assertEqual(arbitrate(l1(38), fb(0.1))["level"], "caution")
        self.assertEqual(arbitrate(l1(95), fb(0.8))["level"], "warning")
        self.assertEqual(arbitrate(l1(95), fb(0.55))["level"], "caution")

    def test_mot_ho_du_manh_den_dau_cung_khong_thanh_nguy_hiem(self):
        self.assertEqual(arbitrate(l1(0), fb(0.0))["level"], "warning")

    def test_sach_khi_a_b_day_du_va_duoi_nguong(self):
        r = arbitrate(l1(90), fb(0.2))
        self.assertEqual(r["level"], "safe")
        self.assertEqual(r["families_absent"], ["C"])
        self.assertFalse(r["thresholds_calibrated"])

    def test_ho_vang_mat_khong_tinh_la_sach(self):
        self.assertEqual(arbitrate(None, fb(0.2))["level"], "unknown")
        self.assertEqual(arbitrate(l1(90), None)["level"], "unknown")
        self.assertEqual(arbitrate(l1(90, analysis_incomplete=True), fb(0.2))["level"], "unknown")
        self.assertEqual(arbitrate(None, None)["level"], "unknown")
        self.assertEqual(arbitrate(l1(90), {"available": False, "score": None})["level"], "unknown")

    def test_ho_b_bi_cat_dung_can_duoi_va_khong_ra_an_toan(self):
        r = arbitrate(l1(90), fb(None, observed=0.42))
        b = r["families"][1]
        self.assertTrue(b["partial"])
        self.assertEqual(b["score"], 0.42)
        self.assertEqual(r["level"], "unknown")
        # can duoi da vuot nguong thi van duoc tinh la vuot
        self.assertEqual(arbitrate(l1(10), fb(None, observed=0.6))["level"], "danger")

    def test_apk_lam_meo_khong_duoc_an_toan(self):
        r = arbitrate(l1(90, manifest_tampered=1), fb(0.1))
        self.assertEqual(r["level"], "caution")

    def test_ho_c_tham_gia_xac_nhan_cheo(self):
        r = arbitrate(l1(90), fb(0.6), {"score": 0.7, "evidence": [{"capability": "overlay"}]})
        self.assertEqual(r["level"], "danger")
        self.assertEqual(r["families_over"], ["B", "C"])
        self.assertFalse(r["recommend_dynamic"])

    def test_xac_suat_thang_0_1_va_bien_nguong(self):
        a = fa.family_a_from_layer1({"probabilities": {"Benign": 0.4, "SMS": 0.6}})
        self.assertEqual(a["score"], 0.6)
        self.assertEqual(a["strength"], "weak")
        self.assertEqual(fa.family_b_from_report(fb(0.75))["strength"], "strong")
        self.assertIsNone(fa.family_b_from_report(fb(0.4999))["strength"])

    def test_diem_sai_thang_do_bi_tu_choi(self):
        with self.assertRaises(ValueError):
            fa.family_b_from_report(fb(51.0))


class ContextTests(unittest.TestCase):
    DEEP = {"manifest": {"permissions": ["android.permission.INTERNET",
                                         "android.permission.ACCESS_FINE_LOCATION"],
                         "sensitive_services": ["com.x.MyAccessibilityService"]},
            "certificate": {"certificates": [{"sha256": "AB" * 32}]}}

    def test_ngu_canh_tu_bao_cao_tinh(self):
        ctx = fa.build_context(self.DEEP, known_signers=["ab" * 32])
        self.assertTrue(ctx["accessibility_service"])
        self.assertFalse(ctx["device_admin"])
        self.assertTrue(ctx["known_signer"])
        self.assertIsNone(ctx["trusted_install_source"])   # khong co ADB -> khong biet
        self.assertIsNone(ctx["long_usage"])

    def test_quyen_ACCESS_khong_bi_nham_la_tro_nang(self):
        ctx = fa.build_context({"manifest": {"permissions": ["android.permission.ACCESS_WIFI_STATE"],
                                             "sensitive_services": []}})
        self.assertFalse(ctx["accessibility_service"])

    def test_chua_co_danh_sach_chu_ky_thi_la_khong_biet(self):
        self.assertIsNone(fa.build_context(self.DEEP, known_signers=[])["known_signer"])
        self.assertFalse(fa.build_context(self.DEEP, known_signers=["cd" * 32])["known_signer"])

    def test_thiet_bi_cung_cap_nguon_cai_va_thoi_gian_dung(self):
        ctx = fa.build_context(None, device={"installer": "com.android.vending", "usage_days": 200})
        self.assertTrue(ctx["trusted_install_source"])
        self.assertTrue(ctx["long_usage"])
        ctx = fa.build_context(None, device={"installer": "com.android.packageinstaller", "usage_days": 3})
        self.assertFalse(ctx["trusted_install_source"])
        self.assertFalse(ctx["long_usage"])

    def test_dieu_chinh_bi_chan_va_None_khong_dieu_chinh(self):
        self.assertEqual(fa.context_adjustment({"known_signer": None, "device_admin": False}), (0.0, []))
        d, items = fa.context_adjustment({"trusted_install_source": True, "known_signer": True,
                                          "long_usage": True})
        self.assertEqual(d, fa.CONTEXT_MIN)
        self.assertEqual(len(items), 3)
        d, _ = fa.context_adjustment({"accessibility_service": True, "device_admin": True})
        self.assertEqual(d, fa.CONTEXT_MAX)

    def test_ngu_canh_giam_diem_lam_ha_muc(self):
        base = arbitrate(l1(38), fb(0.1))
        self.assertEqual(base["level"], "caution")
        r = arbitrate(l1(38), fb(0.1), context={"known_signer": True})
        self.assertEqual(r["level"], "safe")
        a = r["families"][0]
        self.assertEqual((a["raw_score"], a["score"]), (0.62, 0.52))
        self.assertEqual(r["context_delta"], -0.10)

    def test_ngu_canh_tang_diem_lam_tang_muc(self):
        self.assertEqual(arbitrate(l1(45), fb(0.1))["level"], "safe")
        r = arbitrate(l1(45), fb(0.1), context={"accessibility_service": True, "device_admin": True})
        self.assertEqual(r["level"], "caution")

    def test_apk_lam_meo_khong_duoc_giam_diem(self):
        r = arbitrate(l1(38, zip_tampered=1), fb(0.1), context={"known_signer": True})
        self.assertEqual(r["context_delta"], 0.0)
        self.assertEqual(r["level"], "caution")

    def test_ngu_canh_khong_bien_ho_vang_mat_thanh_co_mat(self):
        r = arbitrate(None, fb(0.2), context={"accessibility_service": True})
        self.assertIsNone(r["families"][0]["score"])
        self.assertEqual(r["level"], "unknown")


class ThresholdFileTests(unittest.TestCase):
    def test_khong_co_file_thi_dung_de_xuat(self):
        th, calibrated, _ = fa.load_thresholds(os.path.join(tempfile.gettempdir(), "khong-ton-tai.json"))
        self.assertEqual(th, fa.DEFAULT_THRESHOLDS)
        self.assertFalse(calibrated)

    def test_doc_file_hieu_chinh_va_ho_thieu_dung_mac_dinh(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "th.json")
            with open(p, "w", encoding="utf-8") as f:
                json.dump({"calibrated": True, "thresholds": {"A": [0.4, 0.7]},
                           "meta": {"n_benign": 300}}, f)
            th, calibrated, meta = fa.load_thresholds(p)
            self.assertEqual(th["A"], (0.4, 0.7))
            self.assertEqual(th["B"], fa.DEFAULT_THRESHOLDS["B"])
            self.assertTrue(calibrated)
            self.assertEqual(meta["calibrated_families"], ["A"])
            self.assertEqual(_arbitrate(l1(55), fb(0.1), thresholds=th)["level"], "caution")

    def test_file_nguong_sai_bi_tu_choi(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "th.json")
            with open(p, "w", encoding="utf-8") as f:
                json.dump({"calibrated": True, "thresholds": {"A": [0.9, 0.5]}}, f)
            with self.assertRaises(ValueError):
                fa.load_thresholds(p)

    def test_decide_level(self):
        self.assertEqual(fa.decide_level(["weak", "weak"], True), "danger")
        self.assertEqual(fa.decide_level(["strong"], False), "warning")
        self.assertEqual(fa.decide_level([], False), "unknown")
        self.assertEqual(fa.decide_level([], True, tampered=True), "caution")


if __name__ == "__main__":
    unittest.main()
