r"""oof_scores.py phai dung DUNG cau hinh cua train_static_model.py (mo hinh dang trien khai).

Doc train_static_model.py bang ast (khong chay file do, khong nap models/*.pkl).
Chay:  .\venv\Scripts\python.exe -B tests\test_oof_config.py -v
"""
import ast
import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from scanner import oof_scores  # noqa: E402


def _train_xgb_kwargs():
    tree = ast.parse(open(os.path.join(ROOT, "train_static_model.py"), encoding="utf-8").read())
    calls = [n for n in ast.walk(tree) if isinstance(n, ast.Call)
             and getattr(n.func, "id", getattr(n.func, "attr", None)) == "XGBClassifier"]
    assert len(calls) == 1, "train_static_model.py phai co dung 1 loi goi XGBClassifier(...)"
    return {k.arg: ast.literal_eval(k.value) for k in calls[0].keywords}


class TestOofConfig(unittest.TestCase):
    def test_tham_so_xgboost_khop_train_static_model(self):
        self.assertEqual(oof_scores.XGB_PARAMS, _train_xgb_kwargs())

    def test_can_bang_lop_bang_sample_weight_khong_smote(self):
        src_oof = open(oof_scores.__file__, encoding="utf-8").read()
        src_train = open(os.path.join(ROOT, "train_static_model.py"), encoding="utf-8").read()
        self.assertIn('compute_sample_weight("balanced"', src_train)
        self.assertIn('compute_sample_weight("balanced"', src_oof)
        self.assertNotIn("SMOTE(", src_oof)

    def test_van_nhom_theo_package_name_5_fold(self):
        src_oof = open(oof_scores.__file__, encoding="utf-8").read()
        self.assertIn("StratifiedGroupKFold(", src_oof)
        self.assertIn('ap.add_argument("--folds", type=int, default=5)', src_oof)


if __name__ == "__main__":
    unittest.main()
