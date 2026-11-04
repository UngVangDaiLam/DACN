# scanner/detect_and_classify.py
"""
Suy luan Tang 1 (phan tich TINH) cho APK.

Pipeline: extract_features(apk_path)  ->  chon cot theo models/static_feature_schema.json
(dung thu tu)  ->  static_model.predict_proba  ->  static_label_encoder.inverse_transform.

Quy tac: file nay KHONG tu suy ra / dem / them cot dac trung nao. Moi dac trung cua
model deu lay tu scanner/static_features.extract_features(). Neu schema doi hoi cot
ma extract_features() khong tra ve -> bao loi cau hinh, khong dien 0.
"""
import os
import sys
import json
import hashlib
import tempfile
import warnings

import joblib
import numpy as np
import pandas as pd

try:
    from scanner import static_features as _sf
except ImportError:  # chay truc tiep: python scanner/detect_and_classify.py
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from scanner import static_features as _sf

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_MODEL_DIR = os.path.join(_ROOT, "models")

ADWARE_NOTE = ("Lưu ý: lớp Adware chịu ảnh hưởng của đời mẫu - mô hình được huấn luyện "
               "trên mẫu Adware 2017-2018, nên với APK đời mới nhãn này kém tin cậy hơn.")
INCOMPLETE_NOTE = "DEX không phân tích được; cần phân tích động"
UNKNOWN_LABEL = "Không xác định"

# Quyen thuc su nhay cam trong 30 quyen theo doi (static_features.PERMISSIONS):
# - 16 quyen protectionLevel "dangerous" (runtime permission) cua Android
# - 5 quyen dac biet / chi he thong cap, hay bi ma doc lam dung
# Bo qua quyen "normal" cap tu dong luc cai: INTERNET, ACCESS_NETWORK_STATE,
# CHANGE_WIFI_STATE, WAKE_LOCK, RECEIVE_BOOT_COMPLETED, DISABLE_KEYGUARD,
# GET_TASKS, KILL_BACKGROUND_PROCESSES, BLUETOOTH.
SENSITIVE_PERMISSIONS = {
    # dangerous (runtime)
    "READ_SMS", "SEND_SMS", "RECEIVE_SMS", "RECEIVE_MMS",
    "READ_PHONE_STATE", "CALL_PHONE", "READ_CALL_LOG",
    "READ_CONTACTS", "WRITE_CONTACTS", "READ_CALENDAR",
    "ACCESS_FINE_LOCATION", "ACCESS_COARSE_LOCATION",
    "CAMERA", "RECORD_AUDIO",
    "READ_EXTERNAL_STORAGE", "WRITE_EXTERNAL_STORAGE",
    # dac biet / he thong
    "SYSTEM_ALERT_WINDOW", "BIND_ACCESSIBILITY_SERVICE", "BIND_DEVICE_ADMIN",
    "REQUEST_INSTALL_PACKAGES", "PACKAGE_USAGE_STATS",
}

# Ma lop '1'..'5' giu nguyen de tuong thich frontend (scan.html: getRecommendation, recs)
MALWARE_INFO = {
    "Benign":   {"class": "1", "name": "Benign (An toàn)",   "icon": "🟢", "color": "success", "risk_level": "Thấp"},
    "Adware":   {"class": "2", "name": "Adware (Quảng cáo)", "icon": "📢", "color": "warning", "risk_level": "Trung bình"},
    "Banking":  {"class": "3", "name": "Banking Malware",    "icon": "🏦", "color": "danger",  "risk_level": "Rất cao"},
    "SMS":      {"class": "4", "name": "SMS Malware",        "icon": "💬", "color": "danger",  "risk_level": "Rất cao"},
    "Riskware": {"class": "5", "name": "Riskware",           "icon": "⚠️", "color": "warning", "risk_level": "Cao"},
}
INCOMPLETE_INFO = {"class": None, "name": UNKNOWN_LABEL, "icon": "❓",
                   "color": "secondary", "risk_level": UNKNOWN_LABEL}

RISK_RULES = [
    ({"READ_SMS", "INTERNET"}, "Có thể đánh cắp mã OTP và gửi về máy chủ từ xa"),
    ({"RECORD_AUDIO", "INTERNET"}, "Có thể nghe lén và truyền âm thanh lên mạng"),
    ({"ACCESS_FINE_LOCATION", "INTERNET"}, "Có thể theo dõi vị trí GPS và gửi về máy chủ"),
    ({"READ_CONTACTS", "SEND_SMS"}, "Có thể phát tán spam SMS tới toàn bộ danh bạ"),
    ({"CAMERA", "INTERNET"}, "Có thể chụp ảnh bí mật và upload lên mạng"),
    ({"READ_CALL_LOG", "INTERNET"}, "Có thể rò rỉ lịch sử cuộc gọi ra ngoài"),
    ({"WRITE_EXTERNAL_STORAGE", "READ_SMS"}, "Có thể sao chép tin nhắn vào thẻ nhớ"),
]


class MalwareDetector:
    def __init__(self,
                 model_path=os.path.join(_MODEL_DIR, "static_model.pkl"),
                 encoder_path=os.path.join(_MODEL_DIR, "static_label_encoder.pkl"),
                 schema_path=os.path.join(_MODEL_DIR, "static_feature_schema.json")):
        print(f"🔍 Nạp model Tầng 1 (tĩnh) từ: {os.path.abspath(model_path)}")
        self.model = joblib.load(model_path)
        self.label_encoder = joblib.load(encoder_path)
        with open(schema_path, encoding="utf-8") as f:
            self.feature_names = list(json.load(f))
        self.class_names = [str(c) for c in self.label_encoder.classes_]

        # Kiem tra cau hinh ngay khi nap, khong de loi lech cot xay ra am tham luc suy luan
        unknown = [c for c in self.feature_names if c not in _sf.FEATURE_SCHEMA]
        if unknown:
            raise ValueError(f"Schema có cột extract_features() không sinh ra: {unknown}")
        model_cols = getattr(self.model, "feature_names_in_", None)
        if model_cols is not None and list(model_cols) != self.feature_names:
            raise ValueError("static_feature_schema.json không khớp thứ tự cột của static_model.pkl")
        unknown_lbl = [c for c in self.class_names if c not in MALWARE_INFO]
        if unknown_lbl:
            raise ValueError(f"Nhãn không có trong MALWARE_INFO: {unknown_lbl}")

    # ------------------------------------------------------------------ core
    def _predict(self, X: pd.DataFrame):
        """X: DataFrame dung cot/thu tu schema. Tra (nhan[], ma tran xac suat)."""
        proba = self.model.predict_proba(X)
        labels = self.label_encoder.inverse_transform(np.argmax(proba, axis=1))
        return labels, proba

    def _vector(self, feats: dict) -> pd.DataFrame:
        missing = [c for c in self.feature_names if c not in feats]
        if missing:
            raise KeyError(f"extract_features() thiếu cột: {missing}")
        return pd.DataFrame([[feats[c] for c in self.feature_names]],
                            columns=self.feature_names, dtype=float)

    def _contributions(self, X: pd.DataFrame, class_idx: int):
        """Dong gop SHAP (TreeSHAP cua XGBoost) cho lop du doan, tren chinh mau nay."""
        try:
            import xgboost as xgb
            contribs = self.model.get_booster().predict(xgb.DMatrix(X), pred_contribs=True)
            contribs = np.asarray(contribs)
            row = contribs[0, class_idx, :-1] if contribs.ndim == 3 else contribs[0, :-1]
        except Exception as e:
            warnings.warn(f"Không tính được SHAP: {e!r}")
            return []
        pos_total = row[row > 0].sum()
        order = np.argsort(row)[::-1][:15]
        return [
            {
                "name": self.feature_names[i],
                "present": float(X.iloc[0, i]),
                "shap": round(float(row[i]), 4),
                # % trong tong luc day (duong) ve phia lop du doan
                "contribution": round(float(row[i] / pos_total * 100), 3) if pos_total > 0 else 0.0,
            }
            for i in order if row[i] > 0
        ]

    # ------------------------------------------------------------------- APK
    def analyze_apk(self, apk_input, filename):
        """apk_input: bytes (upload stream) hoac duong dan file APK."""
        tmp_path = None
        try:
            if isinstance(apk_input, (bytes, bytearray)):
                apk_bytes = bytes(apk_input)
                fd, tmp_path = tempfile.mkstemp(suffix=".apk")
                with os.fdopen(fd, "wb") as f:
                    f.write(apk_bytes)
                apk_path = tmp_path
            else:
                apk_path = apk_input
                apk_bytes = None

            reasons = []
            with warnings.catch_warnings(record=True) as caught:
                warnings.simplefilter("always")
                try:
                    feats = _sf.extract_features(apk_path)
                except Exception as e:
                    feats = None
                    reasons.append(f"extract_features thất bại: {e!r}")
            reasons += [str(w.message) for w in caught
                        if "AnalyzeAPK loi" in str(w.message)
                        or "opcode" in str(w.message).lower()]

            if feats is None:
                if apk_bytes is None:
                    with open(apk_path, "rb") as f:
                        apk_bytes = f.read()
                return self._incomplete_result(filename, reasons, apk_bytes=apk_bytes)

            # Tieu chi giong train_static_model.py: tong opcode__* = 0 -> khong co DEX
            # de phan tich -> KHONG goi predict (model khong duoc train tren vector nay).
            opcode_cols = [c for c in self.feature_names if c.startswith("opcode__")]
            if sum(feats[c] for c in opcode_cols) == 0:
                if not reasons:
                    reasons.append("Không đếm được lệnh DEX nào (tổng opcode__* = 0)")
                return self._incomplete_result(filename, reasons, feats=feats)

            return self._apk_result(filename, feats)
        except Exception as e:
            import traceback
            print(traceback.format_exc())
            return {"success": False, "error": f"Lỗi phân tích: {e}"}
        finally:
            if tmp_path:
                try:
                    os.remove(tmp_path)
                except OSError:
                    pass

    def _permission_info(self, feats):
        """Thong tin quyen (doc tu manifest, KHONG phai du doan) de hien thi."""
        perm_cols = [c for c in self.feature_names if c.startswith("perm__")]
        present = {c[len("perm__"):] for c in perm_cols if feats[c]}
        return {
            "dangerous_permissions": sorted(f"android.permission.{p}"
                                            for p in present & SENSITIVE_PERMISSIONS),
            "total_permissions": int(feats["num_permissions"]),
            "risk_combos": [msg for req, msg in RISK_RULES if req.issubset(present)],
        }

    def _incomplete_result(self, filename, reasons, feats=None, apk_bytes=None):
        """
        Khong co DEX phan tich duoc -> KHONG goi predict. Van tra co tamper, sha256,
        package_name (va thong tin quyen neu manifest doc duoc).
        """
        if feats is not None:
            tamper = {k: int(feats[k]) for k in ("manifest_tampered", "zip_tampered")}
            sha256, package, source = feats["sha256"], feats["package_name"], feats["manifest_source"]
            perm_info = self._permission_info(feats)
        else:
            tamper = _sf._tamper_flags(apk_bytes)  # (1,1) neu khong doc duoc cau truc
            sha256, package, source = hashlib.sha256(apk_bytes).hexdigest(), None, None
            perm_info = {"dangerous_permissions": [], "total_permissions": 0, "risk_combos": []}
        return {
            "success": True,
            "type": "apk",
            "filename": filename,
            "analysis_incomplete": True,
            "incomplete_reasons": reasons,
            "label": UNKNOWN_LABEL,
            "probabilities": {},
            "all_probabilities": {},
            "confidence": None,
            **INCOMPLETE_INFO,
            "notes": [INCOMPLETE_NOTE],
            "manifest_source": source,
            "manifest_tampered": tamper["manifest_tampered"],
            "zip_tampered": tamper["zip_tampered"],
            "sha256": sha256,
            "package_name": package,
            "app_name": package,
            **perm_info,
            "feature_count": 0,
            "top_contributing": [],
            "absent_important": [],
        }

    def _apk_result(self, filename, feats):
        X = self._vector(feats)
        labels, proba = self._predict(X)
        label = str(labels[0])
        probs = {c: round(float(p) * 100, 2) for c, p in zip(self.class_names, proba[0])}
        class_idx = self.class_names.index(label)
        info = MALWARE_INFO[label]

        notes = [ADWARE_NOTE] if label == "Adware" else []

        importances = getattr(self.model, "feature_importances_", None)
        absent_important = []
        if importances is not None:
            absent_important = [
                {"name": self.feature_names[i], "importance": round(float(importances[i]) * 100, 3)}
                for i in np.argsort(importances)[::-1] if X.iloc[0, i] == 0
            ][:5]

        sample_cols = self.feature_names[:20]
        return {
            "success": True,
            "type": "apk",
            "filename": filename,
            "analysis_incomplete": False,
            "incomplete_reasons": [],
            # --- ket qua model ---
            "label": label,
            "probabilities": probs,          # {ten lop: %}
            "all_probabilities": probs,      # khoa cu ma scan.html dung de ve bieu do
            "confidence": probs[label],
            "class": info["class"],
            "name": info["name"],
            "icon": info["icon"],
            "color": info["color"],
            "risk_level": info["risk_level"],
            "notes": notes,
            # --- metadata tu extract_features ---
            "manifest_source": feats["manifest_source"],
            "manifest_tampered": int(feats["manifest_tampered"]),
            "zip_tampered": int(feats["zip_tampered"]),
            "sha256": feats["sha256"],
            "package_name": feats["package_name"],
            "app_name": feats["package_name"],  # extract_features khong doc ten app
            # --- giai thich / hien thi ---
            **self._permission_info(feats),
            "feature_count": int((X.iloc[0] != 0).sum()),  # so cot khac 0 / len(schema)
            "binary_vector_sample": [float(X.iloc[0][c]) for c in sample_cols],
            "feature_column_names": sample_cols,
            "top_contributing": self._contributions(X, class_idx),
            "absent_important": absent_important,
        }

    # ------------------------------------------------------------------- CSV
    def analyze_csv(self, filepath, filename):
        """
        CSV dac trung tinh (vd dataset/processed/static_features.csv). Phai co DU cac cot
        trong schema, dung ten; khong dien cot thieu.
        """
        df = pd.read_csv(filepath, low_memory=False)
        missing = [c for c in self.feature_names if c not in df.columns]
        if missing:
            return {"success": False,
                    "error": f"CSV thiếu {len(missing)}/{len(self.feature_names)} cột của schema "
                             f"Tầng 1 (vd: {missing[:5]}). Hãy tạo CSV bằng extract_features()."}
        X = df[self.feature_names].apply(pd.to_numeric, errors="coerce")
        bad_rows = int(X.isna().any(axis=1).sum())
        if bad_rows:
            return {"success": False, "error": f"{bad_rows} dòng có giá trị không phải số trong cột đặc trưng."}

        labels, proba = self._predict(X.astype(float))
        stats = {}
        uniq, counts = np.unique(labels, return_counts=True)
        for lbl, cnt in zip(uniq, counts):
            stats[MALWARE_INFO[str(lbl)]["class"]] = {
                "count": int(cnt), "percentage": round(float(cnt) / len(labels) * 100, 2)}

        first = str(labels[0])
        info = MALWARE_INFO[first]
        return {
            "success": True,
            "type": "csv",
            "filename": filename,
            "total_samples": len(df),
            "statistics": stats,
            "first_sample": {
                "class": info["class"],
                "label": first,
                "name": info["name"],
                "confidence": round(float(proba[0].max()) * 100, 2),
                "icon": info["icon"],
                "risk_level": info["risk_level"],
                "notes": [ADWARE_NOTE] if first == "Adware" else [],
            },
        }


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python scanner/detect_and_classify.py <file.apk|file.csv> [...]")
        sys.exit(1)
    detector = MalwareDetector()
    for filepath in sys.argv[1:]:
        filename = os.path.basename(filepath)
        if filename.lower().endswith(".csv"):
            result = detector.analyze_csv(filepath, filename)
        elif filename.lower().endswith(".apk"):
            result = detector.analyze_apk(filepath, filename)
        else:
            print(f"Bỏ qua (không hỗ trợ): {filepath}")
            continue
        keys = ["success", "label", "probabilities", "manifest_source", "manifest_tampered",
                "zip_tampered", "sha256", "package_name", "analysis_incomplete",
                "incomplete_reasons", "notes", "error"]
        print(f"\n📊 {filename}")
        print(json.dumps({k: result.get(k) for k in keys if k in result},
                         ensure_ascii=False, indent=2))
