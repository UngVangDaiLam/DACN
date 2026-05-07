# src/apk_analyzer.py
"""
PHÂN TÍCH FILE APK - TRÍCH XUẤT ĐẶC TRƯNG
Dùng để phân tích file APK trực tiếp
"""

import os
import hashlib
from androguard.misc import AnalyzeAPK
from androguard.core.apk import APK
import pandas as pd
import numpy as np
import joblib


class APKAnalyzer:
    def __init__(self, model_path='models/malware_model.pkl',
                 scaler_path='models/scaler.pkl',
                 encoder_path='models/label_encoder.pkl'):
        """Khởi tạo analyzer với model đã train"""
        self.model = joblib.load(model_path)
        self.scaler = joblib.load(scaler_path)
        self.label_encoder = joblib.load(encoder_path)
        self.class_names = [str(name) for name in self.label_encoder.classes_]

        # Danh sách các permission nguy hiểm (dùng làm đặc trưng)
        self.dangerous_permissions = [
            'android.permission.READ_SMS',
            'android.permission.SEND_SMS',
            'android.permission.RECEIVE_SMS',
            'android.permission.CALL_PHONE',
            'android.permission.READ_CONTACTS',
            'android.permission.ACCESS_FINE_LOCATION',
            'android.permission.CAMERA',
            'android.permission.RECORD_AUDIO',
            'android.permission.READ_EXTERNAL_STORAGE',
            'android.permission.WRITE_EXTERNAL_STORAGE'
        ]

    def extract_features_from_apk(self, apk_path):
        """Trích xuất đặc trưng từ file APK"""

        # Phân tích APK
        apk = APK(apk_path)

        # 1. Lấy danh sách permissions
        permissions = apk.get_permissions()

        # 2. Tạo vector đặc trưng từ permissions
        features = {}
        for perm in self.dangerous_permissions:
            features[perm] = 1 if perm in permissions else 0

        # 3. Lấy thông tin bổ sung
        features['has_debuggable'] = 1 if apk.is_debuggable() else 0
        features['has_allow_backup'] = 1 if apk.is_allow_backup() else 0
        features['num_permissions'] = len(permissions)
        features['num_dangerous_perms'] = sum(
            1 for p in permissions if p in self.dangerous_permissions)

        # 4. Lấy thông tin về các thành phần
        features['num_activities'] = len(apk.get_activities())
        features['num_services'] = len(apk.get_services())
        features['num_receivers'] = len(apk.get_receivers())

        # 5. Tính hash của APK để làm ID
        with open(apk_path, 'rb') as f:
            features['md5_hash'] = hashlib.md5(f.read()).hexdigest()

        return features, permissions, apk


    def predict_apk(self, apk_path):
        """Dự đoán file APK và xuất mảng phân phối xác suất"""
        features, permissions, apk = self.extract_features_from_apk(apk_path)

        # Chuyển features thành DataFrame
        feature_df = pd.DataFrame([features])

        # Xử lý dữ liệu
        for col in feature_df.columns:
            if feature_df[col].dtype == 'object':
                feature_df[col] = pd.to_numeric(
                    feature_df[col], errors='coerce').fillna(0)

        feature_df = feature_df.fillna(0).replace([np.inf, -np.inf], 0)

        # Đảm bảo số cột khớp với model
        n_features = self.scaler.mean_.shape[0]
        if feature_df.shape[1] > n_features:
            feature_df = feature_df.iloc[:, :n_features]
        elif feature_df.shape[1] < n_features:
            for i in range(n_features - feature_df.shape[1]):
                feature_df[f'dummy_{i}'] = 0

        # 1. Chuẩn hóa và Dự đoán (Scaling & Prediction)
        X_scaled = self.scaler.transform(feature_df)
        probs_array = self.model.predict_proba(X_scaled)[0]
        pred = int(self.model.predict(X_scaled)[0])
        prob = probs_array[pred] * 100
        class_name = str(pred + 1)

        # 2. Đóng gói mảng xác suất (Probability Distribution)
        all_probabilities = {
            'Benign': round(float(probs_array[0]) * 100, 2),
            'Adware': round(float(probs_array[1]) * 100, 2),
            'Banking': round(float(probs_array[2]) * 100, 2),
            'SMS': round(float(probs_array[3]) * 100, 2),
            'Riskware': round(float(probs_array[4]) * 100, 2)
        }

        # 3. Trích xuất các đặc trưng kích hoạt (Active Features) cho XAI
        active_features = [
            key for key, val in features.items() if val == 1 and key != 'md5_hash']

        # Lấy tên app
        app_name = apk.get_app_name() or apk.get_package()

        return {
            'package_name': apk.get_package(),
            'app_name': app_name,
            'version': apk.get_android_version_code(),
            'target_sdk': apk.get_target_sdk_version(),
            'class_name': class_name,
            'confidence': round(float(prob), 2),
            'all_probabilities': all_probabilities,
            'active_features': active_features,
            'permissions': permissions,
            'dangerous_permissions': [p for p in permissions if p in self.dangerous_permissions],
            'features': features
        }

    def get_detailed_report(self, apk_path):
        """Tạo báo cáo chi tiết từ APK"""
        result = self.predict_apk(apk_path)
        
        # Ánh xạ class sang thông tin
        class_info = {
            '1': {'name': 'Benign (An toàn)', 'risk': 'Thấp', 'icon': '🟢', 'color': 'success'},
            '2': {'name': 'Adware (Quảng cáo độc hại)', 'risk': 'Trung bình', 'icon': '📢', 'color': 'warning'},
            '3': {'name': 'Banking Malware (Mã độc ngân hàng)', 'risk': 'Rất cao', 'icon': '🏦', 'color': 'danger'},
            '4': {'name': 'SMS Malware (Mã độc tin nhắn)', 'risk': 'Rất cao', 'icon': '💬', 'color': 'danger'},
            '5': {'name': 'Riskware (Phần mềm rủi ro)', 'risk': 'Cao', 'icon': '⚠️', 'color': 'warning'}
        }
        
        info = class_info.get(result['class_name'], class_info['1'])
        
        report = {
            **result,
            'display_name': info['name'],
            'risk_level': info['risk'],
            'icon': info['icon'],
            'color': info['color'],
            'recommendations': self._get_recommendations(result['class_name'], result['dangerous_permissions'])
        }
        
        return report
    
    def _get_recommendations(self, class_name, dangerous_perms):
        """Đưa ra khuyến nghị dựa trên kết quả"""
        if class_name == '1':
            return [
                "✅ Ứng dụng an toàn, có thể sử dụng bình thường",
                "✅ Nên cập nhật ứng dụng thường xuyên",
                "✅ Kiểm tra quyền truy cập định kỳ"
            ]
        elif class_name in ['3', '4']:
            return [
                "🔴 Gỡ cài đặt NGAY LẬP TỨC!",
                "🔴 Đổi mật khẩu các tài khoản quan trọng",
                "🔴 Quét toàn bộ thiết bị bằng phần mềm diệt virus",
                f"🔴 Ứng dụng yêu cầu {len(dangerous_perms)} quyền nguy hiểm: {', '.join(dangerous_perms[:3])}"
            ]
        else:
            return [
                "⚠️ Cân nhắc gỡ cài đặt nếu không cần thiết",
                "⚠️ Hạn chế quyền truy cập của ứng dụng",
                f"⚠️ Kiểm tra các quyền: {', '.join(dangerous_perms[:5])}"
            ]


# Test nhanh
if __name__ == "__main__":
    analyzer = APKAnalyzer()
    
    # Thay bằng đường dẫn đến file APK của bạn
    apk_file = "path/to/your/app.apk"
    
    if os.path.exists(apk_file):
        report = analyzer.get_detailed_report(apk_file)
        print("\n" + "="*60)
        print(f"📱 Ứng dụng: {report['app_name']}")
        print(f"📦 Package: {report['package_name']}")
        print(f"{report['icon']} Kết quả: {report['display_name']}")
        print(f"🎯 Độ tin cậy: {report['confidence']}%")
        print(f"⚠️ Mức độ rủi ro: {report['risk_level']}")
        print(f"\n📋 Quyền nguy hiểm: {len(report['dangerous_permissions'])}")
        for perm in report['dangerous_permissions'][:5]:
            print(f"   - {perm}")
        print("\n💡 KHUYẾN NGHỊ:")
        for rec in report['recommendations']:
            print(f"   {rec}")
        print("="*60)
    else:
        print("Chưa có file APK để test. Hãy tải một file APK bất kỳ về để test.")