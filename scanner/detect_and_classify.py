# scanner/detect_and_classify.py
import pandas as pd
import numpy as np
import joblib
import os
import hashlib
import tempfile

# Thư mục gốc dự án — để nạp model đúng bất kể chạy từ thư mục nào
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_MODELS = os.path.join(_ROOT, 'models')

# Model tĩnh (Tầng 1) sinh bởi train_static_model.py
STATIC_MODEL_PATH = os.path.join(_MODELS, 'static_model.pkl')
STATIC_ENCODER_PATH = os.path.join(_MODELS, 'static_label_encoder.pkl')

RISK_RULES = [
    ({'android.permission.READ_SMS', 'android.permission.INTERNET'},
     'Có thể đánh cắp mã OTP và gửi về máy chủ từ xa'),
    ({'android.permission.RECORD_AUDIO', 'android.permission.INTERNET'},
     'Có thể nghe lén và truyền âm thanh lên mạng'),
    ({'android.permission.ACCESS_FINE_LOCATION', 'android.permission.INTERNET'},
     'Có thể theo dõi vị trí GPS và gửi về máy chủ'),
    ({'android.permission.READ_CONTACTS', 'android.permission.SEND_SMS'},
     'Có thể phát tán spam SMS tới toàn bộ danh bạ'),
    ({'android.permission.CAMERA', 'android.permission.INTERNET'},
     'Có thể chụp ảnh bí mật và upload lên mạng'),
    ({'android.permission.READ_CALL_LOG', 'android.permission.INTERNET'},
     'Có thể rò rỉ lịch sử cuộc gọi ra ngoài'),
    ({'android.permission.WRITE_EXTERNAL_STORAGE', 'android.permission.READ_SMS'},
     'Có thể sao chép tin nhắn vào thẻ nhớ'),
]

class MalwareDetector:
    def __init__(self, model_path=os.path.join(_MODELS, 'malware_model.pkl'),
                 scaler_path=os.path.join(_MODELS, 'scaler.pkl'),
                 encoder_path=os.path.join(_MODELS, 'label_encoder.pkl')):
        print(f"🔍 DEBUG: Đang nạp Model từ: {os.path.abspath(model_path)}")
        self.model = joblib.load(model_path)
        self.scaler = joblib.load(scaler_path)
        self.label_encoder = joblib.load(encoder_path)
        self.class_names = [str(name) for name in self.label_encoder.classes_]
        
        self.malware_info = {
            '1': {'name': 'Benign (An toàn)', 'icon': '🟢', 'color': 'success', 'risk_level': 'Thấp'},
            '2': {'name': 'Adware (Quảng cáo)', 'icon': '📢', 'color': 'warning', 'risk_level': 'Trung bình'},
            '3': {'name': 'Banking Malware', 'icon': '🏦', 'color': 'danger', 'risk_level': 'Rất cao'},
            '4': {'name': 'SMS Malware', 'icon': '💬', 'color': 'danger', 'risk_level': 'Rất cao'},
            '5': {'name': 'Riskware', 'icon': '⚠️', 'color': 'warning', 'risk_level': 'Cao'}
        }
    
    def analyze_csv(self, filepath, filename):
        """Phân tích file CSV"""
        df = pd.read_csv(filepath, low_memory=False)
        
        for col in df.columns:
            if col.lower() in ['class', 'category', 'label']:
                df = df.drop(columns=[col])
                break
        
        for col in df.columns:
            if df[col].dtype == 'object':
                df[col] = pd.to_numeric(df[col], errors='coerce').fillna(0)
        
        df = df.fillna(0).replace([np.inf, -np.inf], 0)
        
        n_features = self.scaler.mean_.shape[0]
        if df.shape[1] > n_features:
            df = df.iloc[:, :n_features]
        elif df.shape[1] < n_features:
            for i in range(n_features - df.shape[1]):
                df[f'dummy_{i}'] = 0
        
        X_scaled = self.scaler.transform(df)
        predictions = self.model.predict(X_scaled)
        probabilities = self.model.predict_proba(X_scaled)
        
        unique, counts = np.unique(predictions, return_counts=True)
        stats = {}
        for code, count in zip(unique, counts):
            class_key = str(code + 1)
            stats[class_key] = {
                'count': int(count),
                'percentage': round(count / len(predictions) * 100, 2)
            }
        
        first_pred = predictions[0]
        first_class = str(first_pred + 1)
        first_conf = probabilities[0][first_pred] * 100
        first_info = self.malware_info.get(first_class, self.malware_info['1'])
        
        return {
            'success': True,
            'type': 'csv',
            'filename': filename,
            'total_samples': len(df),
            'statistics': stats,
            'first_sample': {
                'class': first_class,
                'name': first_info['name'],
                'confidence': round(first_conf, 2),
                'icon': first_info['icon'],
                'risk_level': first_info['risk_level']
            }
        }
    
    def _load_static_model(self):
        """Nạp model tĩnh (cache). Trả về (model, encoder) hoặc None nếu chưa train."""
        if not hasattr(self, '_static'):
            self._static = None
            if os.path.exists(STATIC_MODEL_PATH) and os.path.exists(STATIC_ENCODER_PATH):
                self._static = (joblib.load(STATIC_MODEL_PATH), joblib.load(STATIC_ENCODER_PATH))
                print(f"✅ Đã nạp model tĩnh: {STATIC_MODEL_PATH}")
            else:
                print("⚠️ Chưa có models/static_model.pkl — APK sẽ dùng pipeline cũ (KHÔNG đáng tin). "
                      "Chạy build_static_dataset.py + train_static_model.py.")
        return self._static

    @staticmethod
    def _static_class_info(label):
        """Ánh xạ nhãn của model tĩnh sang class key '1'-'5' mà frontend đang dùng."""
        low = label.lower()
        if low == 'benign':
            key = '1'
        elif 'adware' in low:
            key = '2'
        elif 'bank' in low:
            key = '3'
        elif 'sms' in low:
            key = '4'
        else:
            key = '5'
        return key

    def analyze_apk(self, apk_input, filename):
        """Phân tích APK. Dùng model tĩnh (extract_features) nếu có; nếu chưa train thì dùng pipeline cũ."""
        static = self._load_static_model()
        if static is None:
            result = self._analyze_apk_legacy(apk_input, filename)
            if result.get('success'):
                result['unreliable'] = True
                result['warning'] = ('Model tĩnh chưa được train — kết quả dựa trên pipeline cũ '
                                     '(dò chuỗi trong DEX) và KHÔNG đáng tin cậy.')
            return result
        return self._analyze_apk_static(apk_input, filename, *static)

    def _analyze_apk_static(self, apk_input, filename, model, encoder):
        """Pipeline đúng: cùng extract_features() với lúc train, không cắt/đệm cột."""
        tmp_path = None
        try:
            from scanner.static_features import extract_features, FEATURE_SCHEMA
            from androguard.core.apk import APK

            if isinstance(apk_input, (bytes, bytearray)):
                with tempfile.NamedTemporaryFile(suffix='.apk', delete=False) as tmp:
                    tmp.write(bytes(apk_input))
                    tmp_path = tmp.name
                apk_path = tmp_path
            else:
                apk_path = apk_input

            feats = extract_features(apk_path)
            apk = APK(apk_path)
            permissions = list(apk.get_permissions())

            X = pd.DataFrame([{c: feats[c] for c in FEATURE_SCHEMA}])[FEATURE_SCHEMA].astype(float)
            proba = model.predict_proba(X)[0]
            pred = int(np.argmax(proba))
            label = str(encoder.classes_[pred])
            class_key = self._static_class_info(label)
            info = self.malware_info[class_key]
            display_name = info['name'] if class_key in ('1', '2', '3', '4') else f"{info['name']} ({label})"

            importances = getattr(model, 'feature_importances_', np.zeros(len(FEATURE_SCHEMA)))
            values = X.iloc[0].to_numpy()
            present = (values != 0).astype(float)
            contributions = present * importances
            top_idx = np.argsort(contributions)[::-1][:15]
            top_contributing = [
                {'name': FEATURE_SCHEMA[i], 'present': int(present[i]),
                 'importance': round(float(importances[i]) * 100, 3),
                 'contribution': round(float(contributions[i]) * 100, 3)}
                for i in top_idx if contributions[i] > 0
            ]
            absent_important = [
                {'name': FEATURE_SCHEMA[i], 'importance': round(float(importances[i]) * 100, 3)}
                for i in np.argsort(importances)[::-1][:30] if present[i] == 0
            ][:5]

            perms_set = set(permissions)
            risk_combos = [w for req, w in RISK_RULES if req.issubset(perms_set)]
            dangerous = [p for p in permissions if f"perm__{p.split('.')[-1]}" in FEATURE_SCHEMA]
            sample_cols = FEATURE_SCHEMA[:20]

            return {
                'success': True,
                'type': 'apk',
                'filename': filename,
                'package_name': feats['package_name'],
                'app_name': apk.get_app_name() or feats['package_name'],
                'class': class_key,
                'name': display_name,
                'label': label,
                'confidence': float(round(proba[pred] * 100, 2)),
                'icon': info['icon'],
                'color': info['color'],
                'risk_level': info['risk_level'],
                'dangerous_permissions': dangerous,
                'all_permissions': permissions,
                'total_permissions': len(permissions),
                'feature_count': len(FEATURE_SCHEMA),
                'sha256': feats['sha256'],
                'binary_vector_sample': [float(feats[c]) for c in sample_cols],
                'feature_column_names': sample_cols,
                'risk_combos': risk_combos,
                'top_contributing': top_contributing,
                'absent_important': absent_important,
            }
        except Exception as e:
            import traceback
            print(traceback.format_exc())
            return {'success': False, 'error': f"Lỗi phân tích: {str(e)}"}
        finally:
            if tmp_path:
                try: os.remove(tmp_path)
                except OSError: pass

    def _analyze_apk_legacy(self, apk_input, filename):
        """[CŨ - KHÔNG ĐÁNG TIN] Dò chuỗi trong DEX theo tên đặc trưng syscall của CICMalDroid."""
        try:
            from androguard.core.apk import APK
            # Nhận bytes trực tiếp hoặc đọc từ file path
            if isinstance(apk_input, (bytes, bytearray)):
                apk_bytes = bytes(apk_input)
            else:
                with open(apk_input, 'rb') as _f:
                    apk_bytes = _f.read()
            sha256 = hashlib.sha256(apk_bytes).hexdigest()
            apk = APK(apk_bytes, raw=True)
            permissions = apk.get_permissions()
            
            # 1. Lấy danh sách đặc trưng mà Model/Scaler thực sự mong đợi
            if hasattr(self.scaler, 'feature_names_in_'):
                expected_features = self.scaler.feature_names_in_
            else:
                return {'success': False, 'error': 'Không tìm thấy danh sách đặc trưng trong Scaler.'}

            # 2. Tạo một dictionary rỗng
            features_dict = {feat: 0 for feat in expected_features}
            # ==========================================
        
            # 3. Khớp (Map) đặc trưng bằng cách quét thẳng vào Bytecode (RAW DEX)
            found_count = 0
            
            try:
                raw_data = b""
                
                # 1. Quét RAW toàn bộ các file .dex trong APK
                for fname in apk.get_files():
                    if fname.endswith('.dex'):
                        raw_data += apk.get_file(fname)
                
                # 2. Gộp thêm danh sách Permissions, Activities, Services
                all_components = permissions + apk.get_activities() + apk.get_services()
                components_str = " ".join(all_components).lower()
                raw_data += components_str.encode('utf-8', errors='ignore')
                
                # 3. Thuật toán tìm kiếm siêu tốc trên Bytes
                for feat in expected_features:
                    # Gọt chữ (VD: 'CREATE_FOLDER___' -> 'create_folder')
                    clean_feat = feat.strip('_').lower()
                    
                    # Kiểm tra trực tiếp xem từ khóa có nằm trong đống byte mã nguồn không
                    if clean_feat.encode('utf-8', errors='ignore') in raw_data:
                        features_dict[feat] = 1
                        found_count += 1
                        
            except Exception as e:
                print(f"[-] Lỗi quét RAW: {e}")

            print(f"📊 [DEBUG] Đã KHỚP thành công {found_count}/{len(expected_features)} đặc trưng.")

            # 4. Tạo DataFrame và BẮT BUỘC giữ đúng thứ tự cột
            feature_df = pd.DataFrame([features_dict])[expected_features]

            # 5. Tiến hành dự đoán
            X_scaled = self.scaler.transform(feature_df)
            pred = int(self.model.predict(X_scaled)[0])
            prob = self.model.predict_proba(X_scaled)[0][pred] * 100
            
            class_key = str(pred + 1)
            info = self.malware_info.get(class_key, self.malware_info['1'])
            
            dangerous_found = [p for p in permissions if p.split('.')[-1] + "__" in expected_features]

            # Binary vector mẫu (20 cột đầu) để hiển thị trong UI
            sample_cols = list(expected_features[:20])
            binary_vector_sample = [int(features_dict[c]) for c in sample_cols]

            # Top contributing features: contribution = feature_value × global_importance
            # Cho biết đặc trưng nào trong APK này đã "kéo" model về kết quả phân loại
            importances = self.model.feature_importances_
            feat_values = np.array([features_dict[f] for f in expected_features])
            contributions = feat_values * importances
            top_idx = np.argsort(contributions)[::-1][:15]
            top_contributing = [
                {
                    'name': str(expected_features[i]),
                    'present': int(feat_values[i]),
                    'importance': round(float(importances[i]) * 100, 3),
                    'contribution': round(float(contributions[i]) * 100, 3),
                }
                for i in top_idx if contributions[i] > 0
            ]
            # Top vắng mặt nhưng quan trọng (absent but high importance)
            absent_important = [
                {
                    'name': str(expected_features[i]),
                    'importance': round(float(importances[i]) * 100, 3),
                }
                for i in np.argsort(importances)[::-1][:30]
                if feat_values[i] == 0
            ][:5]

            # Static risk combo — phát hiện tổ hợp quyền nguy hiểm
            perms_set = set(permissions)
            risk_combos = []
            RISK_RULES = [
                ({'android.permission.READ_SMS', 'android.permission.INTERNET'},
                 'Có thể đánh cắp mã OTP và gửi về máy chủ từ xa'),
                ({'android.permission.RECORD_AUDIO', 'android.permission.INTERNET'},
                 'Có thể nghe lén và truyền âm thanh lên mạng'),
                ({'android.permission.ACCESS_FINE_LOCATION', 'android.permission.INTERNET'},
                 'Có thể theo dõi vị trí GPS và gửi về máy chủ'),
                ({'android.permission.READ_CONTACTS', 'android.permission.SEND_SMS'},
                 'Có thể phát tán spam SMS tới toàn bộ danh bạ'),
                ({'android.permission.CAMERA', 'android.permission.INTERNET'},
                 'Có thể chụp ảnh bí mật và upload lên mạng'),
                ({'android.permission.READ_CALL_LOG', 'android.permission.INTERNET'},
                 'Có thể rò rỉ lịch sử cuộc gọi ra ngoài'),
                ({'android.permission.WRITE_EXTERNAL_STORAGE', 'android.permission.READ_SMS'},
                 'Có thể sao chép tin nhắn vào thẻ nhớ'),
            ]
            for required_perms, warning in RISK_RULES:
                if required_perms.issubset(perms_set):
                    risk_combos.append(warning)

            confidence_score = float(round(prob, 2))

            return {
                'success': True,
                'type': 'apk',
                'filename': filename,
                'package_name': apk.get_package(),
                'app_name': apk.get_app_name() or apk.get_package(),
                'class': class_key,
                'name': info['name'],
                'confidence': confidence_score,
                'icon': info['icon'],
                'color': info['color'],
                'risk_level': info['risk_level'],
                'dangerous_permissions': dangerous_found,
                'all_permissions': list(permissions),
                'total_permissions': len(permissions),
                'feature_count': found_count,
                'sha256': sha256,
                'binary_vector_sample': binary_vector_sample,
                'feature_column_names': sample_cols,
                'risk_combos': risk_combos,
                'top_contributing': top_contributing,
                'absent_important': absent_important,
            }

        except Exception as e:
            import traceback
            print(traceback.format_exc())
            return {'success': False, 'error': f"Lỗi phân tích: {str(e)}"}


if __name__ == "__main__":
    import sys
    detector = MalwareDetector()
    
    if len(sys.argv) < 2:
        print("Usage: python detect_and_classify.py <file_path>")
        sys.exit(1)
    
    filepath = sys.argv[1]
    filename = os.path.basename(filepath)
    
    if filename.endswith('.csv'):
        result = detector.analyze_csv(filepath, filename)
    elif filename.endswith('.apk'):
        result = detector.analyze_apk(filepath, filename)
    else:
        print("Unsupported file type")
        sys.exit(1)
    
    if result['success']:
        print(f"\n📊 KẾT QUẢ: {result['filename']}")
        print(f"   Kết quả: {result['name']}")
        print(f"   Độ tin cậy: {result['confidence']}%")
    else:
        print(f"Lỗi: {result['error']}")