# scanner/smart_filter.py
"""
SMART FILTER - Phát hiện và phân loại mã độc Android từ CLI
Chức năng: Quét file CSV và hiển thị kết quả dạng bảng
"""

import pandas as pd
import numpy as np
import joblib
import sys
import os
from datetime import datetime

class SmartFilter:
    def __init__(self, model_path='models/malware_model.pkl', 
                 scaler_path='models/scaler.pkl',
                 encoder_path='models/label_encoder.pkl'):
        """
        Khởi tạo bộ lọc thông minh
        """
        print("\n" + "="*60)
        print("🦾 SMART FILTER - PHÁT HIỆN MÃ ĐỘC ANDROID")
        print("="*60)
        
        # Load model
        if not os.path.exists(model_path):
            raise FileNotFoundError(f"Không tìm thấy model: {model_path}")
        self.model = joblib.load(model_path)
        print(f"✅ Đã load model: {model_path}")
        
        # Load scaler
        if not os.path.exists(scaler_path):
            raise FileNotFoundError(f"Không tìm thấy scaler: {scaler_path}")
        self.scaler = joblib.load(scaler_path)
        print(f"✅ Đã load scaler: {scaler_path}")
        
        # Load label encoder
        if not os.path.exists(encoder_path):
            raise FileNotFoundError(f"Không tìm thấy label encoder: {encoder_path}")
        self.label_encoder = joblib.load(encoder_path)
        self.class_names = [str(name) for name in self.label_encoder.classes_]
        print(f"✅ Đã load label encoder: {self.class_names}")
        
        # Định nghĩa thông tin các loại mã độc
        self.malware_info = {
            '1': {
                'name': 'Benign (An toàn)',
                'icon': '🟢',
                'color': 'green',
                'risk': 'THẤP',
                'action': '✅ Không cần xử lý'
            },
            '2': {
                'name': 'Adware (Quảng cáo độc hại)',
                'icon': '📢',
                'color': 'yellow',
                'risk': 'TRUNG BÌNH',
                'action': '⚠️ Cân nhắc gỡ cài đặt'
            },
            '3': {
                'name': 'Banking Malware (Mã độc ngân hàng)',
                'icon': '🏦',
                'color': 'red',
                'risk': 'RẤT CAO',
                'action': '🔴 Gỡ NGAY lập tức!'
            },
            '4': {
                'name': 'SMS Malware (Mã độc tin nhắn)',
                'icon': '💬',
                'color': 'red',
                'risk': 'RẤT CAO',
                'action': '🔴 Gỡ NGAY lập tức!'
            },
            '5': {
                'name': 'Riskware (Phần mềm rủi ro)',
                'icon': '⚠️',
                'color': 'yellow',
                'risk': 'CAO',
                'action': '⚠️ Thận trọng khi sử dụng'
            }
        }
        
        print("="*60)
    
    def preprocess(self, csv_path):
        """Tiền xử lý file CSV"""
        print(f"\n📂 Đang đọc file: {csv_path}")
        
        # Đọc file
        df = pd.read_csv(csv_path, low_memory=False)
        print(f"   Số dòng: {df.shape[0]:,}")
        print(f"   Số cột: {df.shape[1]}")
        
        # Loại bỏ cột nhãn nếu có
        for col in df.columns:
            if col.lower() in ['class', 'category', 'label', 'type']:
                df = df.drop(columns=[col])
                print(f"   ⚠️ Đã loại bỏ cột nhãn: {col}")
                break
        
        # Chuyển đổi dữ liệu sang số
        for col in df.columns:
            if df[col].dtype == 'object':
                df[col] = pd.to_numeric(df[col], errors='coerce').fillna(0)
        
        # Xử lý giá trị thiếu
        df = df.fillna(0).replace([np.inf, -np.inf], 0)
        
        # Đảm bảo số cột khớp với lúc train
        n_features = self.scaler.mean_.shape[0]
        if df.shape[1] > n_features:
            df = df.iloc[:, :n_features]
            print(f"   ⚠️ Đã cắt bớt còn {n_features} cột")
        elif df.shape[1] < n_features:
            for i in range(n_features - df.shape[1]):
                df[f'dummy_{i}'] = 0
            print(f"   ⚠️ Đã thêm {n_features - df.shape[1]} cột giả")
        
        return df
    
    def predict(self, csv_path):
        """Dự đoán từ file CSV"""
        df = self.preprocess(csv_path)
        
        # Chuẩn hóa
        print("   Đang chuẩn hóa dữ liệu...")
        X_scaled = self.scaler.transform(df)
        
        # Dự đoán
        print("   Đang dự đoán bằng AI...")
        predictions = self.model.predict(X_scaled)
        probabilities = self.model.predict_proba(X_scaled)
        
        return predictions, probabilities
    
    def filter_result(self, prediction, probability):
        """
        BỘ LỌC: Chuyển số (0-4) thành ngôn ngữ con người
        """
        class_key = str(prediction + 1)
        info = self.malware_info.get(class_key, self.malware_info['1'])
        confidence = probability[prediction] * 100
        
        return {
            'class_code': prediction,
            'class_name': info['name'],
            'icon': info['icon'],
            'risk_level': info['risk'],
            'confidence': confidence,
            'action': info['action'],
            'is_malware': class_key != '1'
        }
    
    def scan_and_report(self, csv_path, show_details=True, limit=20):
        """
        Quét file và in báo cáo
        """
        print("\n" + "="*70)
        print("📊 KẾT QUẢ PHÂN TÍCH")
        print("="*70)
        
        # Dự đoán
        predictions, probabilities = self.predict(csv_path)
        
        # Thống kê tổng quan
        unique, counts = np.unique(predictions, return_counts=True)
        
        print(f"\n📈 THỐNG KÊ TỔNG QUAN:")
        print(f"   Tổng số mẫu: {len(predictions):,}")
        
        for code, count in zip(unique, counts):
            class_key = str(code + 1)
            info = self.malware_info.get(class_key, self.malware_info['1'])
            percent = count / len(predictions) * 100
            if class_key == '1':
                print(f"   {info['icon']} {info['name']}: {count:,} ({percent:.1f}%)")
            else:
                print(f"   {info['icon']} {info['name']}: {count:,} ({percent:.1f}%)")
        
        # Chi tiết từng mẫu
        if show_details:
            print(f"\n🔍 CHI TIẾT {min(limit, len(predictions))} MẪU ĐẦU TIÊN:")
            print("-"*60)
            
            for i in range(min(limit, len(predictions))):
                result = self.filter_result(predictions[i], probabilities[i])
                
                print(f"\n📱 Mẫu #{i+1}:")
                print(f"   {result['icon']} Kết quả: {result['class_name']}")
                print(f"   🎯 Độ tin cậy: {result['confidence']:.2f}%")
                print(f"   ⚠️ Mức độ rủi ro: {result['risk_level']}")
                print(f"   💡 Khuyến nghị: {result['action']}")
        
        # Kết luận
        print("\n" + "="*70)
        malware_count = sum(1 for code in predictions if code != 0)
        if malware_count > 0:
            print(f"🔴 KẾT LUẬN: PHÁT HIỆN {malware_count:,}/{len(predictions):,} MẪU MÃ ĐỘC!")
            print("🔴 HÀNH ĐỘNG KHUYẾN NGHỊ:")
            print("   1. Gỡ cài đặt ngay các ứng dụng Banking/SMS Malware")
            print("   2. Cân nhắc gỡ ứng dụng Adware/Riskware")
            print("   3. Quét lại thiết bị bằng phần mềm diệt virus")
        else:
            print("🟢 KẾT LUẬN: TẤT CẢ MẪU ĐỀU AN TOÀN!")
            print("🟢 Không phát hiện mã độc nào.")
        print("="*70)
        
        return predictions, probabilities
    
    def export_report(self, csv_path, output_path='report.json'):
        """Xuất báo cáo ra file JSON"""
        import json
        
        predictions, probabilities = self.predict(csv_path)
        
        results = []
        for i, (pred, prob) in enumerate(zip(predictions, probabilities)):
            result = self.filter_result(pred, prob)
            results.append({
                'sample_id': i + 1,
                'prediction': result['class_name'],
                'confidence': result['confidence'],
                'risk_level': result['risk_level'],
                'is_malware': result['is_malware']
            })
        
        report = {
            'timestamp': datetime.now().isoformat(),
            'file': csv_path,
            'total_samples': len(predictions),
            'malware_count': sum(1 for r in results if r['is_malware']),
            'results': results
        }
        
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        
        print(f"\n✅ Đã xuất báo cáo ra file: {output_path}")
        return report


# ============ PHẦN CHẠY TỪ TERMINAL ============
if __name__ == "__main__":
    print("""
    ╔══════════════════════════════════════════════════════════════════╗
    ║     🛡️  SMART FILTER - PHÁT HIỆN & PHÂN LOẠI MÃ ĐỘC            ║
    ║                                                                  ║
    ║     ✓ Phát hiện: Có phải mã độc không? (Malware/Benign)         ║
    ║     ✓ Phân loại: Adware, Banking, SMS, Riskware                 ║
    ║     ✓ Hỗ trợ file CSV từ CICMalDroid2020                        ║
    ╚══════════════════════════════════════════════════════════════════╝
    """)
    
    if len(sys.argv) < 2:
        print("📖 CÁCH SỬ DỤNG:")
        print("   python smart_filter.py <đường_dẫn_file_csv>")
        print("")
        print("📝 VÍ DỤ:")
        print("   python smart_filter.py dataset/processed/sample.csv")
        print("")
        print("💡 TÙY CHỌN:")
        print("   --export-json : Xuất báo cáo ra file JSON")
        print("   --no-details  : Chỉ hiển thị thống kê, không hiển thị chi tiết")
        print("")
        print("📁 FILE CÓ SẴN TRONG THƯ MỤC:")
        print("   dataset/processed/feature_vectors_syscallsbinders_frequency_5_Cat.csv")
    else:
        file_to_scan = sys.argv[1]
        export_json = '--export-json' in sys.argv
        show_details = '--no-details' not in sys.argv
        
        try:
            # Khởi tạo bộ lọc
            filter_tool = SmartFilter()
            
            # Quét và báo cáo
            filter_tool.scan_and_report(file_to_scan, show_details=show_details)
            
            # Xuất JSON nếu yêu cầu
            if export_json:
                filter_tool.export_report(file_to_scan)
            
        except Exception as e:
            print(f"\n❌ LỖI: {e}")
            sys.exit(1)