# src/train_complete.py
"""
HUẤN LUYỆN AI PHÁT HIỆN & PHÂN LOẠI MÃ ĐỘC ANDROID
"""

import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, accuracy_score, confusion_matrix
import joblib
import os
import warnings
warnings.filterwarnings('ignore')

print("="*70)
print("🦾 HỆ THỐNG HUẤN LUYỆN AI - PHÁT HIỆN & PHÂN LOẠI MÃ ĐỘC")
print("="*70)

# ============ 1. ĐỌC DỮ LIỆU ============
print("\n📂 BƯỚC 1: Đọc dữ liệu...")

file_path = 'dataset/processed/feature_vectors_syscallsbinders_frequency_5_Cat.csv'

if not os.path.exists(file_path):
    file_path = 'dataset/raw/feature_vectors_syscallsbinders_frequency_5_Cat.csv'
    if not os.path.exists(file_path):
        print(f"❌ LỖI: Không tìm thấy file CSV!")
        exit(1)

print(f"✅ Đã tìm thấy: {file_path}")
print("⏳ Đang đọc file...")
df = pd.read_csv(file_path, low_memory=False)
print(f"✅ Đọc thành công! {df.shape[0]:,} dòng, {df.shape[1]} cột")

# ============ 2. XÁC ĐỊNH CỘT NHÃN ============
print("\n🏷️ BƯỚC 2: Xác định cột nhãn...")

label_col = None
for col in df.columns:
    if col.lower() in ['class', 'category', 'label', 'type']:
        label_col = col
        break

if label_col is None:
    label_col = df.columns[-1]

print(f"✅ Cột nhãn: {label_col}")

unique_labels = df[label_col].unique()
print(f"📋 Các loại nhãn: {list(unique_labels)} ({len(unique_labels)} loại)")

# ============ 3. TÁCH FEATURES VÀ LABELS ============
print("\n🔧 BƯỚC 3: Tách đặc trưng và nhãn...")

X = df.drop(columns=[label_col])
y = df[label_col]

print(f"✅ Số đặc trưng: {X.shape[1]:,}")
print(f"✅ Số mẫu: {len(y):,}")

# ============ 4. TIỀN XỬ LÝ ============
print("\n🧹 BƯỚC 4: Tiền xử lý dữ liệu...")

for col in X.columns:
    if X[col].dtype == 'object':
        X[col] = pd.to_numeric(X[col], errors='coerce').fillna(0)

X = X.fillna(0).replace([np.inf, -np.inf], 0)
print("   ✅ Hoàn tất")

# ============ 5. MÃ HÓA NHÃN ============
print("\n🔢 BƯỚC 5: Mã hóa nhãn...")

label_encoder = LabelEncoder()
y_encoded = label_encoder.fit_transform(y)

class_names = [str(name) for name in label_encoder.classes_]
print("   📋 Ánh xạ:")
for i, name in enumerate(class_names):
    print(f"      {i} → {name}")

# ============ 6. CHIA DỮ LIỆU ============
print("\n✂️ BƯỚC 6: Chia dữ liệu train/test...")

X_train, X_test, y_train, y_test = train_test_split(
    X, y_encoded, test_size=0.2, random_state=42, stratify=y_encoded
)

print(f"✅ Train: {len(X_train):,} mẫu (80%)")
print(f"✅ Test: {len(X_test):,} mẫu (20%)")

# ============ 7. CHUẨN HÓA ============
print("\n⚙️ BƯỚC 7: Chuẩn hóa dữ liệu...")

scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train)
X_test_scaled = scaler.transform(X_test)
print("✅ Đã chuẩn hóa")

# ============ 8. HUẤN LUYỆN ============
print("\n🧠 BƯỚC 8: Huấn luyện Random Forest...")

model = RandomForestClassifier(
    n_estimators=100, max_depth=20, min_samples_split=5,
    random_state=42, n_jobs=-1, verbose=0
)

model.fit(X_train_scaled, y_train)
print("✅ Huấn luyện hoàn tất!")

# ============ 9. ĐÁNH GIÁ ============
print("\n📊 BƯỚC 9: Đánh giá model...")

y_pred = model.predict(X_test_scaled)
accuracy = accuracy_score(y_test, y_pred)

print(f"\n🎯 ĐỘ CHÍNH XÁC: {accuracy:.2%}")

print("\n📋 BÁO CÁO CHI TIẾT:")
print("-" * 60)
print(classification_report(y_test, y_pred, target_names=class_names))

# ============ 10. MA TRẬN NHẦM LẪN ============
print("\n📊 MA TRẬN NHẦM LẪN:")
print("-" * 50)

cm = confusion_matrix(y_test, y_pred)

# In header
print("     " + "".join(f"{name:>6}" for name in class_names))

# In từng dòng
for i, name in enumerate(class_names):
    print(f"{name:>6} " + "".join(f"{cm[i][j]:>6}" for j in range(len(class_names))))

# ============ 11. KIỂM TRA CHÉO ============
print("\n🔄 BƯỚC 10: Kiểm tra chéo 5-fold...")

cv_scores = cross_val_score(model, X_train_scaled, y_train, cv=5, scoring='accuracy')
print(f"✅ 5-fold CV: {cv_scores.mean():.2%} (+/- {cv_scores.std()*2:.2%})")

# ============ 12. LƯU MODEL ============
print("\n💾 BƯỚC 11: Lưu model...")

os.makedirs('models', exist_ok=True)

joblib.dump(model, 'models/malware_model.pkl')
joblib.dump(scaler, 'models/scaler.pkl')
joblib.dump(label_encoder, 'models/label_encoder.pkl')
print("✅ Đã lưu 3 file .pkl vào thư mục models/")

# ============ 13. ĐẶC TRƯNG QUAN TRỌNG ============
print("\n🔍 BƯỚC 12: Top 20 đặc trưng quan trọng...")

feature_importance = model.feature_importances_
sorted_idx = np.argsort(feature_importance)[::-1]
top_20_features = X.columns[sorted_idx[:20]].tolist()

print("\n📋 TOP 20 ĐẶC TRƯNG:")
for i, f in enumerate(top_20_features):
    print(f"   {i+1}. {f}")

joblib.dump(top_20_features, 'models/top_20_features.pkl')
print("✅ Đã lưu top_20_features.pkl")

# ============ TỔNG KẾT ============
print("\n" + "="*70)
print("🎉 HUẤN LUYỆN THÀNH CÔNG!")
print(f"   Độ chính xác: {accuracy:.2%}")
print("="*70)
print("\n🚀 TIẾP THEO:")
print("   python scanner/detect_and_classify.py dataset/processed/your_file.csv")
print("   hoặc: cd web && python app.py")
print("="*70)