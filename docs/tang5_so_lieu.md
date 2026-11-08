# Tầng 5 — Số liệu

Chỉ gồm số liệu đọc/tính trực tiếp từ các file kết quả có sẵn trong thư mục dự án; mỗi bảng ghi file nguồn và 12 ký tự đầu sha256 của file tại thời điểm sinh. Số liệu không có trong file ghi "không có trong file". Lưu ý: `dataset/processed/` bị .gitignore chặn, các file nguồn trong đó không nằm trong git; `reports/` có trong git.

## 1. Dữ liệu và mẫu bị loại

| lớp | static_features.csv | oof_layer1.csv (L1 OOF) |
|---|---|---|
| Benign | 70 | 70 |
| Adware | 15 | 15 |
| Banking | 19 | 19 |
| SMS | 13 | 13 |
| Riskware | 23 | 22 |
| Malware | 5 | 0 |

Tổng: static_features.csv = 145 mẫu; oof_layer1.csv = 139 mẫu.

Mẫu có trong static_features.csv nhưng không có trong oof_layer1.csv:

| sha256[:8] | label | tổng opcode__* |
|---|---|---|
| 2ace553d | Malware | 0.3658 |
| 69a1d8dc | Malware | 0.5731 |
| 895a9274 | Malware | 0.6997 |
| ad613fc8 | Malware | 0.5926 |
| cf178e04 | Malware | 0.6821 |
| 3c0edd3c | Riskware | 0.0 |

_Nguồn: `dataset/processed/static_features.csv` (sha256 228c720eba85…), `dataset/processed/oof_layer1.csv` (sha256 d356c641b1b4…)_

## 2. L1 out-of-fold (5 lớp)

| chỉ số | giá trị | n |
|---|---|---|
| accuracy 5 lớp (argmax p_*) | 0.863 | 139 |
| macro-F1 5 lớp | 0.791 | 139 |
| accuracy nhị phân (P(độc)=1-p_Benign >= 0.5) | 0.978 | 139 |
| kiểm tra permutation (oof_scores.py --permute, seed mặc định 42, 1 lần xáo trộn) | OOF accuracy sau xáo trộn nhãn = 0.374; mức ngẫu nhiên kỳ vọng (tổng p_i^2) = 0.318; baseline lớp đa số = 0.504 (`reports/oof_permute.txt`) | 139 |
| số fold (cột fold) | 5 (0: 28 mẫu, 1: 28 mẫu, 2: 28 mẫu, 3: 28 mẫu, 4: 27 mẫu) | 139 |

| lớp | n | precision | recall | F1 |
|---|---|---|---|---|
| Benign | 70 | 0.958 | 0.986 | 0.972 |
| Adware | 15 | 0.765 | 0.867 | 0.812 |
| Banking | 19 | 0.611 | 0.579 | 0.595 |
| SMS | 13 | 0.75 | 0.692 | 0.72 |
| Riskware | 22 | 0.9 | 0.818 | 0.857 |

_Nguồn: `dataset/processed/oof_layer1.csv` (sha256 d356c641b1b4…), `reports/oof_permute.txt` (sha256 6f769b53f179…)_

## 3. Ablation theo tầng và chẩn đoán thời đại

| hang | cach_tinh | n | n_khong_xac_dinh | accuracy [CI 95%] | recall_doc | recall_sach | AUC [CI 95%] | acc_ho_tham_khao |
|---|---|---|---|---|---|---|---|---|
| L1 | weighted_vote | 139 | 0 | 0.978 [0.95–1.0] | 0.971 | 0.986 | 0.998 [0.993–1.0] | 52/67 |
| L2 | điểm thô của tầng >= T_MAL (weighted_vote cần L1/L4 bỏ phiếu) | 139 | 0 | 0.475 [0.396–0.554] | 0.261 | 0.686 | 0.497 [0.402–0.593] |  |
| L3 | điểm thô của tầng >= T_MAL (weighted_vote cần L1/L4 bỏ phiếu) | 139 | 0 | 0.727 [0.654–0.799] | 0.449 | 1.0 | 0.968 [0.941–0.988] |  |
| L1+L2 | weighted_vote | 139 | 0 | 0.978 [0.95–1.0] | 0.971 | 0.986 | 0.998 [0.992–1.0] | 52/67 |
| L1+L3 | weighted_vote | 139 | 0 | 0.978 [0.95–1.0] | 0.971 | 0.986 | 0.998 [0.993–1.0] | 52/67 |
| L1+L2+L3 | weighted_vote | 139 | 0 | 0.978 [0.95–1.0] | 0.971 | 0.986 | 0.998 [0.993–1.0] | 52/67 |
| Đầy đủ L1+L2+L3+L4 | weighted_vote | 139 | 0 | 0.978 [0.95–1.0] | 0.971 | 0.986 | 0.998 [0.993–1.0] | 52/67 |
| Chẩn đoán thời đại: chỉ min_sdk+target_sdk | RandomForest(300 cây, min_samples_leaf=2) 5 lớp, fold của oof_layer1 (nhóm package_name) | 139 | 0 | 0.777 [0.705–0.842] | 0.783 | 0.771 | 0.88 [0.815–0.932] | 36/54 |

Số mẫu đúng/đã quyết định theo lớp:

| hang | n_theo_lop | dung_theo_lop |
|---|---|---|
| L1 | Benign=70; Adware=15; Banking=19; SMS=13; Riskware=22 | Benign=69/70; Adware=15/15; Banking=17/19; SMS=13/13; Riskware=22/22 |
| L2 | Benign=70; Adware=15; Banking=19; SMS=13; Riskware=22 | Benign=48/70; Adware=10/15; Banking=5/19; SMS=2/13; Riskware=1/22 |
| L3 | Benign=70; Adware=15; Banking=19; SMS=13; Riskware=22 | Benign=70/70; Adware=4/15; Banking=6/19; SMS=8/13; Riskware=13/22 |
| L1+L2 | Benign=70; Adware=15; Banking=19; SMS=13; Riskware=22 | Benign=69/70; Adware=15/15; Banking=17/19; SMS=13/13; Riskware=22/22 |
| L1+L3 | Benign=70; Adware=15; Banking=19; SMS=13; Riskware=22 | Benign=69/70; Adware=15/15; Banking=17/19; SMS=13/13; Riskware=22/22 |
| L1+L2+L3 | Benign=70; Adware=15; Banking=19; SMS=13; Riskware=22 | Benign=69/70; Adware=15/15; Banking=17/19; SMS=13/13; Riskware=22/22 |
| Đầy đủ L1+L2+L3+L4 | Benign=70; Adware=15; Banking=19; SMS=13; Riskware=22 | Benign=69/70; Adware=15/15; Banking=17/19; SMS=13/13; Riskware=22/22 |
| Chẩn đoán thời đại: chỉ min_sdk+target_sdk | Benign=70; Adware=15; Banking=19; SMS=13; Riskware=22 | Benign=54/70; Adware=15/15; Banking=8/19; SMS=11/13; Riskware=20/22 |

Bootstrap: seed = 42, số lần = 1000 (cột boot_seed, boot_n). Ghi chú từng hàng:

| hang | ghi_chu |
|---|---|
| L1 |  |
| L2 |  |
| L3 | L3 đã gồm làm rối, không độc lập với L2 |
| L1+L2 |  |
| L1+L3 | L3 đã gồm làm rối, không độc lập với L2 |
| L1+L2+L3 | L3 đã gồm làm rối, không độc lập với L2 |
| Đầy đủ L1+L2+L3+L4 | L3 đã gồm làm rối, không độc lập với L2 \| L4 vắng (n=0), không điền 0 -> trùng L1+L2+L3 |
| Chẩn đoán thời đại: chỉ min_sdk+target_sdk | 136 nhóm / 139 mẫu nên gần như không khác chia ngẫu nhiên; không có cột họ/chiến dịch; nhãn lớp trùng nguồn tải (Adware = tar.gz cũ, Banking/Riskware/SMS = MalwareBazaar mới, Benign = F-Droid) |

_Nguồn: `reports/ablation.csv` (sha256 1171926dc2dc…)_

## 4. L3 (rule_score, thang 0–100)

| lớp | n | min | trung vị | max |
|---|---|---|---|---|
| Benign | 70 | 2.8 | 12.6 | 36.0 |
| Adware | 15 | 19.0 | 45.0 | 79.0 |
| Banking | 19 | 14.0 | 45.0 | 74.0 |
| SMS | 13 | 18.0 | 62.0 | 72.0 |
| Riskware | 22 | 20.0 | 66.5 | 70.0 |

Mẫu độc có rule_score <= max của mẫu sạch (36): 14/69.

| tập | n | Spearman rho (rule_score, min_sdk) | p |
|---|---|---|---|
| toàn bộ | 139 | -0.18 | 0.034 |
| Benign | 70 | 0.3 | 0.011 |
| Adware | 15 | -0.23 | 0.414 |
| Banking | 19 | -0.2 | 0.412 |
| SMS | 13 | -0.39 | 0.194 |
| Riskware | 22 | -0.35 | 0.115 |

_Nguồn: `dataset/processed/l2l3_scores.csv` (sha256 1a0889ed2fb8…)_

## 5. Bảng nhạy trọng số — CHỈ để xem độ nhạy, KHÔNG dùng để chọn trọng số

| hang | trong_so | n | accuracy [CI 95%] | recall_doc | recall_sach | AUC [CI 95%] | dung_theo_lop |
|---|---|---|---|---|---|---|---|
| L1+L3 (w_L2=w_L3=0.05) | L1=0.45 L3=0.05 | 139 | 0.978 [0.95–1.0] | 0.971 | 0.986 | 0.998 [0.993–1.0] | Benign=69/70; Adware=15/15; Banking=17/19; SMS=13/13; Riskware=22/22 |
| L1+L2+L3 (w_L2=w_L3=0.05) | L1=0.45 L2=0.05 L3=0.05 | 139 | 0.978 [0.95–1.0] | 0.971 | 0.986 | 0.998 [0.993–1.0] | Benign=69/70; Adware=15/15; Banking=17/19; SMS=13/13; Riskware=22/22 |
| L1+L3 (w_L2=w_L3=0.15) | L1=0.45 L3=0.15 | 139 | 0.978 [0.95–1.0] | 0.971 | 0.986 | 0.998 [0.994–1.0] | Benign=69/70; Adware=15/15; Banking=17/19; SMS=13/13; Riskware=22/22 |
| L1+L2+L3 (w_L2=w_L3=0.15) | L1=0.45 L2=0.15 L3=0.15 | 139 | 0.964 [0.928–0.993] | 0.942 | 0.986 | 0.997 [0.988–1.0] | Benign=69/70; Adware=15/15; Banking=16/19; SMS=13/13; Riskware=21/22 |
| L1+L3 (w_L2=w_L3=0.30) | L1=0.45 L3=0.30 | 139 | 0.978 [0.95–1.0] | 0.971 | 0.986 | 0.998 [0.994–1.0] | Benign=69/70; Adware=15/15; Banking=17/19; SMS=13/13; Riskware=22/22 |
| L1+L2+L3 (w_L2=w_L3=0.30) | L1=0.45 L2=0.30 L3=0.30 | 139 | 0.892 [0.835–0.942] | 0.797 | 0.986 | 0.986 [0.962–1.0] | Benign=69/70; Adware=15/15; Banking=12/19; SMS=10/13; Riskware=18/22 |

_Nguồn: `reports/ablation.csv` (sha256 1171926dc2dc…)_

## 6. Hạn chế

| hạn chế | số liệu | nguồn |
|---|---|---|
| Nhãn lớp trùng nguồn tải | Trích `reports/ablation_notes.txt` mục 1: "ĐÂY LÀ MINH HỌA PHƯƠNG PHÁP, KHÔNG CÓ Ý NGHĨA THỐNG KÊ. n=139 (Benign=70, Adware=15, Banking=19, SMS=13, Riskware=22). Điểm L1 là out-of-fold nhưng vẫn chịu nhiễu nguồn/thời đại: nhãn lớp trùng với nguồn tải (Adware = tar.gz cũ, Banking/Riskware/SMS = MalwareBazaar mới, Benign = F-Droid), nên con số cao có thể phản ánh "nhận ra nguồn" chứ không phải hành vi." | reports/ablation_notes.txt |
| Không có cột họ/chiến dịch | Cột khớp family/campaign trong static_features.csv: không có. Số nhóm package_name (tính cả giá trị trống) trong oof_layer1.csv: 136 nhóm / 139 mẫu; 1 mẫu thiếu package_name. | dataset/processed/static_features.csv, dataset/processed/oof_layer1.csv |
| Luật E2 chưa kích hoạt trên 139 mẫu | rule_score cao nhất = 79; ngưỡng E2 = T_HIGH×100 = 80; số mẫu >= ngưỡng = 0. | dataset/processed/l2l3_scores.csv, scanner/meta_arbiter.py |
| L4 vắng | n = 0 (ablation_notes.txt mục 2: "L4 vắng (n=0)"); hàng 'Đầy đủ L1+L2+L3+L4' trùng 'L1+L2+L3'. | reports/ablation_notes.txt |
| L2 là xấp xỉ, trọng số 0 trong arbitrate | L2 = obfuscated_class_ratio; ARBITRATE_WEIGHTS = {'L1': 0.45, 'L4': 0.45, 'L2': 0.0, 'L3': 0.05}; AUC L2 (điểm thô) = 0.497. | scanner/meta_arbiter.py, reports/ablation.csv |
| Stacking với một tầng L1 cho kết quả âm | L1 thô (OOF): accuracy 0.863, macro-F1 0.791, log-loss 0.420; Meta LR (CV lồng): accuracy 0.835, macro-F1 0.753, log-loss 0.501; nhị phân — L1 thô: độc bắt được 67/69, sạch bị báo nhầm 1/70; Meta LR: độc bắt được 69/69, sạch bị báo nhầm 4/70; Meta CV accuracy sau xáo trộn nhãn: 0.180 (mức ngẫu nhiên kỳ vọng in trong file: 0.318). stacking.py seed mặc định 7. | reports/stacking_l1.txt, reports/stacking_permute.txt |

_Nguồn: `reports/ablation_notes.txt` (sha256 1be7f6a70371…), `dataset/processed/l2l3_scores.csv` (sha256 1a0889ed2fb8…), `scanner/meta_arbiter.py` (sha256 86a833fc8746…), `reports/stacking_l1.txt` (sha256 af19e31e605c…), `reports/stacking_permute.txt` (sha256 6fe0c40fc2d6…)_

Thông số XGBoost/huấn luyện chưa đồng bộ (đọc từ mã nguồn, không phải file kết quả):

| tham số (trích bằng regex) | scanner/oof_scores.py (sinh L1 OOF) | train_static_model.py (static_model.pkl) |
|---|---|---|
| n_estimators | 200 | 300 |
| max_depth | 4 | 6 |
| learning_rate | 0.1 | 0.1 |
| subsample | 0.8 | 0.9 |
| colsample_bytree | 0.8 | 0.9 |
| objective | multi:softprob | (không đặt → mặc định) |
| eval_metric | mlogloss | mlogloss |
| tree_method | hist | (không đặt → mặc định) |
| random_state | 42 | 42 |
| có gọi SMOTE | có | không |
| có gọi compute_sample_weight | không | có |
| có gọi StratifiedGroupKFold | có | không |
| có gọi train_test_split | không | có |
| test_size | — | 0.2 |

_Nguồn: `scanner/oof_scores.py` (sha256 37c964843145…), `train_static_model.py` (sha256 dc73c5991934…)_

