# Kết quả cấu hình OOF cũ (trước đồng bộ)

**OOF với SMOTE, 200/4/0,8/0,8, chưa đồng bộ với mô hình triển khai.**

- Cấu hình L1 OOF (`scanner/oof_scores.py` trước commit `e829a8b`): XGBoost `n_estimators=200`, `max_depth=4`,
  `subsample=0.8`, `colsample_bytree=0.8`, `tree_method=hist`; cân bằng lớp bằng SMOTE trên tập train của từng fold;
  StratifiedGroupKFold 5 fold theo package_name, seed 42.
- File OOF đầu vào: `dataset/processed/oof_layer1.csv`, sha256 `d356c641b1b4…` (bản lưu cục bộ
  `dataset/processed/oof_layer1.csv.bak`, bị .gitignore chặn, không có trong git).
- Các file dưới đây là bản chép nguyên vẹn từ `reports/` trước khi sinh lại bằng OOF đồng bộ. Bản gốc vẫn còn
  trong lịch sử git ở commit ghi cạnh mỗi file.

| file | commit gốc | sha256 (12 ký tự đầu) |
|---|---|---|
| ablation.csv | c924261 | 1171926dc2dc |
| ablation_notes.txt | c924261 | 1be7f6a70371 |
| oof_permute.txt | 6c604d9 | 6f769b53f179 |
| stacking_l1.txt | 6c604d9 | af19e31e605c |
| stacking_permute.txt | 6c604d9 | 6fe0c40fc2d6 |

Kết quả hiện hành (OOF đồng bộ với `train_static_model.py`) nằm ở `reports/` cấp trên.
