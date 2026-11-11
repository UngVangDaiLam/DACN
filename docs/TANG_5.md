# Tầng 5 — Bộ trọng tài xác nhận chéo theo họ bằng chứng

Cập nhật: 11/11/2026. Người làm: Lâm. Dựng trên nhánh `gop-an-20261111` (commit `c628aef`).

## 0. Quan hệ với phần Tầng 5 đã có

- `scanner/meta_arbiter.py` (`arbitrate`, `arbitrate_from_results`): **bỏ phiếu có trọng số**, đang là
  khối "Tầng 5 — Kết luận tổng hợp" trên web (`result['tang5']`). Số liệu thật của nó ở
  `docs/tang5_so_lieu.md` (n = 139, Benign 70). **Không bị sửa.**
- Tài liệu này mô tả phần **thêm vào**: trọng tài xác nhận chéo theo họ (phương pháp chính của đề
  cương), xuất ở `result['arbiter']` và hiện thành một khối riêng ngay dưới khối trên. `result['verdict']`
  (`combine_verdict`) giữ nguyên. Khối nào là kết luận chính trên giao diện: nhóm chưa chốt.
- Trong `scanner/eval_fusion.py`, dòng "Bỏ phiếu có trọng số (baseline)" dùng trọng số
  A 0,45 / B 0,10 trên điểm họ; nó **không** phải `meta_arbiter.arbitrate` (dùng `rule_score`, L2 = 0).
  Số của `meta_arbiter` lấy từ `scanner/evaluate_ablation.py`.

## 1. Ý tưởng

Không cộng điểm thô giữa các tầng. Bằng chứng được gom thành **ba họ độc lập**, mỗi họ cho một
điểm trong [0, 1]:

| Họ | Nguồn | Điểm |
|---|---|---|
| A — Cấu trúc tĩnh | Tầng 1 | `1 − P(Benign)` của mô hình |
| B — Hành vi trong mã | Tầng 2 + Tầng 3 | Gộp theo `capability` (mỗi năng lực tính một lần), noisy-OR có trần (`family_scores.py`) |
| C — Hành vi động | Tầng 4 | Chưa có; hợp đồng: `{"score": 0..1, "evidence": [{"capability": ...}], "partial": bool}` |

Luật kết luận (`family_arbiter.decide_level`):

| Tình huống | Mức | Hành động đề nghị |
|---|---|---|
| ≥ 2 họ cùng vượt ngưỡng | Nguy hiểm | Gỡ / thu hồi quyền (người dùng xác nhận) |
| 1 họ vượt ngưỡng mạnh | Đáng ngờ | Đưa sang Tầng 4 |
| 1 họ vượt ngưỡng yếu | Cần lưu ý | Theo dõi, xem lại quyền |
| Không họ nào vượt, A và B đầy đủ | An toàn | Không |
| Không họ nào vượt, A/B vắng mặt hoặc bị cắt | Chưa đủ bằng chứng | Phân tích lại / Tầng 4 |

Quy tắc an toàn: họ vắng mặt **không** được tính là sạch; điểm họ B bị cắt (Tầng 2 chỉ giữ 100
bằng chứng) được dùng như **cận dưới**; APK bị làm méo manifest/zip không bao giờ ra An toàn.

## 2. Ngưỡng

- Mặc định (đề xuất, chưa hiệu chỉnh): A 0,60 / 0,85; B 0,50 / 0,75; C 0,50 / 0,75.
- Hiệu chỉnh: `scanner/calibrate_arbiter.py` chọn ngưỡng **chỉ từ điểm của mẫu sạch**: ngưỡng yếu
  là ngưỡng nhỏ nhất để không quá 5% mẫu sạch vượt, ngưỡng mạnh 1%. Ghi
  `models/arbiter_thresholds.json`; trọng tài tự đọc file này, giao diện ghi rõ đã hiệu chỉnh
  trên bao nhiêu mẫu sạch và nguồn nào.
- Họ không đủ mẫu sạch có điểm (hiện là họ C) không được ghi, vẫn dùng giá trị đề xuất.

## 3. Ngữ cảnh cài đặt

`family_arbiter.build_context(deep, device)` → điều chỉnh điểm mỗi họ có mặt, tổng bị chặn trong
[−0,15; +0,10]:

| Yếu tố | Điều chỉnh | Nguồn |
|---|---|---|
| Cài từ kho tin cậy | −0,05 | Thiết bị (ADB) — chưa nối |
| Chữ ký nhà phát triển đã biết | −0,10 | `models/known_signers.json` (đang rỗng) |
| Đã dùng ≥ 90 ngày | −0,05 | Thiết bị (ADB) — chưa nối |
| Khai báo dịch vụ trợ năng | +0,05 | Manifest |
| Khai báo quản trị thiết bị | +0,05 | Manifest |

Thông tin không có = "chưa biết", không điều chỉnh. APK bị làm méo không được giảm điểm.
Các hệ số là đề xuất. Lưu ý: Tầng 1 cũng có đặc trưng quyền trợ năng/quản trị, nên phần tăng điểm
có thể trùng một phần với họ A — đã giới hạn ở mức nhỏ, cần nêu trong báo cáo.

## 4. Thí nghiệm

Chạy theo thứ tự (PowerShell, ở gốc repo):

```powershell
.\venv\Scripts\python.exe scanner\oof_scores.py                 # điểm họ A (out-of-fold)
.\venv\Scripts\python.exe scanner\score_family_b.py             # điểm họ B (có cache)
.\venv\Scripts\python.exe scanner\calibrate_arbiter.py          # xem ngưỡng; thêm --write để ghi
.\venv\Scripts\python.exe scanner\eval_fusion.py                # CV nhóm, 5 lần lặp
.\venv\Scripts\python.exe scanner\eval_fusion.py --split family # giữ riêng từng lớp mã độc
.\venv\Scripts\python.exe scanner\eval_fusion.py --split time   # cần cột ngay trong malware_manifest.csv
.\venv\Scripts\python.exe scanner\eval_fusion.py --permute      # kiểm tra rò rỉ: mô hình học phải về AUC ~ 0,5
```

`score_family_b.py` phải chạy lại một lần sau bản cập nhật này để có cột `observed_score_b`
(dùng cache nên nhanh); nếu không, các mẫu bị cắt bằng chứng sẽ bị coi là thiếu họ B.

`eval_fusion.py` ghi vào `reports\layer5\`:

- `fusion_report_<split>.md`, `fusion_metrics_<split>.csv`: Accuracy, Precision, Recall, F1,
  tỉ lệ báo động giả, AUC cho: từng tầng đơn lẻ, HOẶC, VÀ, bỏ phiếu đa số, cộng điểm có giới hạn
  theo họ, bỏ phiếu có trọng số (`meta_arbiter`, baseline), xác nhận chéo theo họ (3 điểm cắt),
  ablation bỏ từng họ, Logistic Regression và LightGBM học trên điểm các họ.
- `levels_by_label.csv`: phân bố 4 mức theo lớp.
- `error_correlation.json`: hai họ A, B báo/sai trên cùng mẫu hay khác mẫu (phi, Yule Q).
- `fusion_per_heldout_class.csv`: recall trên lớp mã độc bị giữ riêng.

Chống ảo tưởng: ngưỡng và mô hình học chỉ chọn trên fold train; chia fold theo nhóm package;
điểm họ A là out-of-fold; luôn in số mẫu thật từng lớp.

## 5. Tệp

| Tệp | Vai trò |
|---|---|
| `scanner/family_arbiter.py` | Trọng tài: điểm họ, ngưỡng, ngữ cảnh, luật, hành động |
| `scanner/family_scores.py`, `scanner/capabilities.py` | Điểm họ B, danh sách năng lực |
| `scanner/fusion_common.py` | Bảng điểm mỗi mẫu, chọn ngưỡng, các cách kết hợp |
| `scanner/calibrate_arbiter.py` | Hiệu chỉnh ngưỡng trên tập sạch |
| `scanner/eval_fusion.py` | So sánh cách kết hợp, ablation, tương quan lỗi, mô hình học |
| `scanner/pipeline_runner.py` | Thêm khối `arbiter` vào báo cáo (không đổi `verdict`) |
| `scanner/score_family_b.py` | Thêm cột `observed_score_b`, `status_b` |
| `models/known_signers.json` | Danh sách chữ ký đã biết (nhóm tự điền) |
| `tests/test_family_arbiter.py`, `tests/test_fusion.py`, `tests/test_arbiter_ui.cjs` | Kiểm thử |

Báo cáo quét có thêm `arbiter` (mức, hành động, từng họ, lý do, ngữ cảnh, thông tin ngưỡng).
Lỗi khi tính → `arbiter = {"error": ...}`, không làm hỏng lượt quét.

## 6. Chưa làm được và giới hạn

- **Con số thật chưa có.** Mọi script đã chạy thử trên bảng điểm giả lập; kết quả thật phải chạy
  trên tập mẫu của nhóm. Không dùng số giả lập trong báo cáo.
- **Tập sạch chỉ từ F-Droid**: ngưỡng hiệu chỉnh trên đó có thể không đúng với app Google Play.
  File ngưỡng ghi rõ nguồn; cần hiệu chỉnh lại khi có AndroZoo.
- **139 mẫu (Benign 70, độc 69), nhãn trùng nguồn tải, chưa có ngày**: chia theo thời gian chưa
  chạy được; khoảng tin cậy rộng. Với 70 mẫu sạch, mục tiêu 5% nghĩa là tối đa 3 mẫu sạch vượt
  ngưỡng, còn ngưỡng mạnh 1% sẽ nằm ngay trên điểm sạch cao nhất (cần ≥ 100 mẫu sạch mới có nghĩa).
- **Danh sách 5 lớp vẫn viết cứng** ở `meta_arbiter.py`, `oof_scores.py`, `stacking.py` (chưa gom).
- **Họ C vắng mặt**: Nguy hiểm chỉ đạt được khi A và B cùng vượt; ablation hiện chỉ có hai họ.
- **Ngữ cảnh nguồn cài và thời gian dùng** cần đọc từ thiết bị qua ADB; chưa nối. Ngữ cảnh chưa
  tham gia `eval_fusion.py` vì bảng điểm không có các cột này.
- **Phân loại nhiều cấp** (loại/họ mã độc) chưa làm; trọng tài hiện chỉ ra mức rủi ro và năng lực.
