# Nghiệm thu chức năng Tầng 2–3 bằng APK tổng hợp

Ngày: **11/11/2026**. Bộ luật: **2.2.0**. Bộ dữ liệu: **synthetic_v1**.

## Kết luận trong phạm vi đã thống nhất

Tầng 2 và Tầng 3 có đủ kiểm chứng chức năng cho các luật tĩnh đã triển khai: sáu kỹ thuật Tầng 2 và tiêu chí API nhạy cảm + API mạng IP cùng chữ ký hàm của Tầng 3. Bộ này không chứng minh phát hiện tốt malware ngoài thực tế, giải mã payload tùy ý, hiểu mã native hoặc taint analysis liên hàm.

**24 APK được build thật**, mỗi APK có package riêng, SHA256 khác nhau, Manifest, DEX và chữ ký APK v2 đã được công cụ SDK xác minh. Mọi mẫu được ghi rõ `dataset_type=synthetic`. Không gọi chúng là malware thu thập thực tế và không gộp chỉ số với bộ APK thực.

Màn hình launcher chỉ gọi `Activity.onCreate`, không gọi các hàm probe. Không khai báo uses-permission; không receiver/service/background task. Địa chỉ POST duy nhất được viết trong mã là loopback `127.0.0.1:9`. Các hàm thử API được giữ trong bytecode để kiểm tra tĩnh; không có APK nào được cài hoặc thực thi. Chưa thử khả năng cài đặt/runtime trên thiết bị; đó không phải tiêu chí của đợt nghiệm thu tĩnh này.

## Nhãn và kết quả

| Tiêu chí | Dương | Âm | FP | FN |
|---|---:|---:|---:|---:|
| dynamic_loading | 1 | 23 | 0 | 0 |
| reflection | 3 | 21 | 0 | 0 |
| encoded_strings | 2 | 22 | 0 | 0 |
| embedded_payload | 1 | 23 | 0 | 0 |
| native_loading | 1 | 23 | 0 | 0 |
| name_obfuscation | 1 | 23 | 0 | 0 |
| Tầng 3: sensitive + IP network cùng hàm | 4 | 20 | 0 | 0 |

Tổng **168 ô nhãn xác định** trên 24 APK, coverage 100% trong bộ tổng hợp này. Đây là kết quả functional/regression trên tình huống chủ động thiết kế, không phải ước lượng accuracy/recall của mã độc thực tế. Số dương của một số kỹ thuật chỉ là 1; không đủ để chứng minh độ bao phủ tổng quát.

Các control quan trọng:

- Class.forName là reflection, không tự thành nạp DEX ngoài; Cipher xử lý tham số đầu vào không tự chứng minh chuỗi hằng được che giấu.
- DEX đổi đuôi thành ảnh là payload; ZIP animation không chứa mã thực thi là âm tính. ELF có mặt nhưng không có API load không được gán native_loading.
- R8 đổi tên 40 lớp được đối chiếu bằng mapping thật với DEX; control 40 lớp tên đọc được đi qua D8, giữ nguyên tên.
- Tầng 3 dương ở SYN14 (Location + HTTP), SYN19 (hai API ở hai nhánh khác nhau nhưng cùng hàm), SYN20 (provider nhạy cảm + HTTP), SYN23 (clipboard + WebView.postUrl).
- Tầng 3 âm khi khác hàm, khác overload, chỉ có nguồn hoặc mạng, dùng SMS, authority URI gần giống hoặc đi qua hàm gửi trung gian. Hai nhánh loại trừ nhau vẫn là dương theo định nghĩa co-occurrence, không phải bằng chứng rò rỉ.

## Cách tránh nhãn vòng tròn/dữ liệu giả

1. Thiết kế mã nguồn và candidate labels trước khi chạy bộ quét.
2. Build cục bộ bằng javac, D8/R8, aapt2, clang NDK và apksigner; không tải dependency hay chạy APK.
3. Dùng **SDK dexdump**, aapt2 và apksigner để đọc APK thực; đối chiếu source, hằng chuỗi, API/offset từng hàm, tài nguyên và mapping. Verifier không import scanner hoặc Androguard.
4. Chốt `labels.json`, CSV, nguồn và bằng chứng bằng `labels_frozen.json`: **310 tệp đầu vào** có hash. CLI trên bộ đã chốt chỉ kiểm hash, không viết lại nhãn.
5. Sau freeze mới chạy `scripts/run_benchmark.py`; lưu hash input và bộ quét trước/sau cùng hash từng báo cáo. Từ chối ghi đè baseline.
6. Có một người thực hiện thiết kế/review; chưa có người thứ hai review mù. Không che giấu giới hạn này.

Không thay đổi 206 ô unknown hoặc nhãn của các bộ APK thực trước đó. Dữ liệu ký dùng chứng chỉ thử nghiệm `StaticTestOnly`, không phải danh tính người dùng hay khóa sản xuất; keystore tạm không nằm trong bộ bàn giao.

## Tệp trong dự án

- `samples/synthetic_v1/apks/`: 24 APK gốc giữ đuôi `.apk.disabled`; `.idsig` là sidecar chữ ký, không phải mẫu bổ sung.
- `samples/synthetic_v1/source/`: Java, Manifest, C và cấu hình R8.
- `samples/synthetic_v1/evidence/`: full SDK dexdump, badging, chữ ký, mapping và review JSON có mọi API/offset.
- `samples/synthetic_v1/labels.json`, `labels.csv`, `manifest.csv`, `labels_frozen.json`, `design_contract.json`, `toolchain.json`, `build_log.json`.
- `reports/synthetic_v1_detector_v2_2/`: 24 báo cáo và evaluation.json/run_metadata.json riêng.
- `scripts/build_synthetic_suite.py`, `scripts/verify_synthetic_suite.py`, `tests/test_synthetic_suite.py`.

## Kiểm tra và tái build

Từ gốc DACN:

```powershell
# Chỉ kiểm hash trên dữ liệu đã chốt; không chạy APK hoặc sửa nhãn.
.\.venv\Scripts\python.exe -B scripts\verify_synthetic_suite.py samples\synthetic_v1

# Chạy các unittest, gồm bộ nghiệm thu tổng hợp khi sample/report có mặt.
.\.venv\Scripts\python.exe -X utf8 -B -m unittest discover -s tests -p "test_*.py" -v

# Lượt chạy mới: bắt buộc dùng thư mục kết quả mới.
.\.venv\Scripts\python.exe -X utf8 -B -m scripts.run_benchmark samples\synthetic_v1\labels.json --output-dir reports\synthetic_new_run

# Build bộ mới bằng SDK/JDK cục bộ; cần chuẩn bị các công cụ trước.
.\.venv\Scripts\python.exe -B scripts\build_synthetic_suite.py --output samples\synthetic_v2
.\.venv\Scripts\python.exe -B scripts\verify_synthetic_suite.py samples\synthetic_v2 --freeze
```

Mặc định builder dùng Android SDK Build Tools 35.0.0, platform android-33, NDK 28.2.13676358 và JDK 23 trên Windows. Tham số `--sdk`, `--jdk`, `--build-tools` có thể đổi khi build; toolchain/hash thật được ghi lại. Tái build sẽ sinh chứng chỉ thử nghiệm mới, vì vậy không hứa APK byte-identical hoặc giữ SHA256 cũ.

## Phần nghiên cứu vẫn tách riêng

Đã bổ sung được dương tính Tầng 3 cho **kiểm thử tổng hợp**. Bộ APK thực trước đó vẫn chưa có gold dương Tầng 3; không dùng mẫu tổng hợp để đổi kết luận đó. Vẫn cần tập APK thực mới, review nhãn bởi người thứ hai và đánh giá held-out nếu muốn công bố hiệu quả thực tế. Dữ liệu training Tầng 1 và hiệu chuẩn trọng tài không được tạo giả hoặc thay đổi trong đợt này.
