# Malware_Android_web

Hệ thống phát hiện và phân loại mã độc Android (AI + MobSF), giao diện web Flask.

## Cài đặt

```powershell
python -m venv venv
.\venv\Scripts\activate
pip install -r requirements.txt
```

Tạo file `.env` ở thư mục gốc:

```
MOBSF_KALI_IP=192.168.x.x          # IP máy Kali chạy MobSF
MOBSF_API_KEY=...                  # API key của MobSF
WINDOWS_IP_FROM_KALI=...           # IP Windows nhìn từ Kali (Tailscale)
WINDOWS_ADB_PORT=5556              # Cổng ADB Genymotion
SCAN_FOLDER=C:\scans               # (tuỳ chọn) nơi lưu file quét
```

## Chạy web

```powershell
.\venv\Scripts\python.exe web\app.py
```

Mở http://localhost:5000. Mặc định chỉ lắng nghe localhost; đặt `APP_HOST=0.0.0.0` / `FLASK_DEBUG=1` trong `.env` nếu cần.

## Chia sẻ link cho người khác (ngrok)

Bật web trước, sau đó chạy ngrok rồi copy link "Forwarding" gửi cho người dùng:

```powershell
cd web
.\ngrok.exe http 5000
```

## Cài MobSF trên Kali (VMware)

```bash
sudo apt update && sudo apt install docker.io -y
sudo systemctl start docker
sudo systemctl enable docker
sudo docker run -it --rm -p 8000:8000 opensecurity/mobile-security-framework-mobsf:latest
```

Lấy API key hiển thị trong log/giao diện MobSF và điền vào `.env` (`MOBSF_KALI_IP`, `MOBSF_API_KEY`).

## Train lại model tĩnh

```powershell
python download_malwarebazaar.py   # mẫu mã độc
python download_fdroid.py          # mẫu lành tính
python build_static_dataset.py
python train_static_model.py
```

## Docker

```bash
docker build -t malware-web .
docker run -p 5000:5000 --env-file .env malware-web
```

## Tầng 2 và tầng 3 — phiên bản 2.2.0

Upload APK tại `/scan`, hoặc chọn quét APK trong File Manager. Báo cáo có hai
khung riêng, mở **Xem bằng chứng** để xem lớp, chữ ký hàm, API và offset trong
bytecode. Tải JSON để giữ bằng chứng và trạng thái. PDF gồm phần tóm tắt tối đa
10 phát hiện/tầng. Hai tầng chạy tĩnh cục bộ, không thực thi APK, không gửi dữ liệu
ra mạng. Chạy CLI độc lập không cần model tầng 1, MobSF hoặc emulator.

- **Tầng 2:** luật theo hàm cho nạp DEX, reflection, Cipher, Base64 và nạp native;
  phát hiện tương quan loader + mã hóa trong cùng hàm. Quét tài nguyên theo magic
  bytes, kể cả đổi đuôi; phân biệt ZIP ảnh/animation với APK/JAR/DEX; thống kê
  tên lớp ngắn theo nguồn mã. Bốn luật YARA trong `scanner/rules/layer2.yar`
  chạy trên DEX, ELF và tài nguyên đã giải nén trong bộ nhớ, có offset chuỗi khớp.
  Không thực thi payload, không tự giải mã tải trọng, không phân tích ngữ nghĩa native.
- **Tầng 3:** tìm API nhạy cảm và API mạng trong cùng hàm, bao gồm SMS, định danh,
  vị trí, camera, âm thanh, clipboard, tài khoản, thông báo; thêm truy vấn SMS,
  danh bạ, nhật ký cuộc gọi, lịch qua ContentResolver khi có URI tương ứng trong
  chuỗi hoặc trường CONTENT_URI của framework. Sink gồm HTTP/socket/UDP,
  OkHttp, Retrofit, Apache HttpClient, WebView.postUrl và WebSocket.send.
  Đây là kiểm tra đồng xuất hiện theo hàm; không chứng minh luồng dữ liệu, nhánh
  chạy thực tế, lời gọi qua nhiều hàm hoặc reflection.
- Mã được gắn nhãn ứng dụng/thư viện/chưa xác định theo tiền tố; đây là heuristic.
  Mỗi tầng giữ tối đa 100 phát hiện, ưu tiên mã ứng dụng; tổng số vẫn được đếm.
  Điểm chỉ báo 0–100 dùng trọng số luật có giới hạn theo kỹ thuật; không phải
  xác suất mã độc hay điểm đã hiệu chỉnh trên dữ liệu thật.
- Kết quả JSON nằm ở `ai_result.deep.layer2` và `ai_result.deep.layer3` khi upload;
  quét từ File Manager trả về `deep.layer2` và `deep.layer3` trực tiếp. Hai tầng
  cùng thuộc họ `code_behavior`, chưa được cộng thêm vào điểm tổng hợp cũ.
  `completed` là hoàn tất phạm vi luật cấu hình; `partial` là chưa đủ;
  `unavailable` là không phân tích được. Điểm là null khi chưa hoàn tất, không
  thay bằng 0. Không có phát hiện không có nghĩa APK an toàn.

Luồng web chạy kiểm ZIP, nạp model, Tầng 1 và Tầng 2/3 trong cùng worker với timeout tổng 180 giây (APK_ANALYSIS_TIMEOUT). Worker
không phải sandbox bảo mật thay cho máy ảo. Preflight giới hạn 500 MiB file đầu vào,
20.000 mục ZIP, 64 MiB/mục và tổng 512 MiB giải nén. Quét tài nguyên/YARA tối đa
256 MiB, 10.000 mục, 30 giây; vòng luật tối đa 250.000 hàm/90 giây. Chạm giới hạn
được báo trong `issues`. Không thay schema, model hoặc dữ liệu huấn luyện tầng 1.

CLI độc lập (cài `requirements.txt`, bao gồm `yara-python`):

```powershell
python -X utf8 -B -m scanner.analysis_runner "sample.apk" --output "report.json"
```

CLI trả mã thoát 0 khi hai tầng hoàn tất, 2 nếu có tầng chưa hoàn tất; báo cáo
vẫn được ghi. API Python: `scanner.analysis_runner.run_deep_analysis(path)` trả
hai tầng dùng chung một lần parse; `analyze_layer2(path)` / `analyze_layer3(path)`
là hàm tiện ích, mỗi lần gọi sẽ phân tích riêng.

Dùng Python đã cài đủ `requirements.txt` (khuyến nghị môi trường ảo), kiểm tra:

```powershell
python -B -m unittest discover -s tests -p "test_*.py" -v
node tests/test_code_layers_ui.cjs
python -B tests/smoke_apk_layers.py "APKPure_v3.20.6504_apkpure.com.apk"
python -B tests/smoke_layer_contract.py "APKPure_v3.20.6504_apkpure.com.apk"
```

Smoke test chạy upload APK thật qua Flask test client và kiểm tra JSON của hai
tầng; phần File Manager kiểm tra tích hợp bằng cách dùng lại kết quả vừa quét.
Test không khởi động server, không gửi APK sang MobSF và không chạy APK.
Node chỉ cần cho kiểm tra JavaScript, không phải dependency của ứng dụng.

`smoke_layer_contract.py` dùng DEX kiểm thử tự sinh và chỉ lấy Manifest từ APK
truyền vào; chạy upload và File Manager thật, kiểm tra trường hợp tầng 3 dương
tính và DEX hỏng. Fixture không được cài đặt hay thực thi.

Đánh giá trên nhãn độc lập: `python scripts/evaluate_layers.py labels.json
--output evaluation.json`. Xem cấu trúc nhãn trong đầu script; tool báo confusion
matrix, Precision/Recall/F1/FPR và coverage, không âm thầm coi mẫu lỗi là âm tính.
Chưa có bộ nhãn kiểm chứng tầng 2/3 trong repo để công bố độ chính xác thực tế.

Bàn giao chi tiết: [docs/TANG_2_3_HOAN_THIEN.md](docs/TANG_2_3_HOAN_THIEN.md).


Cải thiện mới, cách chạy benchmark theo kỹ thuật, nhãn unknown và giới hạn tái lập: [docs/CAI_TIEN_2026_11_10.md](docs/CAI_TIEN_2026_11_10.md).


Nghiệm thu chức năng Tầng 2/3 bằng 24 APK tổng hợp có nhãn chốt độc lập: [docs/NGHIEM_THU_TANG_2_3.md](docs/NGHIEM_THU_TANG_2_3.md). Bộ tổng hợp được lưu riêng tại samples/synthetic_v1; không gộp với APK thực.

Tích hợp mã remote và hợp đồng bằng chứng Tầng 2/3 với Tầng 5:
[docs/TICH_HOP_2026_11_11.md](docs/TICH_HOP_2026_11_11.md).
JSON phân tích có thêm `family_b`; điểm thiếu hoặc bằng chứng bị cắt không
được chuyển thành điểm 0. Điểm này chưa thay thế kết luận cuối của web.
