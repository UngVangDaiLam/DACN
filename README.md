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

## Tầng 2 và tầng 3 — bản sơ bộ

Upload APK tại `/scan`, hoặc chọn quét APK trong File Manager. Báo cáo có hai
khung riêng, mở **Xem bằng chứng** để xem lớp, chữ ký hàm, API và offset trong
bytecode. Hai tầng chạy phân tích tĩnh cục bộ, không thực thi APK và không cần
MobSF, emulator hoặc model tĩnh đã train.

- **Tầng 2:** luật tìm lời gọi nạp DEX, reflection, Cipher, nạp native và chuỗi
  dài có dạng Base64; hiển thị thêm payload nhúng, thư viện native, entropy DEX
  và tỷ lệ tên lớp ngắn từ bộ phân tích hiện có. Chưa tích hợp YARA, giải mã
  payload hoặc phân tích nội dung mã native. Các dấu hiệu này cũng có ở app sạch.
- **Tầng 3:** tìm API nhạy cảm và API mạng trong cùng một hàm. Danh sách ban đầu
  bao phủ SMS qua SmsMessage, định danh thiết bị, vị trí, camera, clipboard;
  API mạng gồm output stream HTTP/socket, UDP, OkHttp và Apache HttpClient.
  Chưa chứng minh quan hệ dữ liệu, chưa theo dõi qua nhiều hàm hoặc các nhánh.
- Mã được gắn nhãn ứng dụng/thư viện/chưa xác định theo tiền tố; đây là heuristic.
  Mỗi tầng giữ tối đa 100 phát hiện, ưu tiên mã ứng dụng; tổng số vẫn được đếm.
  Các danh sách artifact kế thừa giới hạn của bộ phân tích hiện có.
- Kết quả JSON nằm ở `ai_result.deep.layer2` và `ai_result.deep.layer3` khi upload;
  quét từ File Manager trả về `deep.layer2` và `deep.layer3` trực tiếp. Hai tầng
  cùng thuộc họ `code_behavior`, chưa được cộng thêm vào điểm tổng hợp cũ.
  `partial` báo có lỗi phân tích; không có phát hiện không có nghĩa APK an toàn.

Dùng Python đã cài đủ `requirements.txt` (khuyến nghị môi trường ảo), kiểm tra:

```powershell
python -B -m unittest discover -s tests -p "test_*.py" -v
node tests/test_code_layers_ui.cjs
python -B tests/smoke_apk_layers.py "APKPure_v3.20.6504_apkpure.com.apk"
```

Smoke test chạy upload APK thật qua Flask test client và kiểm tra JSON của hai
tầng; phần File Manager kiểm tra tích hợp bằng cách dùng lại kết quả vừa quét.
Test không khởi động server, không gửi APK sang MobSF và không chạy APK.
Node chỉ cần cho kiểm tra JavaScript, không phải dependency của ứng dụng.
