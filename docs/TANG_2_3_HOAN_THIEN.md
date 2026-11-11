# Bàn giao tầng 2 và tầng 3

Ngày kiểm tra: 05/11/2026. Phiên bản bộ luật và giao thức: 2.0.0.

## Phạm vi hoàn thành

Hoàn thiện chức năng hai tầng theo hướng phân tích tĩnh của đề cương: tầng 2
nhận diện kỹ thuật che giấu/nạp mã bằng bytecode, tài nguyên và YARA; tầng 3 tìm
API nhạy cảm cùng API mạng trong một hàm. Kết quả là bằng chứng có thể truy vết,
không phải chứng minh hành vi đã xảy ra hoặc bộ phân loại họ malware mới.
CodeBERT, giải mã tải trọng, taint analysis toàn ứng dụng và phân tích động
không nằm trong phần triển khai này.

## Tầng 2

- Nạp DEX: DexClassLoader, InMemoryDexClassLoader, PathClassLoader,
  DelegateLastClassLoader và DexFile.
- Reflection: Method.invoke, Class.forName, getMethod/getDeclaredMethod,
  Constructor.newInstance.
- Mã hóa/biểu diễn: Cipher và Base64; chuỗi Base64 dài có vị trí tham chiếu,
  kiểm tra magic của dữ liệu giải mã khi hợp lệ. Không chạy dữ liệu giải mã.
- Tương quan: nạp DEX cùng xử lý mã hóa/chuỗi dạng mã hóa trong một hàm.
- Native: lời gọi load/loadLibrary; danh sách ELF và chỉ báo YARA về liên kết
  động/JNI/DEX. Đây là nhận diện chuỗi và cấu trúc, không phải dịch ngược native.
- Payload tài nguyên: nhận diện DEX/ELF/APK/JAR theo magic và cấu trúc ZIP,
  không chỉ tên đuôi; ZIP chỉ chứa ảnh/animation được phân biệt riêng.
- Làm rối tên: tỷ lệ tên lớp ngắn theo mã ứng dụng, SDK đã biết, mã chưa rõ nguồn.
  R8/ProGuard cũng tạo tín hiệu này ở ứng dụng lành tính.
- YARA: 4 luật cục bộ có version qua hash nội dung bộ luật; quét dữ liệu đã
  giải nén trong bộ nhớ; báo file, tên luật, identifier, byte offset và chuỗi khớp.
  Thiếu thư viện hoặc lỗi luật được báo rõ, không thay bằng kết quả sạch.

## Tầng 3

- Nguồn dữ liệu/dấu hiệu truy cập: SMS, định danh thiết bị/thuê bao, vị trí,
  camera, âm thanh, clipboard, tài khoản, thông báo.
- ContentResolver: query/openInputStream/openFileDescriptor khi cùng hàm có
  URI nhạy cảm cho SMS/MMS, danh bạ, cuộc gọi hoặc lịch. Nhận diện cả chuỗi URI
  và tham chiếu CONTENT_URI của các lớp Android framework liên quan.
- API mạng: HTTP output stream, socket, UDP, OkHttp, Retrofit, Apache
  HttpClient, WebView.postUrl, WebSocket.send.
- Kiểm tra trong đúng một chữ ký hàm, không gộp overload hoặc ghép nguồn và sink
  từ các hàm khác nhau. Bằng chứng gồm class, method, descriptor, offset, nhóm
  dữ liệu và URI ngữ cảnh. `flow_confirmed` luôn false trong phương pháp này.
- Thứ tự bytecode source/sink được ghi làm ngữ cảnh, không dùng nó để khẳng định
  cùng đường thực thi hoặc thực sự truyền cùng một dữ liệu.

## Giao thức và tích hợp

Hai tầng có `available`, `status`, `version`, `sha256`, `score`, `score_kind`,
`methods_scanned`, `analysis_errors`, `issues`, `finding_count`, `counts_by_origin`,
`findings`, `truncated`, `limitations`, `evidence_family`.

- completed: hoàn tất phạm vi cấu hình, không phải bảo đảm đã hiểu toàn bộ APK.
- partial: có bằng chứng nhưng còn lỗi/giới hạn/phần không đọc được.
- unavailable: không có đủ dữ liệu để chạy tầng tương ứng.
- score: null khi chưa hoàn tất; 0 chỉ dành cho lần phân tích hoàn tất không
  thấy kỹ thuật được chấm điểm. Điểm 0–100 là chỉ báo heuristic, chưa hiệu chỉnh.
- Mỗi bằng chứng có ID ổn định trong phạm vi mẫu; lặp lại cùng kỹ thuật không
  làm điểm tăng theo số lượng hàm. Toàn bộ số phát hiện vẫn được đếm, danh sách
  lưu tối đa 100/tầng và ưu tiên mã ứng dụng. Điểm được tính trước khi cắt danh sách.
- Cả hai thuộc họ code_behavior. Điểm chưa được cộng thêm vào bộ trọng tài cũ,
  tránh tính hai lần cùng bằng chứng. Đây chưa phải triển khai đầy đủ tầng 5.
- Nguồn mã được suy đoán theo tiền tố, có nhãn unknown; không xem nhãn thư viện
  là chứng nhận an toàn hoặc bỏ hẳn bằng chứng thư viện.

Upload APK và File Manager cùng dùng worker chuyên sâu. Khi worker không trả
kết quả, web giữ báo cáo không khả dụng và không tạo kết luận an toàn từ điểm 0.
Khi có tầng chưa hoàn tất, kết luận tổng hợp cũ ở mức an toàn được đổi thành
chưa đủ bằng chứng. Giao diện hiển thị trạng thái, điểm, lỗi, chi tiết API/YARA,
cho tải JSON. PDF có tóm tắt tối đa 10 phát hiện/tầng; JSON giữ danh sách đã lưu.

## Cách chạy

Từ thư mục DACN, dùng môi trường đã cài requirements.txt:

```powershell
./.venv/Scripts/python.exe -X utf8 -B -m scanner.analysis_runner sample.apk --output report.json
$env:SCAN_FOLDER = "$PWD/scans"
./.venv/Scripts/python.exe -X utf8 -B web/app.py
```

Mở http://localhost:5000/scan. Muốn quét hai tầng độc lập không cần model ML,
dùng CLI. Không cần API key, kết nối mạng, emulator hoặc MobSF.

Worker chạy trong subprocess, hard timeout mặc định 180 giây. Nó là cơ chế
giới hạn thời gian, không phải ranh giới bảo mật tương đương sandbox máy ảo.
APK không được cài đặt hay thực thi. Chuẩn bị dependency trước khi chạy offline.
Luồng tầng 1 trước worker vẫn là pipeline hiện có; timeout worker không giới
hạn toàn bộ thời gian xử lý tầng 1.

Preflight: tối đa 500 MiB file APK, 20.000 mục ZIP, 64 MiB/mục, tổng 512 MiB giải nén.
Artifact scanner: tối đa 10.000 mục, 256 MiB dữ liệu quét, 30 giây; YARA có timeout
riêng từng mục. Phân tích luật: 250.000 hàm và khoảng 90 giây cho vòng duyệt.
Chạm giới hạn được ghi lại. Giới hạn này không phải quota RAM cấp hệ điều hành.

## Kiểm thử và bằng chứng nghiệm thu

```powershell
./.venv/Scripts/python.exe -X utf8 -B -m unittest discover -s tests -p "test_*.py" -v
node tests/test_code_layers_ui.cjs
./.venv/Scripts/python.exe -X utf8 -B tests/smoke_layer_contract.py APKPure_v3.20.6504_apkpure.com.apk
./.venv/Scripts/python.exe -X utf8 -B tests/smoke_apk_layers.py APKPure_v3.20.6504_apkpure.com.apk
```

- Bộ kiểm tra Python: 48 test tại mốc bàn giao, gồm YARA thật, quét ZIP nén,
  payload đổi đuôi, thiếu YARA, giới hạn byte/thời gian, chấm điểm/khử trùng,
  URI framework, phạm vi hàm và thống kê đánh giá.
- DEX tự sinh được Androguard phân tích thật: có 4 hàm; chỉ hàm có cả hai API
  được báo, offset nguồn 0 và mạng 6. Không cài hoặc thực thi fixture.
- Kiểm thử tích hợp dùng DEX nhỏ: upload và File Manager thực sự chạy worker;
  nhận diện cặp API, payload đổi đuôi; DEX hỏng trả tầng 3 unavailable, điểm null;
  worker thất bại được truyền ra giao diện/API rõ ràng.
- APKPure 25 MB: đọc 138.430 hàm, hai tầng completed; tầng 2 có 652 chỉ báo,
  tầng 3 không có cặp API khớp. Các chỉ báo không phải 652 hành vi mã độc.
- JavaScript: kiểm tra cú pháp cả hai khối script, render bằng chứng file/API,
  trạng thái thiếu dữ liệu, escape HTML và nút tải JSON. Chưa nghiệm thu bằng
  thao tác trình duyệt trực quan hoặc mở file PDF xuất ra.
- Dependency đang dùng để kiểm thử: Python 3.14, Androguard 4.1.3, YARA 4.5.4,
  scikit-learn 1.9.0, XGBoost 2.0.3. Môi trường .venv kế thừa thư viện đã có;
  pip check còn báo sklearn-compat 0.1.5 của môi trường nền yêu cầu sklearn <1.9.
  Hai tầng và suy luận app đã chạy; chưa xác minh pipeline training dùng dependency đó.
- Chưa build lại Docker trong đợt này.

## Đánh giá trên dữ liệu thật

Có scripts/evaluate_layers.py đọc JSON báo cáo và nhãn xác minh độc lập để xuất
TP/FP/FN/TN, Precision, Recall, F1, FPR, coverage và danh sách mẫu chưa đánh giá.
Thiếu kết quả không được âm thầm biến thành âm tính. Công cụ từ chối SHA256
trùng và nhãn boolean sai định dạng.

Nhãn đầu vào, đường dẫn report tương đối với file labels.json:

```json
[
  {"report": "reports/sample.json", "layer2_positive": true, "layer3_positive": false}
]
```

```powershell
./.venv/Scripts/python.exe -X utf8 -B scripts/evaluate_layers.py labels.json --output evaluation.json
```

Ngưỡng chỉ báo tầng 2 mặc định 15 chỉ là điểm khởi đầu, có thể đổi bằng
--layer2-threshold; phải hiệu chỉnh trên tập validation và đánh giá lại trên
tập test tách biệt. Tầng 3 dương tính nếu có cặp cùng hàm. Nhãn nên phản ánh đúng
định nghĩa này, không thay bằng nhãn Benign/Malware của tầng 1.

Hiện chưa có bộ nhãn độc lập tầng 2/3 để công bố độ chính xác, báo động giả
hoặc khẳng định hiệu quả trên malware chưa thấy. 65 dòng malware_manifest.csv
của tầng 1 chưa cung cấp loại nhãn này. Không sinh nhãn đánh giá từ chính bộ luật.

## Việc không thay đổi và giới hạn nghiên cứu

Không đổi model/schema tầng 1; không triển khai tầng 4/5, CodeBERT hoặc tự cập
nhật mẫu. Không tự commit/push. Quyền, reflection, Base64, native và entropy cao
đều có thể xuất hiện trong app sạch; API cùng hàm không chứng minh dữ liệu đi
tới sink. Mã native, reflection và payload chỉ tải lúc chạy có thể che khuất
phát hiện. Những giới hạn này cần xác nhận bằng sandbox và trọng tài ở giai đoạn sau.
