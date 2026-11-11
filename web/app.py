# web/app.py
import pandas as pd
import numpy as np
import joblib
import hashlib
import os
import re
import sys
import uuid
import queue
import threading
from datetime import datetime
import requests
from flask import Flask, request, render_template, jsonify
from dotenv import load_dotenv
 
# ============ NẠP BIẾN MÔI TRƯỜNG TỪ FILE .env ============
# Chạy từ gốc dự án (vd: .\venv\Scripts\python.exe web\app.py) nên .env ở gốc dự án sẽ được tự tìm thấy.
load_dotenv()
 
# ============ CẤU HÌNH MOBSF (KALI SERVER) ============
KALI_IP              = os.environ.get("MOBSF_KALI_IP", "127.0.0.1")
MOBSF_API_URL        = f"http://{KALI_IP}:8000/api/v1"
API_KEY              = os.environ.get("MOBSF_API_KEY", "")
 
# IP Windows nhìn từ Kali qua Tailscale + cổng ADB của Genymotion
WINDOWS_IP_FROM_KALI = os.environ.get("WINDOWS_IP_FROM_KALI", "")
WINDOWS_ADB_PORT     = int(os.environ.get("WINDOWS_ADB_PORT", "5556"))
 
if not API_KEY:
    print("ℹ️  MobSF chưa cấu hình (MOBSF_API_KEY) — bỏ qua đối chiếu MobSF, dùng bộ phân tích cục bộ.")
 
# ============ KHỞI TẠO HÀNG ĐỢI (TASK QUEUE) ============
dynamic_task_queue = queue.Queue()
analysis_results = {} # Lưu kết quả trạng thái
 
# Thêm đường dẫn để import scanner
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from scanner.detect_and_classify import MalwareDetector
from scanner.pipeline_runner import run_apk_analysis as analyze_apk_pipeline
from scanner.meta_arbiter import arbitrate_from_results, UNKNOWN as T5_UNKNOWN
from web.layer4_jobs import Layer4Jobs

try:
    layer4_jobs = Layer4Jobs(os.environ.get("ANDROWALL_LAYER4_COMMAND"), analysis_results)
except ValueError:
    print("Tầng 4: cấu hình ANDROWALL_LAYER4_COMMAND không hợp lệ.")
    layer4_jobs = Layer4Jobs(None, analysis_results)
 
import numpy as np
 
def numpy_safe(obj):
    """Đệ quy convert numpy types sang Python native để jsonify không lỗi"""
    if isinstance(obj, dict):
        return {k: numpy_safe(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [numpy_safe(i) for i in obj]
    if isinstance(obj, np.integer): return int(obj)
    if isinstance(obj, np.floating): return round(float(obj), 4)
    if isinstance(obj, np.ndarray): return obj.tolist()
    return obj
 
app = Flask(__name__)
 
# ============ SESSION LOG & CRASH LOG ============
_APP_DIR = os.path.dirname(os.path.abspath(__file__))
SESSION_LOG = os.path.join(_APP_DIR, 'latest_scan.log')
CRASH_LOG   = os.path.join(_APP_DIR, 'error_crash.log')
 
def _log(message, level='INFO', new_scan=False):
    """Ghi dòng log vào latest_scan.log. new_scan=True xóa log cũ (mode w)."""
    timestamp = datetime.now().strftime('%H:%M:%S')
    line = f"[{timestamp}] [{level}] {message}\n"
    mode = 'w' if new_scan else 'a'
    try:
        with open(SESSION_LOG, mode, encoding='utf-8') as f:
            f.write(line)
    except Exception:
        pass
 
def _crash(message, exc=None):
    """Ghi lỗi vào error_crash.log (chế độ append để cộng dồn)."""
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    try:
        with open(CRASH_LOG, 'a', encoding='utf-8') as f:
            f.write(f"\n{'='*60}\n[{timestamp}] ERROR: {message}\n")
            if exc:
                import traceback as tb
                f.write(tb.format_exc())
    except Exception:
        pass


# Traceback day du trong error_crash.log CHI khi CRASH_TRACEBACK=1 (go loi cuc bo). Mac dinh TAT:
# traceback chua duong dan tren may va thong bao loi (co the mang chuoi lay tu APK).
CRASH_TRACEBACK = os.environ.get("CRASH_TRACEBACK") == "1"


def _safe_ids(result=None, file_bytes=None):
    """sha256 (chi hex) + ten goi (chi [A-Za-z0-9._-], <= 200 ky tu) de ghi log an toan."""
    result = result or {}
    sha = re.sub(r'[^0-9a-fA-F]', '', str(result.get('sha256') or ''))[:64]
    if not sha and file_bytes:
        sha = hashlib.sha256(file_bytes).hexdigest()
    pkg = re.sub(r'[^A-Za-z0-9._-]', '?', str(result.get('package_name') or ''))[:200]
    return sha or 'N/A', pkg or 'N/A'


def _crash_safe(context, exc, result=None, file_bytes=None):
    """Ghi crash log toi gian: ngu canh + loai loi + sha256 + ten goi. Khong ghi ten file
    nguoi dung tai len, thong bao loi, duong dan hay bien moi truong (tru khi CRASH_TRACEBACK=1)."""
    sha, pkg = _safe_ids(result, file_bytes)
    _crash(f"{context}: {type(exc).__name__} | sha256={sha} | package={pkg}",
           exc=exc if CRASH_TRACEBACK else None)


# Loi tra ve trinh duyet: CHI thong bao chung + ma loi + loai loi (+ sha256). KHONG tra str(e):
# thong bao loi co the chua duong dan may, IP noi bo, hoac chuoi lay tu APK (vd. ten muc trong zip).
ERROR_MESSAGES = {
    "E_APK": "Không phân tích được file APK (file hỏng, không phải APK hợp lệ hoặc cấu trúc bị làm méo).",
    "E_CSV": "Không đọc được file CSV (sai định dạng hoặc thiếu cột đặc trưng).",
    "E_UPLOAD": "Không lưu được file tải lên.",
    "E_MOBSF": "Lỗi khi lấy báo cáo từ MobSF.",
    "E_INTERNAL": "Lỗi nội bộ máy chủ khi phân tích.",
}


def _error_json(code, exc=None, status=500, sha256=None):
    body = {'success': False, 'error': ERROR_MESSAGES[code], 'error_code': code}
    if exc is not None:
        body['error_type'] = type(exc).__name__
    if sha256 and sha256 != 'N/A':
        body['sha256'] = sha256
    return jsonify(body), status


_ABS_PATH = re.compile(r"(?:[A-Za-z]:[\\/]|\\\\|/(?:home|Users|tmp|var|usr|etc|mnt|opt|root)/)[^\s'\"<>|,;)]*")
_CTRL = re.compile(r"[\x00-\x1f\x7f]")


def _log_safe(text, limit=300):
    """Chuoi tu ben ngoai dua vao latest_scan.log (duoc /api/scan-log tra cho trinh duyet):
    bo ky tu dieu khien (chong gia mao dong log), an duong dan tuyet doi, cat do dai."""
    s = _CTRL.sub(' ', str(text))
    s = _ABS_PATH.sub('<đường dẫn>', s)
    return s[:limit]
 
# Override jsonify để tự động xử lý numpy types (tương thích Flask 2 + 3)
from flask import json as flask_json
_orig_jsonify = jsonify
def jsonify(*args, **kwargs):
    if args and len(args) == 1 and isinstance(args[0], dict):
        args = (numpy_safe(args[0]),)
    elif kwargs:
        kwargs = numpy_safe(kwargs)
    return _orig_jsonify(*args, **kwargs)
# Thư mục lưu file quét: cấu hình qua SCAN_FOLDER trong .env (mặc định C:\scans trên Windows, ./scans nơi khác)
_default_scan = r'C:\scans' if os.name == 'nt' else os.path.join(os.path.dirname(_APP_DIR), 'scans')
app.config['SCAN_FOLDER'] = os.environ.get('SCAN_FOLDER', _default_scan)
app.config['UPLOAD_FOLDER'] = os.path.join(app.config['SCAN_FOLDER'], 'uploads')
app.config['MAX_CONTENT_LENGTH'] = 500 * 1024 * 1024
app.config['APK_ANALYSIS_TIMEOUT'] = float(os.environ.get('APK_ANALYSIS_TIMEOUT', '180'))
 
# Tạo thư mục
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(os.path.join(app.config['SCAN_FOLDER'], 'csv'), exist_ok=True)
os.makedirs(os.path.join(app.config['SCAN_FOLDER'], 'apk'), exist_ok=True)
os.makedirs(os.path.join(app.config['SCAN_FOLDER'], 'other'), exist_ok=True)
 
print("="*60)
print("🦾 ANDROID MALWARE DETECTION SYSTEM")
print("="*60)
 
# Khởi tạo detector
try:
    detector = MalwareDetector()
    print("✅ Detector loaded successfully!")
    print(f"✅ Can classify: {detector.class_names}")
except Exception as e:
    print(f"❌ Error loading detector: {e}")
    detector = None
    print('Tầng 1/CSV chưa khả dụng; worker APK vẫn có thể cung cấp bằng chứng Tầng 2/3.')
 
print("="*60)
 
# ============ WORKER PHÂN TÍCH TĨNH MOBSF (BACKGROUND WORKER) ============
class MobSFError(Exception):
    """Loi MobSF voi thong bao an toan: chi ma HTTP + buoc, KHONG mang noi dung phan hoi cua MobSF."""
    def __init__(self, status, step):
        self.status, self.step = status, step
        super().__init__(f"MobSF {step}: HTTP {status}")

    def user_message(self):
        if self.status in (401, 403):
            return f"❌ MobSF từ chối khóa API (HTTP {self.status}) — kiểm tra cấu hình khóa API MobSF trên máy chủ."
        if self.step == "no_hash":
            return "❌ MobSF không trả về hash sau khi tải lên."
        return f"❌ MobSF trả lỗi HTTP {self.status} ở bước {self.step}."


def mobsf_static_worker():
    """Upload APK lên MobSF, kích hoạt Static Analysis, trả về link xem báo cáo."""
    while True:
        task = dynamic_task_queue.get()
        task_id  = task['task_id']
        filepath = task['filepath']
        headers  = {"Authorization": API_KEY}
 
        try:
            # ── BƯỚC 1: Upload APK ──────────────────────────────────────────
            analysis_results[task_id]['message'] = "Đang upload APK lên MobSF (Kali)..."
            apk_filename = os.path.basename(filepath)
            with open(filepath, 'rb') as f:
                upload_res = requests.post(
                    f"{MOBSF_API_URL}/upload",
                    headers=headers,
                    files={'file': (apk_filename, f, 'application/octet-stream')},
                    timeout=120
                )
            if upload_res.status_code != 200:
                raise MobSFError(upload_res.status_code, "upload")

            mobsf_hash = upload_res.json().get('hash')
            if not mobsf_hash:
                raise MobSFError(upload_res.status_code, "no_hash")
            print(f"[MobSF] Upload OK — hash: {mobsf_hash}")
 
            # ── BƯỚC 2: Kích hoạt Static Analysis (apktool, dex2jar, ...) ───
            analysis_results[task_id]['message'] = "MobSF đang phân tích tĩnh (apktool / dex2jar)..."
            scan_res = requests.post(
                f"{MOBSF_API_URL}/scan",
                headers=headers,
                data={'hash': mobsf_hash},
                timeout=180
            )
            print(f"[MobSF] Scan status: {scan_res.status_code}")
 
            # ── HOÀN THÀNH: trả về link xem báo cáo ────────────────────────
            analysis_results[task_id].update({
                "status": "completed",
                "message": "✅ Phân tích tĩnh hoàn tất! Nhấn nút để xem báo cáo đầy đủ.",
                "mobsf_hash": mobsf_hash,
                "mobsf_link": f"http://{KALI_IP}:8000/static_analyzer/{mobsf_hash}/"
            })
            print(f"[MobSF] Task {task_id} hoàn thành.")
 
        except requests.exceptions.ConnectionError:
            analysis_results[task_id].update({
                "status": "offline",
                "message": "⚠️ Không kết nối được tới máy chủ Kali. MobSF có thể đang tắt."
            })
        except Exception as e:
            _crash_safe(f"mobsf_static_worker task={task_id}", e, {'sha256': task.get('sha256')})
            analysis_results[task_id].update({
                "status": "error",
                "message": e.user_message() if isinstance(e, MobSFError)
                           else f"❌ Lỗi khi gửi tới MobSF ({type(e).__name__})."
            })
        finally:
            dynamic_task_queue.task_done()
 
# Kích hoạt luồng ngầm ngay khi Flask khởi động
threading.Thread(target=mobsf_static_worker, daemon=True).start()
 
# =====================================================================
 
# ============ FILE MANAGEMENT & MOBSF HELPERS ============
def get_files_in_directory(directory):
    """Lấy danh sách file trong thư mục"""
    files = []
    if os.path.exists(directory):
        for filename in os.listdir(directory):
            filepath = os.path.join(directory, filename)
            if os.path.isfile(filepath):
                stat = os.stat(filepath)
                files.append({
                    'name': filename,
                    'size_mb': round(stat.st_size / (1024 * 1024), 2),
                    'modified': datetime.fromtimestamp(stat.st_mtime).strftime('%Y-%m-%d %H:%M:%S'),
                    'ext': filename.split('.')[-1].lower() if '.' in filename else 'unknown'
                })
    return sorted(files, key=lambda x: x['modified'], reverse=True)
 
def upload_to_mobsf(filepath):
    """Hàm dự phòng gọi upload trực tiếp (Nếu cần)"""
    url = f"{MOBSF_API_URL}/upload"
    try:
        with open(filepath, 'rb') as f:
            files = {'file': (os.path.basename(filepath), f, 'application/octet-stream')}
            response = requests.post(url, headers={"Authorization": API_KEY}, files=files, timeout=30)
            if response.status_code == 200:
                return response.json().get("hash")
    except Exception as e:
        print(f"[-] Lỗi MobSF: {e}")
    return None
 
    return sorted(files, key=lambda x: x['modified'], reverse=True)
 
ALLOWED_SUBFOLDERS = {'csv', 'apk', 'other'}

def safe_scan_path(subfolder, filename):
    """Trả về đường dẫn tuyệt đối an toàn trong SCAN_FOLDER, hoặc None nếu không hợp lệ (chống path traversal)."""
    if subfolder not in ALLOWED_SUBFOLDERS:
        return None
    base = os.path.realpath(os.path.join(app.config['SCAN_FOLDER'], subfolder))
    target = os.path.realpath(os.path.join(base, filename))
    if os.path.dirname(target) != base:
        return None
    return target

def save_uploaded_file(file, subfolder):
    """Lưu file với tên hoàn toàn sạch (chỉ timestamp + số) để tránh Errno 22"""
    ext = os.path.splitext(file.filename)[1].lower()  # .apk / .csv
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    new_filename = f"scan_{timestamp}_{uuid.uuid4().hex[:12]}{ext}"
    filepath = os.path.join(app.config['SCAN_FOLDER'], subfolder, new_filename)
    file.save(filepath)
    return new_filename, filepath


TANG5_KEYS = ("label", "risk_level", "p_malicious", "confidence", "layers_present",
              "evidence_by_layer", "layer_errors", "reason", "era_biased")


def attach_tang5(result):
    """Tang 5 (meta_arbiter) tu ket qua L1 + analyze_deep DA CO trong `result` (khong chay lai).
    KHONG dung result['verdict'] (combine_verdict) lam dau vao. Loi -> khoi tang5 co 'error',
    khong lam sap endpoint."""
    try:
        deep = result.get('deep')
        deep_errors = [] if deep else ["L2/L3 (analyze_deep): khong co ket qua phan tich chuyen sau"]
        t5 = arbitrate_from_results(result, deep, deep_errors=deep_errors)
        result['tang5'] = {k: t5.get(k) for k in TANG5_KEYS}
        result['tang5']['error'] = None
    except Exception as e:
        _crash_safe("Tang 5 (arbitrate_from_results) that bai", e, result)
        result['tang5'] = {k: None for k in TANG5_KEYS}
        result['tang5'].update(label=T5_UNKNOWN, risk_level=T5_UNKNOWN, layers_present=[],
                               evidence_by_layer={}, layer_errors=[], era_biased=False,
                               error=f"Không tính được kết luận Tầng 5 ({type(e).__name__}).")
    return result['tang5']
 
# ============ ROUTES ============
@app.route('/')
def index():
    return render_template('index.html')
 
@app.route('/scan')
def scan_page():
    return render_template('scan.html')
 
@app.route('/scan/csv', methods=['POST'])
def scan_csv():
    """API quét file CSV"""
    if 'file' not in request.files:
        return jsonify({'success': False, 'error': 'No file uploaded'}), 400
 
    file = request.files['file']
    if file.filename == '':
        return jsonify({'success': False, 'error': 'No file selected'}), 400
 
    if not file.filename.endswith('.csv'):
        return jsonify({'success': False, 'error': 'Only CSV files are supported'}), 400
 
    if detector is None:
        return jsonify({'success': False, 'error': 'Mô hình CSV chưa khả dụng; hãy kiểm tra cấu hình model.'}), 503
    filename, filepath = save_uploaded_file(file, 'csv')
    try:
        result = detector.analyze_csv(filepath, filename)
        if 'first_sample' in result and 'confidence' in result['first_sample']:
            result['first_sample']['confidence'] = round(float(result['first_sample']['confidence']), 2)
        return jsonify(result)
    except Exception as e:
        import traceback
        print(f"[✗] analyze_csv lỗi: {traceback.format_exc()}")
        _crash_safe("scan_csv that bai", e)
        return _error_json("E_CSV", e)
 
@app.route('/scan/apk', methods=['POST'])
def scan_apk():
    """Stream the upload to disk; all parsing shares one worker deadline."""
    file = request.files.get('file')
    if file is None or not file.filename:
        return jsonify({'success': False, 'error': 'Chưa chọn tệp APK.'}), 400
    if not file.filename.lower().endswith('.apk'):
        return jsonify({'success': False, 'error': 'Chỉ hỗ trợ tệp APK.'}), 400
    # Giu ten file (giao dien so khop dong nay voi file.name), chi bo ky tu dieu khien/duong dan
    _log(f"=== BẮT ĐẦU PHÂN TÍCH: {_log_safe(file.filename, 200)} ===", new_scan=True)
    result = None  # de _crash_safe dung duoc ca khi loi xay ra som
    try:
        filename, filepath = save_uploaded_file(file, 'apk')
        _log('Đang phân tích APK trong worker có giới hạn thời gian cho toàn bộ các tầng...')
        def report_progress(stage, message):
            _log(f"PROGRESS::{stage}::{message}")

        result = analyze_apk_pipeline(
            filepath,
            filename,
            timeout=app.config['APK_ANALYSIS_TIMEOUT'],
            progress=report_progress,
        )
        if not result.get('success'):
            _log(result.get('error', 'Không hoàn tất phân tích'), level='ERROR')
            return jsonify({'success': False, 'error': result.get('error'),
                            'ai_result': result, 'task_id': None}), result.get('http_status', 503)
        for name in ('layer2', 'layer3'):
            layer = result['deep'][name]
            _log(f"{name}: {layer['finding_count']} phát hiện; trạng thái {layer['status']}.")

        # Tầng 5 — bỏ phiếu có trọng số trên kết quả L1/L3 do worker trả về (không chạy lại phân tích)
        t5 = attach_tang5(result)
        _log(f"TẦNG 5: {t5['label']} — P(độc) {t5['p_malicious']} — tầng có mặt {t5['layers_present']}"
             + (f" — {t5['reason']}" if t5.get('reason') else ''),
             level='ERROR' if t5.get('error') else 'SUCCESS')

        # Tầng 4 nhận chính APK đã lưu ở đầu lượt quét (SHA256 tính lại từ file trên đĩa).
        with open(filepath, 'rb') as saved_apk:
            layer4_task_id = layer4_jobs.submit(filepath, hashlib.file_digest(saved_apk, 'sha256').hexdigest())

        task_id = None
        if API_KEY:
            task_id = str(uuid.uuid4())
            analysis_results[task_id] = {'status': 'queued', 'message': 'Đang xếp hàng đối chiếu MobSF.'}
            dynamic_task_queue.put({'task_id': task_id, 'filepath': filepath, 'filename': filename,
                                    'sha256': result.get('sha256')})
        _log('=== HOÀN TẤT PHÂN TÍCH TĨNH ===', level='SUCCESS')
        return jsonify({'success': True, 'ai_result': result, 'task_id': task_id,
                        'layer4_task_id': layer4_task_id,
                        'message': 'Đã phân tích xong.'})
    except Exception as e:
        sha, _ = _safe_ids(result)
        # Giu chuoi 'LỖI NGHIÊM TRỌNG': giao dien dung no de dung polling log
        _log(f"LỖI NGHIÊM TRỌNG (E_INTERNAL, {type(e).__name__}).", level='ERROR')
        _crash_safe("scan_apk that bai", e, result)
        return _error_json('E_INTERNAL', e, sha256=sha)


@app.route('/api/scan-log', methods=['GET'])
def get_scan_log():
    """Trả về nội dung log phiên quét hiện tại cho terminal UI."""
    try:
        with open(SESSION_LOG, 'r', encoding='utf-8') as f:
            lines = [l.rstrip('\n') for l in f.readlines()]
        return jsonify({'lines': lines[-100:]})
    except FileNotFoundError:
        return jsonify({'lines': []})
 
@app.route('/api/status/<task_id>', methods=['GET'])
def get_task_status(task_id):
    """API để Frontend hỏi thăm tiến độ của Genymotion"""
    result = analysis_results.get(task_id)
    if not result:
        return jsonify({"error": "Không tìm thấy tác vụ"}), 404
    return jsonify(result)
 
@app.route('/api/mobsf_report/<mobsf_hash>', methods=['GET'])
def get_mobsf_report(mobsf_hash):
    """Proxy lấy báo cáo JSON từ MobSF trên Kali (tránh CORS)"""
    try:
        headers = {"Authorization": API_KEY, "Content-Type": "application/x-www-form-urlencoded"}
        # Lấy báo cáo static
        static_res = requests.post(
            f"{MOBSF_API_URL}/report_json",
            headers=headers,
            data={"hash": mobsf_hash},
            timeout=15
        )
        if static_res.status_code != 200:
            return jsonify({"error": f"MobSF trả lỗi {static_res.status_code}"}), 502
 
        report = static_res.json()
 
        # Trích xuất các trường quan trọng để hiển thị
        permissions = report.get("permissions", {})
        dangerous_perms = [p for p, v in permissions.items()
                           if isinstance(v, dict) and v.get("status", "").lower().strip() == "dangerous"]
 
        activities = report.get("activities", [])
        services = report.get("services", [])
        receivers = report.get("receivers", [])
 
        security_score = report.get("appsec", {})
        urls = report.get("urls", [])
        emails = report.get("emails", [])
        strings = report.get("strings", [])[:20]
 
        # Certificate info
        cert = report.get("certificate_analysis", {})
 
        return jsonify({
            "success": True,
            "app_name": report.get("app_name", "N/A"),
            "package_name": report.get("package_name", "N/A"),
            "version_name": report.get("version_name", "N/A"),
            "min_sdk": report.get("min_sdk", "N/A"),
            "target_sdk": report.get("target_sdk", "N/A"),
            "file_size": report.get("size", "N/A"),
            "md5": report.get("md5", "N/A"),
            "sha256": report.get("sha256", "N/A"),
            "dangerous_permissions": dangerous_perms,
            "all_permissions": list(permissions.keys()),
            "activities_count": len(activities),
            "services_count": len(services),
            "receivers_count": len(receivers),
            "urls": [u.get("url", "") for u in urls[:15]] if isinstance(urls, list) else [],
            "emails": emails[:10],
            "strings_sample": strings,
            "security_score": security_score,
            "certificate": cert,
            "mobsf_link": f"http://{KALI_IP}:8000/static_analyzer/{mobsf_hash}/"
        })
    except requests.exceptions.ConnectionError:
        return jsonify({"error": "Không kết nối được tới máy chủ Kali. Kiểm tra lại IP/mạng."}), 503
    except Exception as e:
        _crash_safe("mobsf_report that bai", e)
        return _error_json("E_MOBSF", e)
 
@app.route('/file-manager')
def file_manager():
    """File Manager"""
    csv_files = get_files_in_directory(os.path.join(app.config['SCAN_FOLDER'], 'csv'))
    apk_files = get_files_in_directory(os.path.join(app.config['SCAN_FOLDER'], 'apk'))
    other_files = get_files_in_directory(os.path.join(app.config['SCAN_FOLDER'], 'other'))
 
    return render_template('file_manager.html',
                         csv_files=csv_files,
                         apk_files=apk_files,
                         other_files=other_files)
 
@app.route('/file-manager/scan/<subfolder>/<path:filename>')
def scan_file_in_manager(subfolder, filename):
    """Quét file trong file manager"""
    filepath = safe_scan_path(subfolder, filename)
    if filepath is None:
        return jsonify({'success': False, 'error': 'Invalid path'}), 400

    if not os.path.exists(filepath):
        return jsonify({'success': False, 'error': 'File not found'}), 404
 
    try:
        if subfolder == 'csv':
            if detector is None:
                return jsonify({'success': False, 'error': 'Mô hình CSV chưa khả dụng.'}), 503
            result = detector.analyze_csv(filepath, filename)
        elif subfolder == 'apk':
            result = analyze_apk_pipeline(filepath, filename, timeout=app.config['APK_ANALYSIS_TIMEOUT'])
            if not result.get('success'):
                return jsonify(result), result.get('http_status', 503)
            attach_tang5(result)
        else:
            return jsonify({'success': False, 'error': 'Unsupported file type'}), 400
        if result.get('confidence') is not None: result['confidence'] = float(result['confidence'])
        return jsonify(result)
    except Exception as e:
        import traceback
        print(f"[✗] scan_file_in_manager lỗi: {traceback.format_exc()}")
        _crash_safe("scan_file_in_manager that bai", e)
        return _error_json("E_INTERNAL", e)
 
@app.route('/file-manager/upload', methods=['POST'])
def file_manager_upload():
    """Upload file vào file manager (CSV hoặc APK)"""
    if 'file' not in request.files:
        return jsonify({'success': False, 'error': 'Không có file được gửi lên'}), 400
    file = request.files['file']
    if file.filename == '':
        return jsonify({'success': False, 'error': 'Chưa chọn file'}), 400
 
    ext = os.path.splitext(file.filename)[1].lower()
    if ext == '.csv':
        subfolder = 'csv'
    elif ext == '.apk':
        subfolder = 'apk'
    else:
        return jsonify({'success': False, 'error': f'Định dạng {ext} không được hỗ trợ'}), 400
 
    try:
        filename, filepath = save_uploaded_file(file, subfolder)
        return jsonify({
            'success': True,
            'message': f'Upload thành công: {filename}',
            'filename': filename,
            'subfolder': subfolder
        })
    except Exception as e:
        import traceback
        print(f"[✗] file_manager_upload lỗi: {traceback.format_exc()}")
        _crash_safe("file_manager_upload that bai", e)
        return _error_json("E_UPLOAD", e)
 
 
@app.route('/file-manager/delete/<subfolder>/<path:filename>', methods=['DELETE'])
def delete_file(subfolder, filename):
    """Xóa file"""
    filepath = safe_scan_path(subfolder, filename)
    if filepath is None:
        return jsonify({'success': False, 'error': 'Invalid path'}), 400

    if os.path.exists(filepath):
        os.remove(filepath)
        return jsonify({'success': True, 'message': f'Đã xóa {filename}'})
    return jsonify({'success': False, 'error': 'File not found'}), 404
 
@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html')
 
@app.route('/history/data')
def history_data():
    """Tương thích mã cũ gọi AJAX; dữ liệu thật nằm ở localStorage phía trình duyệt."""
    return jsonify([])
 
@app.route('/history')
def history_page():
    return render_template('history.html')
 
@app.route('/about')
def about():
    return render_template('about.html')
 
@app.route('/api/health')
def health_check():
    return jsonify({'status': 'ok'})
 
if __name__ == '__main__':
    print("\n" + "="*60)
    print("🚀 ANDROID MALWARE DETECTION SYSTEM")
    print("="*60)
    print("📱 Web: http://localhost:5000")
    print("🔍 Scan CSV/APK: http://localhost:5000/scan")
    print("📁 File Manager: http://localhost:5000/file-manager")
    print("="*60)
    # Mặc định chỉ lắng nghe localhost, tắt debugger (debugger Werkzeug cho phép chạy code từ xa).
    # Bật lại khi cần: FLASK_DEBUG=1 / APP_HOST=0.0.0.0 trong .env
    app.run(debug=os.environ.get("FLASK_DEBUG") == "1",
            host=os.environ.get("APP_HOST", "127.0.0.1"), port=5000)

